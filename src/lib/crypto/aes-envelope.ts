import { hkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { aesDecrypt, aesEncrypt, assertAesKey, IV_LENGTH, type AesKeyBits, type AesMode } from './aes'
import { concatBytes, fromBase64, timingSafeEqual, toBase64, utf8Encode } from './encoding'
import {
  decodeEnvelope,
  encodePrefix,
  kdfFromHeader,
  type AesHeader,
  type DecodedEnvelope,
  type KdfHeader,
} from './envelope'
import { CryptoError } from './errors'
import { deriveKey, SALT_LENGTH, type KdfParams } from './kdf'
import { randomBytes } from './random'

export type AesSecret = { kind: 'password'; password: string } | { kind: 'raw'; key: Uint8Array }

export interface AesEncryptOptions {
  mode: AesMode
  keyBits: AesKeyBits
  secret: AesSecret
  /** Required when the secret is a password. */
  kdf?: KdfParams
  /** Encrypt-then-MAC with HMAC-SHA256. Ignored for GCM, which authenticates on its own. */
  mac?: boolean
  /** Extra associated data (GCM only). The recipient must provide the same bytes. */
  aad?: Uint8Array
  /** Custom IV / nonce. A fresh random one is generated when omitted. */
  iv?: Uint8Array
  /** Fixed salt, only for reproducible tests. */
  salt?: Uint8Array
}

export interface AesEncryptResult {
  bytes: Uint8Array<ArrayBuffer>
  header: AesHeader
  kdfMs: number
  cipherMs: number
}

const MAC_BYTES = 32
const CHECK_BYTES = 4
const INFO_ENC = utf8Encode('EDT v1 encryption key')
const INFO_MAC = utf8Encode('EDT v1 mac key')
const INFO_CHECK = utf8Encode('EDT v1 key check')

function subkey(master: Uint8Array, info: Uint8Array, length: number): Uint8Array<ArrayBuffer> {
  return new Uint8Array(hkdf(sha256, master, undefined, info, length))
}

function kdfToHeader(kdf: KdfParams, salt: Uint8Array): KdfHeader {
  const saltB64 = toBase64(salt)
  switch (kdf.name) {
    case 'PBKDF2':
      return { name: 'PBKDF2', hash: kdf.hash, iterations: kdf.iterations, salt: saltB64 }
    case 'Argon2id':
      return {
        name: 'Argon2id',
        memoryKiB: kdf.memoryKiB,
        iterations: kdf.iterations,
        parallelism: kdf.parallelism,
        salt: saltB64,
      }
    case 'scrypt':
      return { name: 'scrypt', N: kdf.N, r: kdf.r, p: kdf.p, salt: saltB64 }
  }
}

async function resolveMasterKey(
  secret: AesSecret,
  keyBits: AesKeyBits,
  kdf: KdfParams | undefined,
  salt: Uint8Array,
): Promise<Uint8Array> {
  if (secret.kind === 'raw') {
    assertAesKey(secret.key, keyBits)
    return secret.key
  }
  if (!secret.password) throw new CryptoError('INVALID_INPUT', 'Password is empty')
  if (!kdf) throw new CryptoError('INVALID_INPUT', 'A key derivation function is required')
  return deriveKey(secret.password, salt, kdf, keyBits / 8)
}

export async function encryptAesMessage(plaintext: Uint8Array, options: AesEncryptOptions): Promise<AesEncryptResult> {
  const { mode, keyBits, secret } = options
  const useMac = mode !== 'GCM' && options.mac === true
  const authenticated = mode === 'GCM' || useMac
  const aad = options.aad && options.aad.length > 0 ? options.aad : undefined
  if (aad && mode !== 'GCM') throw new CryptoError('UNSUPPORTED', 'Associated data requires GCM')

  const iv = options.iv ?? randomBytes(IV_LENGTH[mode])
  const salt = options.salt ?? randomBytes(SALT_LENGTH)

  const kdfStart = performance.now()
  const master = await resolveMasterKey(secret, keyBits, options.kdf, salt)
  const kdfMs = performance.now() - kdfStart

  const header: AesHeader = {
    type: 'aes',
    mode,
    keyBits,
    ...(mode !== 'ECB' ? { iv: toBase64(iv) } : {}),
    key: secret.kind === 'password' ? { source: 'password', kdf: kdfToHeader(options.kdf!, salt) } : { source: 'raw' },
    ...(useMac ? { mac: 'HMAC-SHA256' as const } : {}),
    ...(!authenticated ? { check: toBase64(subkey(master, INFO_CHECK, CHECK_BYTES)) } : {}),
    ...(aad ? { aad: true } : {}),
  }
  const prefix = encodePrefix(header)

  const cipherStart = performance.now()
  const encKey = useMac ? subkey(master, INFO_ENC, keyBits / 8) : master
  let payload: Uint8Array<ArrayBuffer>
  if (mode === 'GCM') {
    payload = await aesEncrypt(mode, encKey, iv, plaintext, aad ? concatBytes(prefix, aad) : prefix)
  } else {
    const ciphertext = await aesEncrypt(mode, encKey, iv, plaintext)
    payload = useMac
      ? concatBytes(ciphertext, hmac(sha256, subkey(master, INFO_MAC, MAC_BYTES), concatBytes(prefix, ciphertext)))
      : ciphertext
  }
  const cipherMs = performance.now() - cipherStart

  return { bytes: concatBytes(prefix, payload), header, kdfMs, cipherMs }
}

export interface AesDecryptResult {
  plaintext: Uint8Array<ArrayBuffer>
  header: AesHeader
  kdfMs: number
  cipherMs: number
}

export async function decryptAesMessage(
  input: Uint8Array | DecodedEnvelope,
  secret: AesSecret,
  aad?: Uint8Array,
): Promise<AesDecryptResult> {
  const envelope = input instanceof Uint8Array ? decodeEnvelope(input) : input
  const { header, prefix, payload } = envelope
  if (header.type !== 'aes') throw new CryptoError('UNSUPPORTED', 'Not an AES message')
  if (header.key.source === 'password' && secret.kind !== 'password') {
    throw new CryptoError('INVALID_INPUT', 'This message was encrypted with a password')
  }
  if (header.key.source === 'raw' && secret.kind !== 'raw') {
    throw new CryptoError('INVALID_INPUT', 'This message was encrypted with a raw key')
  }
  if (header.aad && !(aad && aad.length > 0)) throw new CryptoError('AAD_REQUIRED', 'Associated data is required')

  const { mode, keyBits } = header
  const iv = header.iv ? fromBase64(header.iv) : new Uint8Array()

  const kdfStart = performance.now()
  const master =
    header.key.source === 'password'
      ? await resolveMasterKey(secret, keyBits, kdfFromHeader(header.key.kdf), fromBase64(header.key.kdf.salt))
      : await resolveMasterKey(secret, keyBits, undefined, new Uint8Array())
  const kdfMs = performance.now() - kdfStart

  if (header.check && !timingSafeEqual(subkey(master, INFO_CHECK, CHECK_BYTES), fromBase64(header.check))) {
    throw new CryptoError('WRONG_KEY', 'Wrong password or key')
  }

  const cipherStart = performance.now()
  let plaintext: Uint8Array<ArrayBuffer>
  if (mode === 'GCM') {
    try {
      plaintext = await aesDecrypt(mode, master, iv, payload, aad && aad.length > 0 ? concatBytes(prefix, aad) : prefix)
    } catch (error) {
      if (error instanceof CryptoError && error.code === 'DECRYPT_FAILED') {
        throw new CryptoError('DECRYPT_FAILED', 'Wrong password/key, wrong associated data, or modified data')
      }
      throw error
    }
  } else if (header.mac) {
    if (payload.length < MAC_BYTES) throw new CryptoError('INTEGRITY_FAILED', 'Message is truncated')
    const ciphertext = payload.subarray(0, payload.length - MAC_BYTES)
    const tag = payload.subarray(payload.length - MAC_BYTES)
    const expected = hmac(sha256, subkey(master, INFO_MAC, MAC_BYTES), concatBytes(prefix, ciphertext))
    if (!timingSafeEqual(expected, tag)) {
      throw new CryptoError('INTEGRITY_FAILED', 'Wrong password/key or modified data')
    }
    plaintext = await aesDecrypt(mode, subkey(master, INFO_ENC, keyBits / 8), iv, ciphertext)
  } else {
    plaintext = await aesDecrypt(mode, master, iv, payload)
  }
  const cipherMs = performance.now() - cipherStart

  return { plaintext, header, kdfMs, cipherMs }
}
