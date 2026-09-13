import { md5 } from '@noble/hashes/legacy.js'
import { aesDecrypt, aesEncrypt, type AesKeyBits } from './aes'
import { concatBytes, isValidUtf8, toBufferSource, utf8Encode } from './encoding'
import { hasOpenSslMagic } from './envelope'
import { CryptoError } from './errors'
import { randomBytes } from './random'

/**
 * Compatibility with `openssl enc` and CryptoJS: "Salted__" + 8-byte salt + ciphertext.
 * The file stores no parameters, so both sides must agree on cipher and key derivation.
 *
 *  - pbkdf2: `openssl enc -aes-256-cbc -pbkdf2 -iter 10000` (PBKDF2-HMAC-SHA256 -> key || iv)
 *  - md5:    legacy EVP_BytesToKey with MD5, used by `openssl enc` without -pbkdf2 and by
 *            `CryptoJS.AES.encrypt(text, passphrase)`. Weak; offered for decrypting old data.
 *
 * Passwords are used as raw UTF-8 without normalization, exactly like those tools.
 */
export type OpenSslMode = 'CBC' | 'CTR' | 'ECB'

export type OpenSslKdf = { kind: 'pbkdf2'; hash: 'SHA-256' | 'SHA-512'; iterations: number } | { kind: 'md5' }

export interface OpenSslOptions {
  mode: OpenSslMode
  keyBits: AesKeyBits
  kdf: OpenSslKdf
}

export const OPENSSL_DEFAULTS: OpenSslOptions = {
  mode: 'CBC',
  keyBits: 256,
  kdf: { kind: 'pbkdf2', hash: 'SHA-256', iterations: 10_000 },
}

const MAGIC = utf8Encode('Salted__')
const SALT_BYTES = 8

export function evpBytesToKey(password: Uint8Array, salt: Uint8Array, keyLength: number, ivLength: number) {
  let derived = new Uint8Array(0)
  let block = new Uint8Array(0)
  while (derived.length < keyLength + ivLength) {
    block = md5(concatBytes(block, password, salt))
    derived = concatBytes(derived, block)
  }
  return { key: derived.slice(0, keyLength), iv: derived.slice(keyLength, keyLength + ivLength) }
}

async function deriveKeyIv(password: string, salt: Uint8Array, options: OpenSslOptions) {
  const keyLength = options.keyBits / 8
  const ivLength = options.mode === 'ECB' ? 0 : 16
  const secret = utf8Encode(password)
  if (options.kdf.kind === 'md5') return evpBytesToKey(secret, salt, keyLength, ivLength)
  if (!Number.isInteger(options.kdf.iterations) || options.kdf.iterations < 1 || options.kdf.iterations > 10_000_000) {
    throw new CryptoError('PARAMS_OUT_OF_RANGE', 'PBKDF2 iterations out of range', { field: 'iterations' })
  }
  const base = await crypto.subtle.importKey('raw', secret, 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: options.kdf.hash, salt: toBufferSource(salt), iterations: options.kdf.iterations },
    base,
    (keyLength + ivLength) * 8,
  )
  const all = new Uint8Array(bits)
  return { key: all.slice(0, keyLength), iv: all.slice(keyLength) }
}

export async function encryptOpenSsl(
  plaintext: Uint8Array,
  password: string,
  options: OpenSslOptions,
  salt: Uint8Array = randomBytes(SALT_BYTES),
): Promise<Uint8Array<ArrayBuffer>> {
  if (!password) throw new CryptoError('INVALID_INPUT', 'Password is empty')
  if (salt.length !== SALT_BYTES) throw new CryptoError('INVALID_INPUT', 'Salt must be 8 bytes')
  const { key, iv } = await deriveKeyIv(password, salt, options)
  const ciphertext = await aesEncrypt(options.mode, key, iv, plaintext)
  return concatBytes(MAGIC, salt, ciphertext)
}

export async function decryptOpenSsl(
  data: Uint8Array,
  password: string,
  options: OpenSslOptions,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!hasOpenSslMagic(data)) throw new CryptoError('UNKNOWN_FORMAT', 'Missing "Salted__" header')
  const salt = data.subarray(8, 16)
  const { key, iv } = await deriveKeyIv(password, salt, options)
  return aesDecrypt(options.mode, key, iv, data.subarray(16))
}

/** Configurations tried by auto-detection, most common first. */
export const OPENSSL_CANDIDATES: OpenSslOptions[] = [
  { mode: 'CBC', keyBits: 256, kdf: { kind: 'pbkdf2', hash: 'SHA-256', iterations: 10_000 } },
  { mode: 'CBC', keyBits: 256, kdf: { kind: 'md5' } },
  { mode: 'CBC', keyBits: 128, kdf: { kind: 'pbkdf2', hash: 'SHA-256', iterations: 10_000 } },
  { mode: 'CBC', keyBits: 128, kdf: { kind: 'md5' } },
  { mode: 'CBC', keyBits: 192, kdf: { kind: 'pbkdf2', hash: 'SHA-256', iterations: 10_000 } },
  { mode: 'CBC', keyBits: 192, kdf: { kind: 'md5' } },
]

/**
 * Tries the common CBC configurations. A candidate is accepted only when the padding is valid
 * and the output is valid UTF-8 text, which rules out wrong guesses in practice for text data.
 */
export async function decryptOpenSslAuto(
  data: Uint8Array,
  password: string,
): Promise<{ plaintext: Uint8Array<ArrayBuffer>; options: OpenSslOptions }> {
  for (const options of OPENSSL_CANDIDATES) {
    try {
      const plaintext = await decryptOpenSsl(data, password, options)
      if (isValidUtf8(plaintext)) return { plaintext, options }
    } catch (error) {
      if (error instanceof CryptoError && error.code !== 'DECRYPT_FAILED') throw error
    }
  }
  throw new CryptoError('DECRYPT_FAILED', 'No common OpenSSL/CryptoJS configuration matched this password')
}
