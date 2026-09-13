import { aesDecrypt, aesEncrypt, type AesKeyBits } from './aes'
import { concatBytes, fromBase64, toBase64, toBufferSource } from './encoding'
import { decodeEnvelope, encodePrefix, type DecodedEnvelope, type HybridHeader, type RsaHeader } from './envelope'
import { CryptoError } from './errors'
import { randomBytes } from './random'
import {
  computeKeyId,
  HASH_BYTES,
  importPrivateKey,
  importPublicKey,
  modulusBits,
  type RsaHash,
  type RsaKeyMaterial,
} from './rsa-keys'

/** Largest message RSA-OAEP can encrypt directly: k - 2*hLen - 2 bytes (RFC 8017, 7.1.1). */
export function oaepMaxMessageBytes(bits: number, hash: RsaHash): number {
  return Math.max(0, Math.ceil(bits / 8) - 2 * HASH_BYTES[hash] - 2)
}

export async function rsaOaepEncrypt(
  spki: Uint8Array,
  hash: RsaHash,
  data: Uint8Array,
  label?: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  const bits = modulusBits(spki)
  const max = oaepMaxMessageBytes(bits, hash)
  if (data.length > max) {
    throw new CryptoError('MESSAGE_TOO_LONG', 'Message is too long for RSA-OAEP with this key', {
      max,
      actual: data.length,
    })
  }
  const key = await importPublicKey(spki, 'RSA-OAEP', hash)
  const params: RsaOaepParams = label ? { name: 'RSA-OAEP', label: toBufferSource(label) } : { name: 'RSA-OAEP' }
  return new Uint8Array(await crypto.subtle.encrypt(params, key, toBufferSource(data)))
}

export async function rsaOaepDecrypt(
  pkcs8: Uint8Array,
  hash: RsaHash,
  data: Uint8Array,
  label?: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await importPrivateKey(pkcs8, 'RSA-OAEP', hash)
  const params: RsaOaepParams = label ? { name: 'RSA-OAEP', label: toBufferSource(label) } : { name: 'RSA-OAEP' }
  try {
    return new Uint8Array(await crypto.subtle.decrypt(params, key, toBufferSource(data)))
  } catch {
    throw new CryptoError('DECRYPT_FAILED', 'RSA decryption failed: wrong private key, hash, or modified data')
  }
}

export interface HybridRecipient {
  spki: Uint8Array
  hash: RsaHash
}

/**
 * Hybrid encryption: a random AES-GCM content key encrypts the data, and RSA-OAEP wraps that
 * key once per recipient. Size is unlimited, and the header (IV + wrapped keys) is bound to the
 * ciphertext as GCM additional data.
 */
export async function encryptHybrid(
  plaintext: Uint8Array,
  recipients: HybridRecipient[],
  keyBits: AesKeyBits = 256,
): Promise<{ bytes: Uint8Array<ArrayBuffer>; header: HybridHeader }> {
  if (recipients.length === 0) throw new CryptoError('INVALID_INPUT', 'At least one recipient is required')
  if (recipients.length > 32)
    throw new CryptoError('PARAMS_OUT_OF_RANGE', 'Too many recipients', { field: 'recipients' })
  const contentKey = randomBytes(keyBits / 8)
  const iv = randomBytes(12)
  const header: HybridHeader = {
    type: 'rsa-hybrid',
    mode: 'GCM',
    keyBits,
    iv: toBase64(iv),
    recipients: await Promise.all(
      recipients.map(async ({ spki, hash }) => ({
        keyId: await computeKeyId(spki),
        hash,
        wrappedKey: toBase64(await rsaOaepEncrypt(spki, hash, contentKey)),
      })),
    ),
  }
  const prefix = encodePrefix(header)
  const payload = await aesEncrypt('GCM', contentKey, iv, plaintext, prefix)
  return { bytes: concatBytes(prefix, payload), header }
}

export async function decryptHybrid(
  input: Uint8Array | DecodedEnvelope,
  keys: RsaKeyMaterial[],
): Promise<{ plaintext: Uint8Array<ArrayBuffer>; header: HybridHeader; keyId: string }> {
  const { header, prefix, payload } = input instanceof Uint8Array ? decodeEnvelope(input) : input
  if (header.type !== 'rsa-hybrid') throw new CryptoError('UNSUPPORTED', 'Not a hybrid RSA message')
  const privateKeys = keys.filter((key) => key.pkcs8)
  if (privateKeys.length === 0) throw new CryptoError('PRIVATE_KEY_REQUIRED', 'A private key is required')

  for (const key of privateKeys) {
    const keyId = await computeKeyId(key.spki)
    for (const recipient of header.recipients.filter((r) => r.keyId === keyId)) {
      const contentKey = await rsaOaepDecrypt(key.pkcs8!, recipient.hash, fromBase64(recipient.wrappedKey))
      if (contentKey.length !== header.keyBits / 8) throw new CryptoError('DECRYPT_FAILED', 'Invalid content key')
      try {
        const plaintext = await aesDecrypt('GCM', contentKey, fromBase64(header.iv), payload, prefix)
        return { plaintext, header, keyId }
      } catch {
        throw new CryptoError('DECRYPT_FAILED', 'The message was modified after encryption')
      }
    }
  }
  throw new CryptoError('NO_MATCHING_KEY', 'None of the available private keys is a recipient of this message', {
    recipients: header.recipients.map((r) => r.keyId).join(', '),
  })
}

/**
 * Direct RSA-OAEP of a short message. The container prefix is used as the OAEP label, so a
 * modified header makes decryption fail.
 */
export async function encryptRsaDirect(
  plaintext: Uint8Array,
  spki: Uint8Array,
  hash: RsaHash,
): Promise<{ bytes: Uint8Array<ArrayBuffer>; header: RsaHeader }> {
  const header: RsaHeader = { type: 'rsa', hash, keyId: await computeKeyId(spki) }
  const prefix = encodePrefix(header)
  const payload = await rsaOaepEncrypt(spki, hash, plaintext, prefix)
  return { bytes: concatBytes(prefix, payload), header }
}

export async function decryptRsaDirect(
  input: Uint8Array | DecodedEnvelope,
  keys: RsaKeyMaterial[],
): Promise<{ plaintext: Uint8Array<ArrayBuffer>; header: RsaHeader; keyId: string }> {
  const { header, prefix, payload } = input instanceof Uint8Array ? decodeEnvelope(input) : input
  if (header.type !== 'rsa') throw new CryptoError('UNSUPPORTED', 'Not a direct RSA message')
  const privateKeys = keys.filter((key) => key.pkcs8)
  if (privateKeys.length === 0) throw new CryptoError('PRIVATE_KEY_REQUIRED', 'A private key is required')
  for (const key of privateKeys) {
    const keyId = await computeKeyId(key.spki)
    if (keyId !== header.keyId) continue
    const plaintext = await rsaOaepDecrypt(key.pkcs8!, header.hash, payload, prefix)
    return { plaintext, header, keyId }
  }
  throw new CryptoError('NO_MATCHING_KEY', 'None of the available private keys matches this message', {
    recipients: header.keyId,
  })
}
