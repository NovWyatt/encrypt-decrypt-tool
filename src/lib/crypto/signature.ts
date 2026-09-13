import { concatBytes, toBufferSource } from './encoding'
import { decodeEnvelope, encodePrefix, type SignatureHeader } from './envelope'
import { CryptoError } from './errors'
import { computeKeyId, importPrivateKey, importPublicKey, modulusBits, type RsaKeyMaterial } from './rsa-keys'
import { HASH_BYTES, pssMaxSaltLength, type RsaHash, type SignatureScheme } from './rsa-params'

export { pssMaxSaltLength, type SignatureScheme }

function algorithmParams(scheme: SignatureScheme, saltLength: number): AlgorithmIdentifier | RsaPssParams {
  return scheme === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength } : { name: 'RSASSA-PKCS1-v1_5' }
}

export async function signData(
  data: Uint8Array,
  pkcs8: Uint8Array,
  scheme: SignatureScheme,
  hash: RsaHash,
  saltLength?: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const salt = saltLength ?? HASH_BYTES[hash]
  const key = await importPrivateKey(pkcs8, scheme, hash)
  return new Uint8Array(await crypto.subtle.sign(algorithmParams(scheme, salt), key, toBufferSource(data)))
}

export async function verifyData(
  data: Uint8Array,
  signature: Uint8Array,
  spki: Uint8Array,
  scheme: SignatureScheme,
  hash: RsaHash,
  saltLength?: number,
): Promise<boolean> {
  const key = await importPublicKey(spki, scheme, hash)
  const salt = saltLength ?? HASH_BYTES[hash]
  return crypto.subtle.verify(algorithmParams(scheme, salt), key, toBufferSource(signature), toBufferSource(data))
}

export interface SignatureEnvelopeResult {
  bytes: Uint8Array<ArrayBuffer>
  header: SignatureHeader
  signature: Uint8Array<ArrayBuffer>
}

/** Detached signature over the raw data; the container only records how to verify it. */
export async function createSignature(
  data: Uint8Array,
  key: RsaKeyMaterial,
  scheme: SignatureScheme,
  hash: RsaHash,
  saltLength?: number,
): Promise<SignatureEnvelopeResult> {
  if (!key.pkcs8) throw new CryptoError('PRIVATE_KEY_REQUIRED', 'A private key is required to sign')
  const salt = scheme === 'RSA-PSS' ? (saltLength ?? HASH_BYTES[hash]) : undefined
  if (salt !== undefined && (salt < 0 || salt > pssMaxSaltLength(modulusBits(key.spki), hash))) {
    throw new CryptoError('PARAMS_OUT_OF_RANGE', 'PSS salt length is too large for this key', { field: 'saltLength' })
  }
  const signature = await signData(data, key.pkcs8, scheme, hash, salt)
  const header: SignatureHeader = {
    type: 'signature',
    scheme,
    hash,
    ...(salt !== undefined ? { saltLength: salt } : {}),
    keyId: await computeKeyId(key.spki),
  }
  return { bytes: concatBytes(encodePrefix(header), signature), header, signature }
}

export interface VerifyOutcome {
  valid: boolean
  scheme: SignatureScheme
  hash: RsaHash
  saltLength?: number
  keyId: string
  /** Set when the signature container names a different key than the one used to verify. */
  keyMismatch: boolean
}

export async function verifySignatureContainer(
  data: Uint8Array,
  container: Uint8Array,
  publicKey: Uint8Array,
): Promise<VerifyOutcome> {
  const { header, payload } = decodeEnvelope(container)
  if (header.type !== 'signature') throw new CryptoError('UNSUPPORTED', 'Not a signature')
  const keyId = await computeKeyId(publicKey)
  const valid = await verifyData(data, payload, publicKey, header.scheme, header.hash, header.saltLength)
  return {
    valid,
    scheme: header.scheme,
    hash: header.hash,
    saltLength: header.saltLength,
    keyId,
    keyMismatch: keyId !== header.keyId,
  }
}

/**
 * Verifies a bare signature (for example from `openssl dgst -sign`). PSS signers disagree on
 * salt length (hash length, maximum, or zero), so when none is given the common ones are tried.
 */
export async function verifyRawSignature(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  scheme: SignatureScheme,
  hash: RsaHash,
  saltLength?: number,
): Promise<VerifyOutcome> {
  const keyId = await computeKeyId(publicKey)
  const base = { scheme, hash, keyId, keyMismatch: false }
  if (scheme === 'RSASSA-PKCS1-v1_5') {
    return { ...base, valid: await verifyData(data, signature, publicKey, scheme, hash) }
  }
  const candidates =
    saltLength !== undefined
      ? [saltLength]
      : [...new Set([HASH_BYTES[hash], pssMaxSaltLength(modulusBits(publicKey), hash), 0])]
  for (const salt of candidates) {
    if (await verifyData(data, signature, publicKey, scheme, hash, salt)) {
      return { ...base, valid: true, saltLength: salt }
    }
  }
  return { ...base, valid: false, saltLength }
}
