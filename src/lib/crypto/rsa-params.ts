// RSA sizes and limits only, without key parsing or WebCrypto calls, so the UI can import them cheaply.

export type RsaHash = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
export type SignatureScheme = 'RSA-PSS' | 'RSASSA-PKCS1-v1_5'

export const RSA_HASHES: readonly RsaHash[] = ['SHA-256', 'SHA-384', 'SHA-512', 'SHA-1']
export const HASH_BYTES: Record<RsaHash, number> = { 'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 }
export const RSA_KEY_SIZES = [1024, 2048, 3072, 4096] as const

/** Largest message RSA-OAEP can encrypt directly: k - 2*hLen - 2 bytes (RFC 8017, 7.1.1). */
export function oaepMaxMessageBytes(bits: number, hash: RsaHash): number {
  return Math.max(0, Math.ceil(bits / 8) - 2 * HASH_BYTES[hash] - 2)
}

/** emLen - hLen - 2, where emLen = ceil((modBits - 1) / 8) (RFC 8017, 9.1.1). */
export function pssMaxSaltLength(bits: number, hash: RsaHash): number {
  return Math.ceil((bits - 1) / 8) - HASH_BYTES[hash] - 2
}
