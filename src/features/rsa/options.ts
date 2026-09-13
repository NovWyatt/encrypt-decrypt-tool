import { oaepMaxMessageBytes, RSA_HASHES, type RsaHash } from '@/lib/crypto/rsa-params'
import type { Level } from '@/stores/settings'

/** Hybrid encryption wraps an AES-256 key, so OAEP must have room for 32 bytes. */
export const HYBRID_KEY_BYTES = 32

/** Whether a key of this size can be used with the scheme and hash (large hashes eat OAEP room). */
export function fitsOaep(bits: number, hash: RsaHash, scheme: 'hybrid' | 'direct'): boolean {
  return oaepMaxMessageBytes(bits, hash) >= (scheme === 'hybrid' ? HYBRID_KEY_BYTES : 1)
}

/** Non-secret RSA preferences remembered between visits. */
export interface RsaOptions {
  scheme: 'hybrid' | 'direct'
  hash: RsaHash
  /** Only direct RSA-OAEP can produce raw output; hybrid always uses the EDT container. */
  format: 'edt' | 'raw'
  encoding: 'base64' | 'hex'
}

export const DEFAULT_RSA_OPTIONS: RsaOptions = { scheme: 'hybrid', hash: 'SHA-256', format: 'edt', encoding: 'base64' }

export function isRsaOptions(value: unknown): value is RsaOptions {
  const v = value as RsaOptions
  return (
    typeof v === 'object' &&
    v !== null &&
    (v.scheme === 'hybrid' || v.scheme === 'direct') &&
    RSA_HASHES.includes(v.hash) &&
    (v.format === 'edt' || v.format === 'raw') &&
    (v.encoding === 'base64' || v.encoding === 'hex')
  )
}

export function effectiveRsaOptions(options: RsaOptions, level: Level): RsaOptions {
  if (level === 'basic') return DEFAULT_RSA_OPTIONS
  return options.scheme === 'hybrid' ? { ...options, format: 'edt' } : options
}
