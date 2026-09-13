import { HASH_BYTES, pssMaxSaltLength, RSA_HASHES, type RsaHash, type SignatureScheme } from '@/lib/crypto/rsa-params'
import type { Level } from '@/stores/settings'

/** Non-secret signing preferences remembered between visits. */
export interface SignOptions {
  scheme: SignatureScheme
  hash: RsaHash
  /** PSS only. Null follows the hash length, which is what most verifiers assume. */
  saltLength: number | null
  format: 'edt' | 'raw'
  encoding: 'base64' | 'hex'
}

export const DEFAULT_SIGN_OPTIONS: SignOptions = {
  scheme: 'RSA-PSS',
  hash: 'SHA-256',
  saltLength: null,
  format: 'edt',
  encoding: 'base64',
}

const SCHEMES: readonly SignatureScheme[] = ['RSA-PSS', 'RSASSA-PKCS1-v1_5']

function isSaltLength(value: unknown): value is number | null {
  return value === null || (Number.isInteger(value) && (value as number) >= 0)
}

export function isSignOptions(value: unknown): value is SignOptions {
  const v = value as SignOptions
  return (
    typeof v === 'object' &&
    v !== null &&
    SCHEMES.includes(v.scheme) &&
    RSA_HASHES.includes(v.hash) &&
    isSaltLength(v.saltLength) &&
    (v.format === 'edt' || v.format === 'raw') &&
    (v.encoding === 'base64' || v.encoding === 'hex')
  )
}

export function effectiveSignOptions(options: SignOptions, level: Level): SignOptions {
  return level === 'basic' ? DEFAULT_SIGN_OPTIONS : options
}

/** Parameters for a bare signature, which records nothing about how it was made. */
export interface RawVerifyParams {
  scheme: SignatureScheme
  hash: RsaHash
  /** Null tries the common PSS salt lengths. */
  saltLength: number | null
}

export const DEFAULT_RAW_VERIFY: RawVerifyParams = { scheme: 'RSA-PSS', hash: 'SHA-256', saltLength: null }

export const SCHEME_LABEL: Record<SignatureScheme, string> = {
  'RSA-PSS': 'RSA-PSS',
  'RSASSA-PKCS1-v1_5': 'PKCS#1 v1.5',
}

/** The hash length, unless the key is too small for it (1024-bit keys with SHA-512). */
export function defaultSaltLength(bits: number, hash: RsaHash): number {
  return Math.max(0, Math.min(HASH_BYTES[hash], pssMaxSaltLength(bits, hash)))
}

export function signatureExtensions(container: 'edt' | 'raw', encoding: 'base64' | 'hex') {
  return container === 'edt'
    ? { text: '.sig', binary: '.sig.bin' }
    : { text: encoding === 'hex' ? '.sig.hex' : '.sig.b64', binary: '.sig' }
}
