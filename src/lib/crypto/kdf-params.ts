import { CryptoError } from './errors'

// Parameters and validation only, without the hash-wasm dependency, so the UI can import them cheaply.

export type Pbkdf2Hash = 'SHA-256' | 'SHA-512'

export interface Pbkdf2Params {
  name: 'PBKDF2'
  hash: Pbkdf2Hash
  iterations: number
}

export interface Argon2idParams {
  name: 'Argon2id'
  /** Memory cost in KiB. */
  memoryKiB: number
  iterations: number
  parallelism: number
}

export interface ScryptParams {
  name: 'scrypt'
  /** CPU/memory cost, a power of two. */
  N: number
  r: number
  p: number
}

export type KdfParams = Pbkdf2Params | Argon2idParams | ScryptParams
export type KdfName = KdfParams['name']

/**
 * Defaults follow current guidance: RFC 9106 second recommendation for Argon2id,
 * OWASP Password Storage Cheat Sheet for PBKDF2 and scrypt.
 */
export const KDF_DEFAULTS = {
  Argon2id: { name: 'Argon2id', memoryKiB: 65536, iterations: 3, parallelism: 4 },
  PBKDF2: { name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000 },
  scrypt: { name: 'scrypt', N: 131072, r: 8, p: 1 },
} as const satisfies Record<KdfName, KdfParams>

export const SALT_LENGTH = 16

/** Hard limits applied to parameters read from untrusted files, to stop memory/CPU exhaustion. */
export const KDF_LIMITS = {
  pbkdf2Iterations: { min: 1, max: 10_000_000 },
  argon2MemoryKiB: { min: 8, max: 1_048_576 },
  argon2Iterations: { min: 1, max: 64 },
  argon2Parallelism: { min: 1, max: 16 },
  scryptLogN: { min: 1, max: 20 },
  scryptR: { min: 1, max: 32 },
  scryptP: { min: 1, max: 16 },
  scryptMaxMemoryBytes: 1024 ** 3,
} as const

function inRange(value: number, range: { min: number; max: number }): boolean {
  return Number.isInteger(value) && value >= range.min && value <= range.max
}

export function validateKdfParams(params: KdfParams): void {
  const fail = (field: string) => {
    throw new CryptoError('PARAMS_OUT_OF_RANGE', `KDF parameter out of range: ${field}`, { field })
  }
  switch (params.name) {
    case 'PBKDF2':
      if (params.hash !== 'SHA-256' && params.hash !== 'SHA-512') fail('hash')
      if (!inRange(params.iterations, KDF_LIMITS.pbkdf2Iterations)) fail('iterations')
      return
    case 'Argon2id':
      if (!inRange(params.memoryKiB, KDF_LIMITS.argon2MemoryKiB)) fail('memoryKiB')
      if (!inRange(params.iterations, KDF_LIMITS.argon2Iterations)) fail('iterations')
      if (!inRange(params.parallelism, KDF_LIMITS.argon2Parallelism)) fail('parallelism')
      if (params.memoryKiB < 8 * params.parallelism) fail('memoryKiB')
      return
    case 'scrypt': {
      const logN = Math.log2(params.N)
      if (!Number.isInteger(logN) || !inRange(logN, KDF_LIMITS.scryptLogN)) fail('N')
      if (!inRange(params.r, KDF_LIMITS.scryptR)) fail('r')
      if (!inRange(params.p, KDF_LIMITS.scryptP)) fail('p')
      if (128 * params.N * params.r > KDF_LIMITS.scryptMaxMemoryBytes) fail('N')
      return
    }
    default:
      throw new CryptoError('UNSUPPORTED', 'Unknown KDF')
  }
}

/** True when parameters fall below the recommended minimums (the UI shows a warning). */
export function isWeakKdf(params: KdfParams): boolean {
  switch (params.name) {
    case 'PBKDF2':
      return params.iterations < (params.hash === 'SHA-512' ? 210_000 : 600_000)
    case 'Argon2id':
      return params.memoryKiB < 19_456 || params.iterations < 2
    case 'scrypt':
      return params.N < 131072 || params.r < 8
  }
}
