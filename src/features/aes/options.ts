import { AES_KEY_SIZES, AES_MODES, type AesKeyBits, type AesMode } from '@/lib/crypto/aes-params'
import {
  KDF_DEFAULTS,
  type Argon2idParams,
  type KdfName,
  type KdfParams,
  type Pbkdf2Params,
  type ScryptParams,
} from '@/lib/crypto/kdf-params'
import type { InspectState } from '@/hooks/use-inspection'
import type { ContainerKind } from '@/lib/crypto/service'
import type { Level } from '@/stores/settings'

/** Non-secret AES preferences remembered between visits. Passwords and keys are never stored. */
export interface AesOptions {
  mode: AesMode
  keyBits: AesKeyBits
  kdfName: KdfName
  argon2: Argon2idParams
  scrypt: ScryptParams
  pbkdf2: Pbkdf2Params
  mac: boolean
  format: ContainerKind
  opensslKdf: 'pbkdf2' | 'md5'
  opensslIterations: number
  encoding: 'base64' | 'hex'
  wrapLines: boolean
}

export const DEFAULT_AES_OPTIONS: AesOptions = {
  mode: 'GCM',
  keyBits: 256,
  kdfName: 'Argon2id',
  argon2: { ...KDF_DEFAULTS.Argon2id },
  scrypt: { ...KDF_DEFAULTS.scrypt },
  pbkdf2: { ...KDF_DEFAULTS.PBKDF2 },
  mac: true,
  format: 'edt',
  opensslKdf: 'pbkdf2',
  opensslIterations: 10_000,
  encoding: 'base64',
  wrapLines: false,
}

export function isAesOptions(value: unknown): value is AesOptions {
  const v = value as AesOptions
  return (
    typeof v === 'object' &&
    v !== null &&
    AES_MODES.includes(v.mode) &&
    AES_KEY_SIZES.includes(v.keyBits) &&
    ['Argon2id', 'scrypt', 'PBKDF2'].includes(v.kdfName) &&
    typeof v.argon2?.memoryKiB === 'number' &&
    typeof v.scrypt?.N === 'number' &&
    typeof v.pbkdf2?.iterations === 'number' &&
    typeof v.mac === 'boolean' &&
    ['edt', 'openssl', 'raw'].includes(v.format) &&
    ['pbkdf2', 'md5'].includes(v.opensslKdf) &&
    typeof v.opensslIterations === 'number' &&
    ['base64', 'hex'].includes(v.encoding) &&
    typeof v.wrapLines === 'boolean'
  )
}

export function selectedKdf(options: AesOptions): KdfParams {
  switch (options.kdfName) {
    case 'Argon2id':
      return options.argon2
    case 'scrypt':
      return options.scrypt
    case 'PBKDF2':
      return options.pbkdf2
  }
}

/** Basic level always uses the recommended configuration, whatever advanced settings were saved. */
export function effectiveOptions(options: AesOptions, level: Level): AesOptions {
  if (level === 'advanced') {
    // openssl enc has no GCM; keep the saved choice valid instead of failing at run time.
    if (options.format === 'openssl' && options.mode === 'GCM') return { ...options, mode: 'CBC' }
    return options
  }
  return { ...DEFAULT_AES_OPTIONS }
}

export type SecretKind = 'password' | 'raw'

/** Secrets typed into the form. Kept in memory only, never persisted. */
export interface SecretState {
  kind: SecretKind
  password: string
  keyText: string
  aad: string
  iv: string
}

export interface OpenSslDecryptOptions {
  auto: boolean
  mode: 'CBC' | 'CTR' | 'ECB'
  keyBits: AesKeyBits
  kdf: 'pbkdf2' | 'md5'
  iterations: number
}

export interface RawDecryptOptions {
  mode: AesMode
  keyBits: AesKeyBits
  iv: string
}

export function encryptSecretKind(level: Level, options: AesOptions, secret: SecretState): SecretKind {
  if (level === 'basic' || options.format === 'openssl') return 'password'
  if (options.format === 'raw') return 'raw'
  return secret.kind
}

/** The ciphertext decides which secret it needs; the user's choice only applies to unknown input. */
export function decryptSecretKind(inspection: InspectState, secret: SecretState): SecretKind {
  if (inspection.status !== 'ok') return secret.kind
  const { result } = inspection
  if (result.container === 'openssl') return 'password'
  if (result.container === 'raw') return 'raw'
  if (result.summary.kind === 'aes') return result.summary.keySource === 'raw' ? 'raw' : 'password'
  return secret.kind
}
