import { argon2id, scrypt } from 'hash-wasm'
import { toBufferSource, utf8Encode } from './encoding'
import { validateKdfParams, type KdfParams } from './kdf-params'

export * from './kdf-params'

/**
 * Passwords are NFC-normalized so Vietnamese text typed with composed or decomposed
 * diacritics (different keyboards / operating systems) derives the same key.
 */
export function normalizePassword(password: string): Uint8Array<ArrayBuffer> {
  return utf8Encode(password.normalize('NFC'))
}

export async function deriveKey(
  password: string,
  salt: Uint8Array,
  params: KdfParams,
  length: number,
): Promise<Uint8Array<ArrayBuffer>> {
  validateKdfParams(params)
  const secret = normalizePassword(password)
  switch (params.name) {
    case 'PBKDF2': {
      const baseKey = await crypto.subtle.importKey('raw', secret, 'PBKDF2', false, ['deriveBits'])
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: params.hash, salt: toBufferSource(salt), iterations: params.iterations },
        baseKey,
        length * 8,
      )
      return new Uint8Array(bits)
    }
    case 'Argon2id': {
      const out = await argon2id({
        password: secret,
        salt,
        iterations: params.iterations,
        parallelism: params.parallelism,
        memorySize: params.memoryKiB,
        hashLength: length,
        outputType: 'binary',
      })
      return new Uint8Array(out)
    }
    case 'scrypt': {
      const out = await scrypt({
        password: secret,
        salt,
        costFactor: params.N,
        blockSize: params.r,
        parallelism: params.p,
        hashLength: length,
        outputType: 'binary',
      })
      return new Uint8Array(out)
    }
  }
}
