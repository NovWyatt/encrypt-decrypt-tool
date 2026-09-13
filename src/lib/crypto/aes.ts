import { cbc, ctr, ecb, gcm } from '@noble/ciphers/aes.js'
import { BLOCK_BYTES, GCM_TAG_BYTES, type AesKeyBits, type AesMode } from './aes-params'
import { toBufferSource } from './encoding'
import { CryptoError } from './errors'

export * from './aes-params'

export function isAuthenticatedMode(mode: AesMode): boolean {
  return mode === 'GCM'
}

export function assertAesKey(key: Uint8Array, keyBits?: AesKeyBits): void {
  if (![16, 24, 32].includes(key.length)) {
    throw new CryptoError('INVALID_KEY', 'AES key must be 128, 192 or 256 bits', { bytes: key.length })
  }
  if (keyBits !== undefined && key.length * 8 !== keyBits) {
    throw new CryptoError('INVALID_KEY', `Expected a ${keyBits}-bit key`, { bytes: key.length })
  }
}

function assertIv(mode: AesMode, iv: Uint8Array): void {
  if (mode === 'ECB') return
  if (mode === 'GCM' ? iv.length < 8 : iv.length !== 16) {
    throw new CryptoError('INVALID_INPUT', `Invalid IV length for AES-${mode}`, { bytes: iv.length })
  }
}

/**
 * WebCrypto is used whenever it supports the combination (native, constant-time).
 * Chromium rejects 192-bit AES keys and no browser exposes ECB, so those go through
 * the audited @noble/ciphers implementation, which follows the same standards.
 */
function canUseWebCrypto(mode: AesMode, key: Uint8Array): boolean {
  return mode !== 'ECB' && key.length !== 24
}

function webCryptoParams(
  mode: AesMode,
  iv: Uint8Array,
  aad?: Uint8Array,
): AlgorithmIdentifier & Record<string, unknown> {
  switch (mode) {
    case 'GCM':
      return aad && aad.length > 0
        ? { name: 'AES-GCM', iv: toBufferSource(iv), additionalData: toBufferSource(aad), tagLength: 128 }
        : { name: 'AES-GCM', iv: toBufferSource(iv), tagLength: 128 }
    case 'CBC':
      return { name: 'AES-CBC', iv: toBufferSource(iv) }
    case 'CTR':
      // Full 128-bit counter increment, identical to OpenSSL and NIST SP 800-38A.
      return { name: 'AES-CTR', counter: toBufferSource(iv), length: 128 }
    case 'ECB':
      throw new CryptoError('INTERNAL', 'ECB is not available in WebCrypto')
  }
}

function nobleCipher(mode: AesMode, key: Uint8Array, iv: Uint8Array, aad?: Uint8Array) {
  switch (mode) {
    case 'GCM':
      return gcm(key, iv, aad && aad.length > 0 ? aad : undefined)
    case 'CBC':
      return cbc(key, iv)
    case 'CTR':
      return ctr(key, iv)
    case 'ECB':
      return ecb(key)
  }
}

export async function aesEncrypt(
  mode: AesMode,
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  assertAesKey(key)
  assertIv(mode, iv)
  if (aad && aad.length > 0 && mode !== 'GCM') {
    throw new CryptoError('UNSUPPORTED', 'Additional authenticated data requires GCM')
  }
  if (canUseWebCrypto(mode, key)) {
    const cryptoKey = await crypto.subtle.importKey('raw', toBufferSource(key), `AES-${mode}`, false, ['encrypt'])
    const out = await crypto.subtle.encrypt(webCryptoParams(mode, iv, aad), cryptoKey, toBufferSource(plaintext))
    return new Uint8Array(out)
  }
  return new Uint8Array(nobleCipher(mode, key, iv, aad).encrypt(plaintext))
}

/** Throws DECRYPT_FAILED for a GCM tag mismatch or invalid CBC/ECB padding. */
export async function aesDecrypt(
  mode: AesMode,
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  assertAesKey(key)
  assertIv(mode, iv)
  if (mode === 'GCM' && ciphertext.length < GCM_TAG_BYTES) {
    throw new CryptoError('DECRYPT_FAILED', 'Ciphertext is shorter than the GCM tag')
  }
  if ((mode === 'CBC' || mode === 'ECB') && (ciphertext.length === 0 || ciphertext.length % BLOCK_BYTES !== 0)) {
    throw new CryptoError('DECRYPT_FAILED', 'Ciphertext length is not a multiple of the block size')
  }
  try {
    if (canUseWebCrypto(mode, key)) {
      const cryptoKey = await crypto.subtle.importKey('raw', toBufferSource(key), `AES-${mode}`, false, ['decrypt'])
      const out = await crypto.subtle.decrypt(webCryptoParams(mode, iv, aad), cryptoKey, toBufferSource(ciphertext))
      return new Uint8Array(out)
    }
    return new Uint8Array(nobleCipher(mode, key, iv, aad).decrypt(ciphertext))
  } catch (error) {
    if (error instanceof CryptoError) throw error
    throw new CryptoError('DECRYPT_FAILED', 'Decryption failed: wrong key or corrupted data')
  }
}
