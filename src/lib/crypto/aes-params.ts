// Constants only, without the cipher implementations, so the UI can import them cheaply.

export type AesMode = 'GCM' | 'CBC' | 'CTR' | 'ECB'
export type AesKeyBits = 128 | 192 | 256

export const AES_MODES: readonly AesMode[] = ['GCM', 'CBC', 'CTR', 'ECB']
export const AES_KEY_SIZES: readonly AesKeyBits[] = [128, 192, 256]

/** Default IV / nonce length per mode. ECB has none. */
export const IV_LENGTH: Record<AesMode, number> = { GCM: 12, CBC: 16, CTR: 16, ECB: 0 }
export const GCM_TAG_BYTES = 16
export const BLOCK_BYTES = 16
