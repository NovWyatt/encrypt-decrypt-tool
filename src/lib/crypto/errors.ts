/**
 * Every failure the crypto layer can report. The UI maps each code to a localized message,
 * so codes must stay stable even when wording changes.
 */
export type CryptoErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_ENCODING'
  | 'UNKNOWN_FORMAT'
  | 'UNSUPPORTED'
  | 'DECRYPT_FAILED'
  | 'WRONG_KEY'
  | 'INTEGRITY_FAILED'
  | 'INVALID_KEY'
  | 'MESSAGE_TOO_LONG'
  | 'PARAMS_OUT_OF_RANGE'
  | 'NO_MATCHING_KEY'
  | 'PRIVATE_KEY_REQUIRED'
  | 'PASSPHRASE_REQUIRED'
  | 'WRONG_PASSPHRASE'
  | 'AAD_REQUIRED'
  | 'INTERNAL'

export class CryptoError extends Error {
  readonly code: CryptoErrorCode
  readonly details?: Record<string, string | number>

  constructor(code: CryptoErrorCode, message?: string, details?: Record<string, string | number>) {
    super(message ?? code)
    this.name = 'CryptoError'
    this.code = code
    this.details = details
  }
}

export function isCryptoError(error: unknown): error is CryptoError {
  return error instanceof CryptoError
}

/** Plain-object form that survives structured cloning across the worker boundary. */
export interface SerializedCryptoError {
  code: CryptoErrorCode
  message: string
  details?: Record<string, string | number>
}

export function serializeError(error: unknown): SerializedCryptoError {
  if (error instanceof CryptoError) {
    return { code: error.code, message: error.message, details: error.details }
  }
  const message = error instanceof Error ? error.message : String(error)
  return { code: 'INTERNAL', message }
}
