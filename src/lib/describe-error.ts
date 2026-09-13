import type { TFunction, TKey } from '@/i18n'
import { CryptoError } from '@/lib/crypto/errors'
import { FileTooLargeError, MAX_FILE_BYTES } from '@/lib/files'

/** Validation problems caught before calling the crypto layer, carrying an i18n key. */
export class InputProblem extends Error {
  constructor(key: TKey) {
    super(key)
    this.name = 'InputProblem'
  }
}

/** Turns anything thrown by the crypto layer or the UI into a localized, user-facing sentence. */
export function describeError(error: unknown, t: TFunction): string {
  if (error instanceof CryptoError) {
    if (error.code === 'INVALID_KEY' && error.details?.expected && error.details?.actual) {
      return t('errors.keySizeMismatch', { expected: error.details.expected, actual: error.details.actual })
    }
    if (error.details?.field === 'iv') {
      if (error.details.missing) return t('errors.ivRequired')
      const expected = Number(error.details.expected)
      return t('errors.ivInvalid', { expected, hex: expected * 2 })
    }
    return t(`errors.${error.code}` as TKey, error.details)
  }
  if (error instanceof FileTooLargeError) {
    return t('common.fileTooLarge', { max: `${MAX_FILE_BYTES / 1024 / 1024} MB` })
  }
  if (error instanceof InputProblem) return t(error.message as TKey)
  return t('errors.INTERNAL')
}
