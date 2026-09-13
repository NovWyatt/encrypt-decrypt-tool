import type { TFunction } from '@/i18n'
import type { KdfParams } from '@/lib/crypto/kdf-params'
import type { CipherSummary } from '@/lib/crypto/service'

type NumberFormatter = (value: number, options?: Intl.NumberFormatOptions) => string

export function formatSize(bytes: number, formatNumber: NumberFormatter): string {
  if (bytes < 1024) return `${formatNumber(bytes)} B`
  if (bytes < 1024 * 1024) return `${formatNumber(bytes / 1024, { maximumFractionDigits: 1 })} KB`
  return `${formatNumber(bytes / (1024 * 1024), { maximumFractionDigits: 2 })} MB`
}

export function formatDuration(ms: number, t: TFunction, formatNumber: NumberFormatter): string {
  if (ms < 1000) return t('common.ms', { value: formatNumber(Math.max(1, Math.round(ms))) })
  return t('common.seconds', { value: formatNumber(ms / 1000, { maximumFractionDigits: 2 }) })
}

export function describeKdf(kdf: KdfParams, formatNumber: NumberFormatter): string {
  switch (kdf.name) {
    case 'Argon2id':
      return `Argon2id, ${formatNumber(kdf.memoryKiB / 1024, { maximumFractionDigits: 1 })} MiB, t=${kdf.iterations}, p=${kdf.parallelism}`
    case 'scrypt':
      return `scrypt, N=2^${Math.log2(kdf.N)}, r=${kdf.r}, p=${kdf.p}`
    case 'PBKDF2':
      return `PBKDF2-HMAC-${kdf.hash}, ${formatNumber(kdf.iterations)}`
  }
}

export function algorithmLabel(summary: CipherSummary): string {
  if (summary.kind === 'rsa-hybrid') return `RSA-OAEP + AES-${summary.keyBits}-GCM`
  if (summary.kind === 'rsa') return `RSA-OAEP-${summary.rsaHash}`
  if (summary.kind === 'signature') return `${summary.scheme} ${summary.rsaHash}`
  if (summary.mode && summary.keyBits) return `AES-${summary.keyBits}-${summary.mode}`
  return 'AES'
}

/** Splits a hex string into readable byte groups. */
export function groupHex(hex: string, group = 2): string {
  return hex.match(new RegExp(`.{1,${group}}`, 'g'))?.join(' ') ?? hex
}
