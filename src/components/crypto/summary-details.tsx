import type { ReactNode } from 'react'
import { Tag } from '@/components/common/choice'
import { DetailsList, type DetailRow } from '@/components/common/output'
import { useI18n } from '@/i18n'
import type { CipherSummary } from '@/lib/crypto/service'
import { algorithmLabel, describeKdf, groupHex } from '@/lib/format'
import { useKeyring } from '@/stores/keyring'
import { KeyIdenticon } from './key-identicon'

/** A key ID with its identicon and, when the key is in the keyring, its name. */
export function KeyReference({ id }: { id: string }) {
  const keys = useKeyring()
  const key = keys.find((item) => item.id === id)
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      <KeyIdenticon id={id} className="size-5 shrink-0 rounded" />
      {/* Names are user text and may have no spaces at all, so they break anywhere rather than widen the page. */}
      <span className="min-w-0 wrap-anywhere">
        {/* The space lets a line break between name and ID, instead of inside the first ID group. */}
        {key && <span className="mr-1 font-sans text-[0.8125rem] font-medium">{key.name}</span>}{' '}
        <span className="font-mono text-xs text-muted-foreground">{groupHex(id, 4)}</span>
      </span>
    </span>
  )
}

/** Everything a ciphertext or signature header says about how it was produced. */
export function SummaryDetails({ summary, extra }: { summary: CipherSummary; extra?: DetailRow[] }) {
  const { t, formatNumber } = useI18n()
  const rows: DetailRow[] = [{ label: t('aes.sumAlgorithm'), value: algorithmLabel(summary) }]

  rows.push({
    label: t('aes.sumContainer'),
    value: { edt: t('aes.formatEdt'), openssl: t('aes.formatOpenssl'), raw: t('aes.formatRaw') }[summary.container],
  })
  if (summary.keySource) {
    const sources = { password: t('aes.keyFromPassword'), raw: t('aes.keyFromRaw'), rsa: t('aes.keyFromRsa') }
    rows.push({ label: t('aes.sumKey'), value: sources[summary.keySource] })
  }
  if (summary.kdf) rows.push({ label: t('aes.sumKdf'), value: describeKdf(summary.kdf, formatNumber) })
  if (summary.openssl) {
    const { kdf } = summary.openssl
    rows.push({
      label: t('aes.sumKdf'),
      value: kdf.kind === 'md5' ? 'EVP_BytesToKey (MD5)' : `PBKDF2-HMAC-${kdf.hash}, ${formatNumber(kdf.iterations)}`,
    })
  }
  if (summary.recipients?.length) {
    rows.push({
      label: t('aes.sumRecipients'),
      value: (
        <span className="flex flex-col gap-1.5">
          {summary.recipients.map((recipient) => (
            <KeyReference key={recipient.keyId} id={recipient.keyId} />
          ))}
        </span>
      ),
    })
  } else if (summary.keyId) {
    rows.push({ label: t('keys.keyId'), value: <KeyReference id={summary.keyId} /> })
  }
  if (summary.kind === 'rsa-hybrid' && summary.recipients?.[0]) {
    rows.push({ label: t('rsa.hash'), value: `RSA-OAEP, ${summary.recipients[0].hash}` })
  }
  if (summary.kind === 'signature' && summary.saltLength !== undefined) {
    rows.push({ label: t('sign.saltLength'), value: formatNumber(summary.saltLength) })
  }

  if (summary.kind !== 'signature') {
    const integrity: Record<CipherSummary['integrity'], string> = {
      aead: t('aes.integrityAead'),
      hmac: t('aes.integrityHmac'),
      check: t('aes.integrityCheck'),
      label: t('aes.integrityLabel'),
      none: t('aes.integrityNone'),
    }
    const weak: ReactNode =
      summary.integrity === 'aead' || summary.integrity === 'hmac' || summary.integrity === 'label' ? null : (
        <Tag tone="warn">{t('common.insecure')}</Tag>
      )
    rows.push({
      label: t('aes.sumIntegrity'),
      value: (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          {integrity[summary.integrity]}
          {weak}
        </span>
      ),
    })
  }
  if (summary.ivHex) rows.push({ label: t('aes.sumIv'), value: groupHex(summary.ivHex), mono: true })
  if (summary.saltHex) rows.push({ label: t('aes.sumSalt'), value: groupHex(summary.saltHex), mono: true })
  if (extra) rows.push(...extra)

  return <DetailsList rows={rows} />
}
