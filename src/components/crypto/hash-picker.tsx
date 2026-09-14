import { Segmented } from '@/components/common/segmented'
import { useI18n } from '@/i18n'
import { RSA_HASHES, type RsaHash } from '@/lib/crypto/rsa-params'

/** Hash choice for RSA-OAEP and signatures, with a note when the legacy SHA-1 is picked. */
export function HashPicker({
  value,
  onChange,
  ariaLabel,
}: {
  value: RsaHash
  onChange: (hash: RsaHash) => void
  ariaLabel: string
}) {
  const { t } = useI18n()
  return (
    <>
      {/* The four names need about 16.5rem side by side; narrower panels get two rows. */}
      <div className="@container">
        <Segmented<RsaHash>
          ariaLabel={ariaLabel}
          size="sm"
          fullWidth
          value={value}
          onValueChange={onChange}
          options={RSA_HASHES.map((hash) => ({ value: hash, label: hash }))}
          className="@max-[17rem]:grid @max-[17rem]:grid-cols-2"
        />
      </div>
      {value === 'SHA-1' && <p className="text-xs leading-relaxed text-warning">{t('rsa.sha1Legacy')}</p>}
    </>
  )
}
