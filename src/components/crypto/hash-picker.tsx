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
      <Segmented<RsaHash>
        ariaLabel={ariaLabel}
        size="sm"
        fullWidth
        value={value}
        onValueChange={onChange}
        options={RSA_HASHES.map((hash) => ({ value: hash, label: hash }))}
      />
      {value === 'SHA-1' && <p className="text-xs leading-relaxed text-warning">{t('rsa.sha1Legacy')}</p>}
    </>
  )
}
