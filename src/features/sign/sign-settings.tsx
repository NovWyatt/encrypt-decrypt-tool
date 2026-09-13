import { ArrowRightIcon } from '@phosphor-icons/react'
import { navigate } from '@/app/routes'
import { AdvancedLink } from '@/components/common/advanced-link'
import { Callout } from '@/components/common/callout'
import { ChoiceCards, NumberField, Tag } from '@/components/common/choice'
import { DetailsList } from '@/components/common/output'
import { Panel } from '@/components/common/page'
import { Segmented } from '@/components/common/segmented'
import { SettingsSection } from '@/components/common/settings-section'
import { DetectionSummary } from '@/components/crypto/detection-summary'
import { HashPicker } from '@/components/crypto/hash-picker'
import { KeyReference } from '@/components/crypto/summary-details'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { KeyPicker, KeyringEmpty } from '@/features/keys/key-picker'
import type { InspectState } from '@/hooks/use-inspection'
import { useI18n } from '@/i18n'
import { pssMaxSaltLength, type SignatureScheme } from '@/lib/crypto/rsa-params'
import { describeError } from '@/lib/describe-error'
import { formatSize } from '@/lib/format'
import type { RingKey } from '@/stores/keyring'
import type { Level } from '@/stores/settings'
import { defaultSaltLength, SCHEME_LABEL, type RawVerifyParams, type SignOptions } from './options'

/** Salt sizes depend on the key; without one, assume the most common size. */
const FALLBACK_BITS = 2048

function KeyShortcuts({ onGenerate, onImport }: { onGenerate?: () => void; onImport: () => void }) {
  const { t } = useI18n()
  return (
    <div className="flex flex-wrap gap-1">
      {onGenerate && (
        <Button variant="ghost" size="xs" onClick={onGenerate}>
          {t('keys.generate')}
        </Button>
      )}
      <Button variant="ghost" size="xs" onClick={onImport}>
        {t('keys.import')}
      </Button>
    </div>
  )
}

interface SignSettingsProps {
  level: Level
  options: SignOptions
  onOptions: (patch: Partial<SignOptions>) => void
  privateKeys: readonly RingKey[]
  signerId: string | null
  onSigner: (id: string) => void
  onGenerate: () => void
  onImport: () => void
}

export function SignSettings({
  level,
  options,
  onOptions,
  privateKeys,
  signerId,
  onSigner,
  onGenerate,
  onImport,
}: SignSettingsProps) {
  const { t, formatNumber } = useI18n()
  const advanced = level === 'advanced'
  const bits = privateKeys.find((key) => key.id === signerId)?.bits ?? FALLBACK_BITS
  const maxSalt = pssMaxSaltLength(bits, options.hash)

  return (
    <Panel as="aside" className="overflow-hidden">
      <SettingsSection title={t('sign.signer')}>
        {privateKeys.length === 0 ? (
          <KeyringEmpty
            title={t('sign.noPrivateTitle')}
            body={t('sign.noPrivateBody')}
            onGenerate={onGenerate}
            onImport={onImport}
          />
        ) : (
          <>
            <p className="text-xs leading-relaxed text-muted-foreground">{t('sign.signerHint')}</p>
            <KeyPicker
              ariaLabel={t('sign.signer')}
              keys={privateKeys}
              value={signerId ? [signerId] : []}
              onChange={(ids) => onSigner(ids[0])}
            />
            <KeyShortcuts onGenerate={onGenerate} onImport={onImport} />
          </>
        )}
      </SettingsSection>

      {!advanced && (
        <SettingsSection title={t('aes.basicSummary')}>
          <DetailsList rows={[{ label: t('aes.sumAlgorithm'), value: t('sign.basicScheme') }]} />
          <AdvancedLink />
        </SettingsSection>
      )}

      {advanced && (
        <>
          <SettingsSection title={t('sign.scheme')}>
            <ChoiceCards<SignatureScheme>
              ariaLabel={t('sign.scheme')}
              value={options.scheme}
              onValueChange={(scheme) => onOptions({ scheme })}
              options={[
                {
                  value: 'RSA-PSS',
                  label: SCHEME_LABEL['RSA-PSS'],
                  description: t('sign.schemePssHint'),
                  badge: <Tag tone="good">{t('common.recommended')}</Tag>,
                },
                {
                  value: 'RSASSA-PKCS1-v1_5',
                  label: SCHEME_LABEL['RSASSA-PKCS1-v1_5'],
                  description: t('sign.schemePkcs1Hint'),
                },
              ]}
            />
          </SettingsSection>

          <SettingsSection title={t('sign.hash')}>
            <HashPicker ariaLabel={t('sign.hash')} value={options.hash} onChange={(hash) => onOptions({ hash })} />
            {options.scheme === 'RSA-PSS' && (
              <NumberField
                label={t('sign.saltLength')}
                min={0}
                max={maxSalt}
                value={options.saltLength ?? defaultSaltLength(bits, options.hash)}
                onChange={(saltLength) => onOptions({ saltLength })}
                hint={t('sign.saltHint', { max: formatNumber(maxSalt) })}
              />
            )}
          </SettingsSection>

          <SettingsSection title={t('sign.output')}>
            <ChoiceCards<SignOptions['format']>
              ariaLabel={t('sign.output')}
              value={options.format}
              onValueChange={(format) => onOptions({ format })}
              options={[
                {
                  value: 'edt',
                  label: t('aes.formatEdt'),
                  description: t('sign.formatEdtHint'),
                  badge: <Tag tone="good">{t('common.recommended')}</Tag>,
                },
                { value: 'raw', label: t('aes.formatRaw'), description: t('sign.formatRawHint') },
              ]}
            />
            {options.format === 'raw' && (
              <Segmented<SignOptions['encoding']>
                ariaLabel={t('aes.encoding')}
                size="sm"
                value={options.encoding}
                onValueChange={(encoding) => onOptions({ encoding })}
                options={[
                  { value: 'base64', label: 'Base64' },
                  { value: 'hex', label: 'Hex' },
                ]}
              />
            )}
          </SettingsSection>
        </>
      )}
    </Panel>
  )
}

interface VerifySettingsProps {
  level: Level
  inspection: InspectState
  keys: readonly RingKey[]
  verifierId: string | null
  onVerifier: (id: string) => void
  raw: RawVerifyParams
  onRaw: (patch: Partial<RawVerifyParams>) => void
  onImport: () => void
}

export function VerifySettings({
  level,
  inspection,
  keys,
  verifierId,
  onVerifier,
  raw,
  onRaw,
  onImport,
}: VerifySettingsProps) {
  const { t, formatNumber } = useI18n()
  const advanced = level === 'advanced'
  const result = inspection.status === 'ok' ? inspection.result : null
  const summary = result && result.container !== 'raw' ? result.summary : null
  const signatureKeyId = summary?.kind === 'signature' ? summary.keyId : undefined
  const signerKey = signatureKeyId ? keys.find((key) => key.id === signatureKeyId) : undefined
  const isRaw = result?.container === 'raw'
  const bits = keys.find((key) => key.id === verifierId)?.bits ?? FALLBACK_BITS
  const maxSalt = pssMaxSaltLength(bits, raw.hash)

  let detected = '...'
  if (inspection.status === 'invalid') detected = t('aes.detectInvalid')
  else if (result?.container === 'raw') detected = t('aes.detectRaw', { encoding: result.encoding })
  else if (result?.container === 'openssl') detected = t('aes.detectOpenssl')
  else if (summary?.kind === 'signature') detected = t('aes.detectEdtSignature')
  else if (summary?.kind === 'aes') detected = t('aes.detectEdtAes')
  else if (summary?.kind === 'rsa-hybrid') detected = t('rsa.detectHybrid')
  else if (summary?.kind === 'rsa') detected = t('rsa.detectDirect')

  // A ciphertext pasted into the signature box belongs to one of the encryption pages.
  const elsewhere =
    summary && summary.kind !== 'signature'
      ? summary.kind === 'rsa' || summary.kind === 'rsa-hybrid'
        ? { route: 'rsa' as const, label: t('nav.rsa') }
        : { route: 'aes' as const, label: t('nav.aes') }
      : null

  let verifier
  if (keys.length === 0) {
    verifier = <KeyringEmpty title={t('sign.noPublicTitle')} body={t('sign.noPublicBody')} onImport={onImport} />
  } else if (signatureKeyId) {
    verifier = (
      <>
        <div className="flex min-w-0 flex-wrap items-center justify-between gap-x-2 gap-y-1 rounded-lg bg-muted/50 p-2.5">
          <KeyReference id={signatureKeyId} />
          <Tag tone={signerKey ? 'good' : 'warn'}>{signerKey ? t('sign.keyFound') : t('rsa.recipientUnknown')}</Tag>
        </div>
        {signerKey ? (
          <p className="text-xs leading-relaxed text-muted-foreground">{t('sign.verifierAutoHint')}</p>
        ) : (
          <KeyringEmpty title={t('sign.unknownSigner')} body={t('sign.noPublicBody')} onImport={onImport} />
        )}
      </>
    )
  } else if (isRaw && advanced) {
    verifier = (
      <>
        <p className="text-xs leading-relaxed text-muted-foreground">{t('sign.verifierRawHint')}</p>
        <KeyPicker
          ariaLabel={t('sign.verifier')}
          keys={keys}
          value={verifierId ? [verifierId] : []}
          onChange={(ids) => onVerifier(ids[0])}
        />
        <KeyShortcuts onImport={onImport} />
      </>
    )
  } else if (isRaw) {
    verifier = (
      <>
        <p className="text-xs leading-relaxed text-muted-foreground">{t('sign.formatRawHint')}</p>
        <AdvancedLink />
      </>
    )
  } else {
    verifier = <p className="text-xs leading-relaxed text-muted-foreground">{t('sign.verifierAutoHint')}</p>
  }

  return (
    <Panel as="aside" className="overflow-hidden">
      <SettingsSection title={t('aes.detected')}>
        <DetectionSummary recognized={result !== null} label={detected}>
          {summary?.kind === 'signature' && summary.scheme && (
            <p className="mt-0.5 text-xs text-muted-foreground">
              {SCHEME_LABEL[summary.scheme]}, {summary.rsaHash}
            </p>
          )}
          {inspection.status === 'invalid' && (
            <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{describeError(inspection.error, t)}</p>
          )}
          {isRaw && (
            <p className="mt-0.5 text-xs text-muted-foreground">{formatSize(result.byteLength, formatNumber)}</p>
          )}
        </DetectionSummary>
        {(elsewhere || result?.container === 'openssl') && (
          <Callout
            tone="info"
            action={
              <Button size="sm" variant="outline" onClick={() => navigate(elsewhere?.route ?? 'aes')}>
                {elsewhere?.label ?? t('nav.aes')}
                <ArrowRightIcon />
              </Button>
            }
          >
            {t('sign.notSignatureCipher')}
          </Callout>
        )}
      </SettingsSection>

      {!elsewhere && result?.container !== 'openssl' && (
        <SettingsSection title={t('sign.verifier')}>{verifier}</SettingsSection>
      )}

      {isRaw && advanced && keys.length > 0 && (
        <SettingsSection title={t('sign.rawParams')}>
          <Segmented<SignatureScheme>
            ariaLabel={t('sign.scheme')}
            size="sm"
            fullWidth
            value={raw.scheme}
            onValueChange={(scheme) => onRaw({ scheme })}
            options={[
              { value: 'RSA-PSS', label: SCHEME_LABEL['RSA-PSS'] },
              { value: 'RSASSA-PKCS1-v1_5', label: SCHEME_LABEL['RSASSA-PKCS1-v1_5'] },
            ]}
          />
          <HashPicker ariaLabel={t('sign.hash')} value={raw.hash} onChange={(hash) => onRaw({ hash })} />
          {raw.scheme === 'RSA-PSS' && (
            <>
              <label className="flex items-start justify-between gap-3">
                <span>
                  <span className="block text-sm font-medium">{t('sign.saltAuto')}</span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                    {t('sign.saltAutoHint')}
                  </span>
                </span>
                <Switch
                  className="mt-0.5"
                  checked={raw.saltLength === null}
                  onCheckedChange={(auto) => onRaw({ saltLength: auto ? null : defaultSaltLength(bits, raw.hash) })}
                />
              </label>
              {raw.saltLength !== null && (
                <NumberField
                  label={t('sign.saltLength')}
                  min={0}
                  max={maxSalt}
                  value={raw.saltLength}
                  onChange={(saltLength) => onRaw({ saltLength })}
                />
              )}
            </>
          )}
        </SettingsSection>
      )}
    </Panel>
  )
}
