import { ArrowRightIcon } from '@phosphor-icons/react'
import { navigate } from '@/app/routes'
import { AdvancedLink } from '@/components/common/advanced-link'
import { Callout } from '@/components/common/callout'
import { ChoiceCards, Tag } from '@/components/common/choice'
import { DetailsList } from '@/components/common/output'
import { Segmented } from '@/components/common/segmented'
import { SettingsPanel, SettingsSection } from '@/components/common/settings-section'
import { DetectionSummary } from '@/components/crypto/detection-summary'
import { HashPicker } from '@/components/crypto/hash-picker'
import { KeyReference } from '@/components/crypto/summary-details'
import { Button } from '@/components/ui/button'
import { KeyPicker, KeyringEmpty } from '@/features/keys/key-picker'
import type { InspectState } from '@/hooks/use-inspection'
import { useI18n } from '@/i18n'
import { oaepMaxMessageBytes, type RsaHash } from '@/lib/crypto/rsa-params'
import { describeError } from '@/lib/describe-error'
import { formatSize } from '@/lib/format'
import type { RingKey } from '@/stores/keyring'
import type { Level } from '@/stores/settings'
import { fitsOaep, type RsaOptions } from './options'

interface EncryptSettingsProps {
  level: Level
  options: RsaOptions
  onOptions: (patch: Partial<RsaOptions>) => void
  keys: readonly RingKey[]
  recipients: string[]
  onRecipients: (ids: string[]) => void
  onGenerate: () => void
  onImport: () => void
}

export function RsaEncryptSettings({
  level,
  options,
  onOptions,
  keys,
  recipients,
  onRecipients,
  onGenerate,
  onImport,
}: EncryptSettingsProps) {
  const { t, formatNumber } = useI18n()
  const advanced = level === 'advanced'
  const direct = options.scheme === 'direct'
  const firstRecipient = keys.find((key) => key.id === recipients[0])
  const directMax = firstRecipient ? oaepMaxMessageBytes(firstRecipient.bits, options.hash) : null
  const tooSmall = (direct ? [firstRecipient] : recipients.map((id) => keys.find((key) => key.id === id))).find(
    (key) => key && !fitsOaep(key.bits, options.hash, options.scheme),
  )

  return (
    <SettingsPanel title={t('aes.encryptSettings')}>
      <SettingsSection title={t('rsa.recipients')}>
        {keys.length === 0 ? (
          <KeyringEmpty
            title={t('rsa.noKeysTitle')}
            body={t('rsa.noKeysBody')}
            onGenerate={onGenerate}
            onImport={onImport}
          />
        ) : (
          <>
            <p className="text-xs leading-relaxed text-muted-foreground">
              {direct ? t('rsa.recipientsDirect') : t('rsa.recipientsHint')}
            </p>
            <KeyPicker
              ariaLabel={t('rsa.recipients')}
              keys={keys}
              multiple={!direct}
              value={direct ? recipients.slice(0, 1) : recipients}
              onChange={onRecipients}
            />
            <div className="flex flex-wrap gap-1">
              <Button variant="ghost" size="xs" onClick={onGenerate}>
                {t('keys.generate')}
              </Button>
              <Button variant="ghost" size="xs" onClick={onImport}>
                {t('keys.import')}
              </Button>
            </div>
          </>
        )}
      </SettingsSection>

      {!advanced && (
        <SettingsSection title={t('aes.basicSummary')}>
          <DetailsList
            rows={[
              { label: t('aes.sumAlgorithm'), value: t('rsa.basicScheme') },
              { label: t('aes.sumContainer'), value: t('aes.formatEdt') },
            ]}
          />
          <AdvancedLink />
        </SettingsSection>
      )}

      {advanced && (
        <>
          <SettingsSection title={t('rsa.scheme')}>
            <ChoiceCards<RsaOptions['scheme']>
              ariaLabel={t('rsa.scheme')}
              value={options.scheme}
              onValueChange={(scheme) => onOptions({ scheme })}
              options={[
                {
                  value: 'hybrid',
                  label: t('rsa.schemeHybrid'),
                  description: t('rsa.schemeHybridHint'),
                  badge: <Tag tone="good">{t('common.recommended')}</Tag>,
                },
                {
                  value: 'direct',
                  label: t('rsa.schemeDirect'),
                  description:
                    directMax === null || directMax < 1
                      ? t('rsa.schemeDirectHintNoKey')
                      : t('rsa.schemeDirectHint', { max: formatNumber(directMax) }),
                },
              ]}
            />
          </SettingsSection>
          <SettingsSection title={t('rsa.hash')}>
            <HashPicker ariaLabel={t('rsa.hash')} value={options.hash} onChange={(hash) => onOptions({ hash })} />
            {tooSmall && (
              <p className="text-xs leading-relaxed text-destructive">
                {t('rsa.keyTooSmall', { name: tooSmall.name, bits: tooSmall.bits, hash: options.hash })}
              </p>
            )}
          </SettingsSection>
          {direct && (
            <SettingsSection title={t('rsa.output')}>
              <ChoiceCards<RsaOptions['format']>
                ariaLabel={t('rsa.output')}
                value={options.format}
                onValueChange={(format) => onOptions({ format })}
                options={[
                  { value: 'edt', label: t('aes.formatEdt'), description: t('rsa.formatEdtHint') },
                  { value: 'raw', label: t('aes.formatRaw'), description: t('rsa.formatRawHint') },
                ]}
              />
              {options.format === 'raw' && (
                <Segmented<'base64' | 'hex'>
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
          )}
        </>
      )}
    </SettingsPanel>
  )
}

interface DecryptSettingsProps {
  level: Level
  inspection: InspectState
  keys: readonly RingKey[]
  rawKeyId: string | null
  onRawKey: (id: string) => void
  rawHash: RsaHash
  onRawHash: (hash: RsaHash) => void
  onImport: () => void
}

export function RsaDecryptSettings({
  level,
  inspection,
  keys,
  rawKeyId,
  onRawKey,
  rawHash,
  onRawHash,
  onImport,
}: DecryptSettingsProps) {
  const { t, formatNumber } = useI18n()
  const advanced = level === 'advanced'
  const result = inspection.status === 'ok' ? inspection.result : null
  const summary = result && result.container !== 'raw' ? result.summary : null
  const isRsa = summary?.kind === 'rsa' || summary?.kind === 'rsa-hybrid'
  const privateKeys = keys.filter((key) => key.pkcs8)
  const recipients = summary?.recipients ?? []
  const matching = recipients.filter((recipient) => privateKeys.some((key) => key.id === recipient.keyId))

  let detected = t('aes.detectWaiting')
  if (inspection.status === 'invalid') detected = t('aes.detectInvalid')
  else if (result?.container === 'raw') detected = t('aes.detectRaw', { encoding: result.encoding })
  else if (result?.container === 'openssl') detected = t('aes.detectOpenssl')
  else if (summary?.kind === 'rsa-hybrid') detected = t('rsa.detectHybrid')
  else if (summary?.kind === 'rsa') detected = t('rsa.detectDirect')
  else if (summary?.kind === 'aes') detected = t('aes.detectEdtAes')
  else if (summary?.kind === 'signature') detected = t('aes.detectEdtSignature')

  const elsewhere =
    result?.container === 'openssl' || summary?.kind === 'aes'
      ? { note: t('rsa.notRsaAes'), route: 'aes' as const, label: t('nav.aes') }
      : summary?.kind === 'signature'
        ? { note: t('rsa.notRsaSignature'), route: 'sign' as const, label: t('nav.sign') }
        : null

  return (
    <SettingsPanel title={t('aes.decryptSettings')}>
      <SettingsSection title={t('aes.detected')}>
        <DetectionSummary recognized={result !== null} label={detected}>
          {inspection.status === 'invalid' && (
            <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{describeError(inspection.error, t)}</p>
          )}
          {result && (
            <p className="mt-0.5 text-xs text-muted-foreground">{formatSize(result.byteLength, formatNumber)}</p>
          )}
        </DetectionSummary>

        {isRsa && recipients.length > 0 && (
          <ul className="flex flex-col gap-2 rounded-lg bg-muted/50 p-2.5">
            {recipients.map((recipient) => {
              const key = keys.find((item) => item.id === recipient.keyId)
              const status = key?.pkcs8 ? 'ready' : key ? 'public' : 'unknown'
              return (
                <li
                  key={recipient.keyId}
                  className="flex min-w-0 flex-wrap items-center justify-between gap-x-2 gap-y-1"
                >
                  <KeyReference id={recipient.keyId} />
                  <Tag tone={status === 'ready' ? 'good' : status === 'public' ? 'warn' : 'neutral'}>
                    {status === 'ready'
                      ? t('rsa.recipientReady')
                      : status === 'public'
                        ? t('rsa.recipientPublicOnly')
                        : t('rsa.recipientUnknown')}
                  </Tag>
                </li>
              )
            })}
          </ul>
        )}

        {elsewhere && (
          <Callout
            tone="info"
            action={
              <Button size="sm" variant="outline" onClick={() => navigate(elsewhere.route)}>
                {elsewhere.label}
                <ArrowRightIcon />
              </Button>
            }
          >
            {elsewhere.note}
          </Callout>
        )}
      </SettingsSection>

      {!elsewhere && (
        <SettingsSection title={t('rsa.decryptKey')}>
          {result?.container === 'raw' ? (
            advanced ? (
              privateKeys.length === 0 ? (
                <KeyringEmpty title={t('rsa.noPrivateTitle')} body={t('rsa.noPrivateBody')} onImport={onImport} />
              ) : (
                <>
                  <KeyPicker
                    ariaLabel={t('rsa.rawKey')}
                    keys={privateKeys}
                    value={rawKeyId ? [rawKeyId] : []}
                    onChange={(ids) => onRawKey(ids[0])}
                  />
                  <HashPicker ariaLabel={t('rsa.hash')} value={rawHash} onChange={onRawHash} />
                </>
              )
            ) : (
              <>
                <p className="text-xs leading-relaxed text-muted-foreground">{t('rsa.formatRawHint')}</p>
                <AdvancedLink />
              </>
            )
          ) : isRsa && matching.length === 0 ? (
            <KeyringEmpty title={t('rsa.noPrivateTitle')} body={t('rsa.noPrivateBody')} onImport={onImport} />
          ) : (
            <p className="text-xs leading-relaxed text-muted-foreground">{t('rsa.decryptAuto')}</p>
          )}
        </SettingsSection>
      )}
    </SettingsPanel>
  )
}
