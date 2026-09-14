import type { ReactNode } from 'react'
import { ArrowRightIcon, SlidersHorizontalIcon, WarningIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { navigate } from '@/app/routes'
import { AdvancedLink } from '@/components/common/advanced-link'
import { ChoiceCards, NumberField, Tag } from '@/components/common/choice'
import { DetectionSummary } from '@/components/crypto/detection-summary'
import { Panel } from '@/components/common/page'
import { SettingsSection } from '@/components/common/settings-section'
import { KeyField, PasswordField } from '@/components/common/secret-fields'
import { Segmented } from '@/components/common/segmented'
import { DetailsList } from '@/components/common/output'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { useI18n, type TKey } from '@/i18n'
import { IV_LENGTH, type AesKeyBits, type AesMode } from '@/lib/crypto/aes-params'
import { isWeakKdf, KDF_DEFAULTS, type KdfName } from '@/lib/crypto/kdf-params'
import type { InspectState } from '@/hooks/use-inspection'
import { describeError } from '@/lib/describe-error'
import { algorithmLabel, describeKdf } from '@/lib/format'
import { updateSettings, type Level } from '@/stores/settings'
import {
  decryptSecretKind,
  encryptSecretKind,
  selectedKdf,
  type AesOptions,
  type OpenSslDecryptOptions,
  type RawDecryptOptions,
  type SecretKind,
  type SecretState,
} from './options'

function InlineWarning({ children, tone = 'warn' }: { children: ReactNode; tone?: 'warn' | 'bad' }) {
  return (
    <p
      className={cn(
        'flex gap-2 rounded-md px-2.5 py-2 text-xs leading-relaxed',
        tone === 'warn' ? 'bg-warning/10 text-warning' : 'bg-destructive/10 text-destructive',
      )}
    >
      <WarningIcon weight="fill" className="mt-0.5 size-3.5 shrink-0" />
      <span>{children}</span>
    </p>
  )
}

const MODE_HINT: Record<AesMode, TKey> = {
  GCM: 'aes.modeGCM',
  CBC: 'aes.modeCBC',
  CTR: 'aes.modeCTR',
  ECB: 'aes.modeECB',
}

const KDF_HINT: Record<KdfName, TKey> = {
  Argon2id: 'aes.kdfArgon2id',
  scrypt: 'aes.kdfScrypt',
  PBKDF2: 'aes.kdfPBKDF2',
}

function ModePicker({
  mode,
  keyBits,
  onMode,
  onKeyBits,
  disableGcm,
}: {
  mode: AesMode
  keyBits: AesKeyBits
  onMode: (mode: AesMode) => void
  onKeyBits: (bits: AesKeyBits) => void
  disableGcm?: boolean
}) {
  const { t } = useI18n()
  return (
    <>
      <ChoiceCards<AesMode>
        ariaLabel={t('aes.mode')}
        columns={2}
        value={mode}
        onValueChange={onMode}
        options={[
          { value: 'GCM', label: 'GCM', badge: <Tag tone="good">{t('common.recommended')}</Tag>, disabled: disableGcm },
          { value: 'CBC', label: 'CBC' },
          { value: 'CTR', label: 'CTR' },
          { value: 'ECB', label: 'ECB', badge: <Tag tone="bad">{t('common.insecure')}</Tag> },
        ]}
      />
      <p className={cn('text-xs leading-relaxed', mode === 'ECB' ? 'text-destructive' : 'text-muted-foreground')}>
        {t(MODE_HINT[mode])}
      </p>
      <Field className="gap-1.5">
        <FieldLabel className="text-xs font-medium text-muted-foreground">{t('aes.keySize')}</FieldLabel>
        <Segmented<`${AesKeyBits}`>
          ariaLabel={t('aes.keySize')}
          size="sm"
          fullWidth
          value={`${keyBits}`}
          onValueChange={(next) => onKeyBits(Number(next) as AesKeyBits)}
          options={[
            { value: '128', label: '128 bit' },
            { value: '192', label: '192 bit' },
            { value: '256', label: '256 bit' },
          ]}
        />
      </Field>
    </>
  )
}

function KdfEditor({ options, onChange }: { options: AesOptions; onChange: (patch: Partial<AesOptions>) => void }) {
  const { t, formatNumber } = useI18n()
  const kdf = selectedKdf(options)
  return (
    <>
      <Select value={options.kdfName} onValueChange={(name) => onChange({ kdfName: name as KdfName })}>
        <SelectTrigger className="h-9 w-full" aria-label={t('aes.kdf')}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="Argon2id">Argon2id ({t('common.recommended')})</SelectItem>
          <SelectItem value="scrypt">scrypt</SelectItem>
          <SelectItem value="PBKDF2">PBKDF2</SelectItem>
        </SelectContent>
      </Select>
      <p className="text-xs leading-relaxed text-muted-foreground">{t(KDF_HINT[options.kdfName])}</p>

      {options.kdfName === 'Argon2id' && (
        <div className="grid grid-cols-3 gap-2">
          <NumberField
            label={t('aes.memory')}
            min={1}
            max={1024}
            value={options.argon2.memoryKiB / 1024}
            onChange={(mib) => onChange({ argon2: { ...options.argon2, memoryKiB: Math.round(mib * 1024) } })}
          />
          <NumberField
            label={t('aes.iterations')}
            min={1}
            max={64}
            value={options.argon2.iterations}
            onChange={(iterations) => onChange({ argon2: { ...options.argon2, iterations } })}
          />
          <NumberField
            label={t('aes.parallelism')}
            min={1}
            max={16}
            value={options.argon2.parallelism}
            onChange={(parallelism) => onChange({ argon2: { ...options.argon2, parallelism } })}
          />
        </div>
      )}
      {options.kdfName === 'scrypt' && (
        <div className="grid grid-cols-3 gap-2">
          <NumberField
            label={`${t('aes.scryptN')} 2^`}
            min={10}
            max={20}
            value={Math.log2(options.scrypt.N)}
            onChange={(log) => onChange({ scrypt: { ...options.scrypt, N: 2 ** Math.round(log) } })}
          />
          <NumberField
            label={t('aes.scryptR')}
            min={1}
            max={32}
            value={options.scrypt.r}
            onChange={(r) => onChange({ scrypt: { ...options.scrypt, r } })}
          />
          <NumberField
            label={t('aes.scryptP')}
            min={1}
            max={16}
            value={options.scrypt.p}
            onChange={(p) => onChange({ scrypt: { ...options.scrypt, p } })}
          />
        </div>
      )}
      {options.kdfName === 'PBKDF2' && (
        <div className="grid grid-cols-[1fr_1.4fr] gap-2">
          <Field className="gap-1.5">
            <FieldLabel className="text-xs font-medium text-muted-foreground">{t('aes.hash')}</FieldLabel>
            <Select
              value={options.pbkdf2.hash}
              onValueChange={(hash) => onChange({ pbkdf2: { ...options.pbkdf2, hash: hash as 'SHA-256' | 'SHA-512' } })}
            >
              <SelectTrigger className="h-8 w-full" aria-label={t('aes.hash')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="SHA-256">SHA-256</SelectItem>
                <SelectItem value="SHA-512">SHA-512</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <NumberField
            label={t('aes.iterations')}
            min={1000}
            max={10_000_000}
            step={1000}
            value={options.pbkdf2.iterations}
            onChange={(iterations) => onChange({ pbkdf2: { ...options.pbkdf2, iterations } })}
          />
        </div>
      )}
      {isWeakKdf(kdf) && <InlineWarning>{t('aes.weakKdf')}</InlineWarning>}
      {JSON.stringify(kdf) !== JSON.stringify(KDF_DEFAULTS[options.kdfName]) && (
        <Button
          variant="link"
          size="xs"
          className="self-start px-0"
          onClick={() =>
            onChange(
              options.kdfName === 'Argon2id'
                ? { argon2: { ...KDF_DEFAULTS.Argon2id } }
                : options.kdfName === 'scrypt'
                  ? { scrypt: { ...KDF_DEFAULTS.scrypt } }
                  : { pbkdf2: { ...KDF_DEFAULTS.PBKDF2 } },
            )
          }
        >
          {t('common.recommended')}: {describeKdf(KDF_DEFAULTS[options.kdfName], formatNumber)}
        </Button>
      )}
    </>
  )
}

function TextField({
  label,
  value,
  onChange,
  hint,
  mono,
  placeholder,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  hint?: string
  mono?: boolean
  placeholder?: string
}) {
  return (
    <Field className="gap-1.5">
      <FieldLabel className="text-xs font-medium text-muted-foreground">{label}</FieldLabel>
      <Input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        spellCheck={false}
        autoComplete="off"
        placeholder={placeholder}
        className={cn('h-8', mono && 'font-mono text-[0.8125rem]')}
      />
      {hint && <FieldDescription className="text-xs">{hint}</FieldDescription>}
    </Field>
  )
}

interface EncryptSettingsProps {
  level: Level
  options: AesOptions
  onOptions: (patch: Partial<AesOptions>) => void
  secret: SecretState
  onSecret: (patch: Partial<SecretState>) => void
  errors: { password?: string; key?: string }
}

export function EncryptSettings({ level, options, onOptions, secret, onSecret, errors }: EncryptSettingsProps) {
  const { t, formatNumber } = useI18n()
  const advanced = level === 'advanced'
  const kind = encryptSecretKind(level, options, secret)

  return (
    <Panel as="aside" className="overflow-hidden">
      <SettingsSection title={t('aes.keySection')}>
        {advanced && options.format === 'edt' && (
          <Segmented<SecretKind>
            ariaLabel={t('aes.keySection')}
            size="sm"
            fullWidth
            value={kind}
            onValueChange={(next) => onSecret({ kind: next })}
            options={[
              { value: 'password', label: t('aes.keyPassword') },
              { value: 'raw', label: t('aes.keyRaw') },
            ]}
          />
        )}
        {kind === 'password' ? (
          <PasswordField
            label={t('aes.password')}
            value={secret.password}
            onChange={(password) => onSecret({ password })}
            hint={t('aes.passwordHintEncrypt')}
            error={errors.password}
            showStrength
            allowGenerate
            autoComplete="new-password"
          />
        ) : (
          <KeyField
            label={t('aes.rawKey', { bits: options.keyBits })}
            bits={options.keyBits}
            value={secret.keyText}
            onChange={(keyText) => onSecret({ keyText })}
            hint={t('aes.rawKeyHint', { hex: options.keyBits / 4 })}
            error={errors.key}
            allowGenerate
          />
        )}
      </SettingsSection>

      {!advanced && (
        <SettingsSection title={t('aes.basicSummary')}>
          <DetailsList
            rows={[
              { label: t('aes.sumAlgorithm'), value: 'AES-256-GCM' },
              { label: t('aes.sumKdf'), value: describeKdf(KDF_DEFAULTS.Argon2id, formatNumber) },
              { label: t('aes.sumContainer'), value: t('aes.formatEdt') },
            ]}
          />
          <AdvancedLink />
        </SettingsSection>
      )}

      {advanced && (
        <>
          <SettingsSection title={t('aes.output')}>
            <ChoiceCards
              ariaLabel={t('aes.output')}
              value={options.format}
              onValueChange={(format) => onOptions({ format })}
              options={[
                {
                  value: 'edt',
                  label: t('aes.formatEdt'),
                  badge: <Tag tone="good">{t('common.recommended')}</Tag>,
                  description: t('aes.formatEdtHint'),
                },
                { value: 'openssl', label: t('aes.formatOpenssl'), description: t('aes.formatOpensslHint') },
                { value: 'raw', label: t('aes.formatRaw'), description: t('aes.formatRawHint') },
              ]}
            />
            {options.format !== 'edt' && (
              <div className="flex items-center justify-between gap-3">
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
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Switch
                    size="sm"
                    checked={options.wrapLines}
                    onCheckedChange={(wrapLines) => onOptions({ wrapLines })}
                  />
                  {t('aes.wrapLines')}
                </label>
              </div>
            )}
          </SettingsSection>

          <SettingsSection title={t('aes.algorithm')}>
            <ModePicker
              mode={options.mode}
              keyBits={options.keyBits}
              onMode={(mode) => onOptions({ mode })}
              onKeyBits={(keyBits) => onOptions({ keyBits })}
              disableGcm={options.format === 'openssl'}
            />
            {options.format === 'openssl' && (
              <p className="text-xs text-muted-foreground">{t('aes.gcmNotForOpenssl')}</p>
            )}
          </SettingsSection>

          {kind === 'password' && options.format === 'edt' && (
            <SettingsSection title={t('aes.kdf')}>
              <KdfEditor options={options} onChange={onOptions} />
            </SettingsSection>
          )}

          {options.format === 'openssl' && (
            <SettingsSection title={t('aes.opensslKdf')}>
              <ChoiceCards<'pbkdf2' | 'md5'>
                ariaLabel={t('aes.opensslKdf')}
                value={options.opensslKdf}
                onValueChange={(opensslKdf) => onOptions({ opensslKdf })}
                options={[
                  { value: 'pbkdf2', label: t('aes.opensslPbkdf2') },
                  { value: 'md5', label: t('aes.opensslMd5'), badge: <Tag tone="bad">{t('common.insecure')}</Tag> },
                ]}
              />
              {options.opensslKdf === 'pbkdf2' && (
                <NumberField
                  label={`${t('aes.iterations')} (-iter)`}
                  min={1000}
                  max={10_000_000}
                  step={1000}
                  value={options.opensslIterations}
                  onChange={(opensslIterations) => onOptions({ opensslIterations })}
                />
              )}
            </SettingsSection>
          )}

          {options.format === 'edt' && options.mode !== 'GCM' && (
            <SettingsSection title={t('aes.integrity')}>
              <label className="flex items-start justify-between gap-3">
                <span>
                  <span className="block text-sm font-medium">{t('aes.mac')}</span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">{t('aes.macHint')}</span>
                </span>
                <Switch className="mt-0.5" checked={options.mac} onCheckedChange={(mac) => onOptions({ mac })} />
              </label>
              {!options.mac && <InlineWarning>{t('aes.macOffWarning')}</InlineWarning>}
            </SettingsSection>
          )}

          {options.format !== 'openssl' && options.mode !== 'ECB' && (
            <SettingsSection>
              {options.mode === 'GCM' && (
                <TextField
                  label={`${t('aes.aad')}, ${t('common.optional')}`}
                  value={secret.aad}
                  onChange={(aad) => onSecret({ aad })}
                  hint={t('aes.aadHint')}
                />
              )}
              <TextField
                label={`${t('aes.iv')}, ${t('common.optional')}`}
                value={secret.iv}
                onChange={(iv) => onSecret({ iv })}
                hint={t('aes.ivHint')}
                placeholder={`${IV_LENGTH[options.mode] * 2} hex`}
                mono
              />
            </SettingsSection>
          )}
        </>
      )}
    </Panel>
  )
}

interface DecryptSettingsProps {
  level: Level
  inspection: InspectState
  secret: SecretState
  onSecret: (patch: Partial<SecretState>) => void
  openssl: OpenSslDecryptOptions
  onOpenssl: (patch: Partial<OpenSslDecryptOptions>) => void
  raw: RawDecryptOptions
  onRaw: (patch: Partial<RawDecryptOptions>) => void
  errors: { password?: string; key?: string }
}

export function DecryptSettings({
  level,
  inspection,
  secret,
  onSecret,
  openssl,
  onOpenssl,
  raw,
  onRaw,
  errors,
}: DecryptSettingsProps) {
  const { t, formatNumber } = useI18n()
  const advanced = level === 'advanced'
  const result = inspection.status === 'ok' ? inspection.result : null
  const summary = result && result.container !== 'raw' ? result.summary : null
  const headerKind = summary?.kind === 'aes' ? (summary.keySource === 'raw' ? 'raw' : 'password') : null
  const kind = decryptSecretKind(inspection, secret)
  const isRsa = summary && (summary.kind === 'rsa' || summary.kind === 'rsa-hybrid' || summary.kind === 'signature')
  const keyBits = summary?.keyBits ?? (result?.container === 'raw' ? raw.keyBits : 256)

  let detected: string = t('aes.detectInvalid')
  if (result?.container === 'raw') detected = t('aes.detectRaw', { encoding: result.encoding })
  else if (result?.container === 'openssl') detected = t('aes.detectOpenssl')
  else if (summary?.kind === 'aes') detected = t('aes.detectEdtAes')
  else if (summary?.kind === 'signature') detected = t('aes.detectEdtSignature')
  else if (summary) detected = t('aes.detectEdtRsa')

  return (
    <Panel as="aside" className="overflow-hidden">
      <SettingsSection title={t('aes.detected')}>
        <DetectionSummary
          recognized={result !== null}
          label={inspection.status === 'empty' ? t('aes.detectWaiting') : detected}
        >
          {summary?.kind === 'aes' && (
            <p className="mt-0.5 text-xs text-muted-foreground">
              {algorithmLabel(summary)}
              {summary.kdf ? `, ${describeKdf(summary.kdf, formatNumber)}` : ''}
            </p>
          )}
          {inspection.status === 'invalid' && (
            <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{describeError(inspection.error, t)}</p>
          )}
        </DetectionSummary>
        {isRsa && (
          <div className="flex flex-col gap-2.5 rounded-lg bg-muted/60 p-3">
            <p className="text-xs leading-relaxed">{t('aes.rsaHere')}</p>
            <Button
              size="sm"
              variant="outline"
              className="self-start"
              onClick={() => navigate(summary?.kind === 'signature' ? 'sign' : 'rsa')}
            >
              {summary?.kind === 'signature' ? t('nav.sign') : t('nav.rsa')}
              <ArrowRightIcon />
            </Button>
          </div>
        )}
      </SettingsSection>

      {!isRsa && (
        <SettingsSection title={t('aes.keySection')}>
          {advanced && !headerKind && !result && (
            <Segmented<SecretKind>
              ariaLabel={t('aes.keySection')}
              size="sm"
              fullWidth
              value={kind}
              onValueChange={(next) => onSecret({ kind: next })}
              options={[
                { value: 'password', label: t('aes.keyPassword') },
                { value: 'raw', label: t('aes.keyRaw') },
              ]}
            />
          )}
          {kind === 'password' ? (
            <PasswordField
              label={t('aes.password')}
              value={secret.password}
              onChange={(password) => onSecret({ password })}
              hint={t('aes.passwordHintDecrypt')}
              error={errors.password}
              autoComplete="current-password"
            />
          ) : (
            <KeyField
              label={t('aes.rawKey', { bits: keyBits })}
              bits={keyBits}
              value={secret.keyText}
              onChange={(keyText) => onSecret({ keyText })}
              hint={t('aes.rawKeyHint', { hex: keyBits / 4 })}
              error={errors.key}
            />
          )}
          {(summary?.aad || (result?.container === 'raw' && raw.mode === 'GCM' && advanced)) && (
            <TextField
              label={summary?.aad ? t('aes.aad') : `${t('aes.aad')}, ${t('common.optional')}`}
              value={secret.aad}
              onChange={(aad) => onSecret({ aad })}
              hint={summary?.aad ? t('aes.aadRequired') : t('aes.aadHint')}
            />
          )}
        </SettingsSection>
      )}

      {result?.container === 'openssl' && advanced && (
        <SettingsSection title={t('aes.opensslKdf')}>
          <label className="flex items-center justify-between gap-3 text-sm">
            {t('aes.opensslAuto')}
            <Switch checked={openssl.auto} onCheckedChange={(auto) => onOpenssl({ auto })} />
          </label>
          {!openssl.auto && (
            <>
              <Segmented<'CBC' | 'CTR' | 'ECB'>
                ariaLabel={t('aes.mode')}
                size="sm"
                fullWidth
                value={openssl.mode}
                onValueChange={(mode) => onOpenssl({ mode })}
                options={[
                  { value: 'CBC', label: 'CBC' },
                  { value: 'CTR', label: 'CTR' },
                  { value: 'ECB', label: 'ECB' },
                ]}
              />
              <Segmented<`${AesKeyBits}`>
                ariaLabel={t('aes.keySize')}
                size="sm"
                fullWidth
                value={`${openssl.keyBits}`}
                onValueChange={(bits) => onOpenssl({ keyBits: Number(bits) as AesKeyBits })}
                options={[
                  { value: '128', label: '128 bit' },
                  { value: '192', label: '192 bit' },
                  { value: '256', label: '256 bit' },
                ]}
              />
              <ChoiceCards<'pbkdf2' | 'md5'>
                ariaLabel={t('aes.opensslKdf')}
                value={openssl.kdf}
                onValueChange={(kdf) => onOpenssl({ kdf })}
                options={[
                  { value: 'pbkdf2', label: t('aes.opensslPbkdf2') },
                  { value: 'md5', label: t('aes.opensslMd5') },
                ]}
              />
              {openssl.kdf === 'pbkdf2' && (
                <NumberField
                  label={`${t('aes.iterations')} (-iter)`}
                  min={1}
                  max={10_000_000}
                  value={openssl.iterations}
                  onChange={(iterations) => onOpenssl({ iterations })}
                />
              )}
            </>
          )}
        </SettingsSection>
      )}

      {result?.container === 'raw' &&
        (advanced ? (
          <SettingsSection title={t('aes.rawParams')}>
            <ModePicker
              mode={raw.mode}
              keyBits={raw.keyBits}
              onMode={(mode) => onRaw({ mode })}
              onKeyBits={(keyBits) => onRaw({ keyBits })}
            />
            {raw.mode !== 'ECB' && (
              <TextField
                label={t('aes.ivRequired')}
                value={raw.iv}
                onChange={(iv) => onRaw({ iv })}
                placeholder={`${IV_LENGTH[raw.mode] * 2} hex`}
                mono
              />
            )}
          </SettingsSection>
        ) : (
          <SettingsSection>
            <p className="text-xs leading-relaxed text-muted-foreground">{t('aes.formatRawHint')}</p>
            <Button
              variant="outline"
              size="sm"
              className="self-start"
              onClick={() => updateSettings({ level: 'advanced' })}
            >
              <SlidersHorizontalIcon />
              {t('settings.advanced')}
            </Button>
          </SettingsSection>
        ))}
    </Panel>
  )
}
