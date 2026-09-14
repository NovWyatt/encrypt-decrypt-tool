import { useEffect, useState } from 'react'
import { DownloadSimpleIcon, LockKeyIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { Callout } from '@/components/common/callout'
import { CopyButton } from '@/components/common/copy-button'
import { ErrorAlert } from '@/components/common/error-alert'
import { PasswordField } from '@/components/common/secret-fields'
import { Segmented } from '@/components/common/segmented'
import { Button } from '@/components/ui/button'
import { Field, FieldLabel } from '@/components/ui/field'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Spinner } from '@/components/ui/spinner'
import { useI18n, type TKey } from '@/i18n'
import { callCrypto } from '@/lib/crypto/client'
import type { KeyExportFormat } from '@/lib/crypto/service'
import { InputProblem } from '@/lib/describe-error'
import { downloadBlob, fileSlug } from '@/lib/files'
import { markPrivateSaved, type RingKey } from '@/stores/keyring'

type Part = 'public' | 'private'

const FORMATS: Record<Part, Array<{ value: KeyExportFormat; label: TKey }>> = {
  public: [
    { value: 'spki-pem', label: 'keys.fmtSpki' },
    { value: 'openssh', label: 'keys.fmtOpenssh' },
    { value: 'jwk-public', label: 'keys.fmtJwkPublic' },
    { value: 'pkcs1-public-pem', label: 'keys.fmtPkcs1Public' },
  ],
  private: [
    { value: 'encrypted-pkcs8-pem', label: 'keys.fmtEncryptedPkcs8' },
    { value: 'pkcs8-pem', label: 'keys.fmtPkcs8' },
    { value: 'pkcs1-private-pem', label: 'keys.fmtPkcs1Private' },
    { value: 'jwk-private', label: 'keys.fmtJwkPrivate' },
  ],
}

interface ExportOutput {
  keyId: string
  format: KeyExportFormat
  text: string
  extension: string
}

export function KeyExport({ ringKey }: { ringKey: RingKey }) {
  const { t } = useI18n()
  const [part, setPart] = useState<Part>('public')
  const [formats, setFormats] = useState<Record<Part, KeyExportFormat>>({
    public: 'spki-pem',
    private: 'encrypted-pkcs8-pem',
  })
  const [passphrase, setPassphrase] = useState('')
  const [output, setOutput] = useState<ExportOutput | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const activePart: Part = ringKey.pkcs8 ? part : 'public'
  const format = formats[activePart]
  const encrypted = format === 'encrypted-pkcs8-pem'
  const current = output && output.keyId === ringKey.id && output.format === format ? output : null
  const isPrivate = activePart === 'private'

  // Everything except the passphrase-protected file is derived instantly from the key.
  useEffect(() => {
    if (encrypted) return
    let cancelled = false
    const material = { spki: ringKey.spki, pkcs8: isPrivate ? ringKey.pkcs8 : undefined }
    callCrypto('exportKey', material, format, { comment: fileSlug(ringKey.name) }).then(
      (result) => {
        if (cancelled) return
        setOutput({ keyId: ringKey.id, format, ...result })
        setError(null)
      },
      (caught: unknown) => !cancelled && setError(caught),
    )
    return () => {
      cancelled = true
    }
  }, [ringKey, format, encrypted, isPrivate])

  const createEncrypted = async () => {
    if (!passphrase) return setError(new InputProblem('errors.emptyPassphrase'))
    setBusy(true)
    setError(null)
    try {
      const result = await callCrypto('exportKey', { spki: ringKey.spki, pkcs8: ringKey.pkcs8 }, format, { passphrase })
      setOutput({ keyId: ringKey.id, format, ...result })
    } catch (caught) {
      setError(caught)
    } finally {
      setBusy(false)
    }
  }

  const saved = () => {
    if (isPrivate) markPrivateSaved(ringKey.id)
  }
  const fileName = current ? `${fileSlug(ringKey.name)}${current.extension}` : ''

  return (
    <div className="flex flex-col gap-3">
      {ringKey.pkcs8 ? (
        <Segmented<Part>
          ariaLabel={t('keys.export')}
          size="sm"
          fullWidth
          value={activePart}
          onValueChange={(next) => {
            setPart(next)
            setError(null)
          }}
          options={[
            { value: 'public', label: t('keys.exportPublic') },
            { value: 'private', label: t('keys.exportPrivate') },
          ]}
        />
      ) : (
        <p className="text-xs leading-relaxed text-muted-foreground">{t('keys.noPrivate')}</p>
      )}

      <Field className="gap-1.5">
        <FieldLabel className="text-xs font-medium text-muted-foreground">{t('keys.exportFormat')}</FieldLabel>
        <Select
          value={format}
          onValueChange={(next) => {
            setFormats((currentFormats) => ({ ...currentFormats, [activePart]: next as KeyExportFormat }))
            setError(null)
          }}
        >
          <SelectTrigger className="h-9 w-full" aria-label={t('keys.exportFormat')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {FORMATS[activePart].map((item) => (
              <SelectItem key={item.value} value={item.value}>
                {t(item.label)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>

      {encrypted && (
        <>
          <PasswordField
            label={t('keys.exportPassphrase')}
            value={passphrase}
            onChange={(value) => {
              setPassphrase(value)
              setError(null)
            }}
            hint={t('keys.exportPassphraseHint')}
            showStrength
            allowGenerate
            autoComplete="new-password"
          />
          <Button type="button" variant="outline" className="self-start" onClick={createEncrypted} disabled={busy}>
            {busy ? <Spinner /> : <LockKeyIcon />}
            {t('keys.exportCreate')}
          </Button>
        </>
      )}

      {isPrivate && !encrypted && <Callout tone="warn">{t('keys.privateWarning')}</Callout>}
      {error !== null && <ErrorAlert error={error} />}

      {current && (
        <div className="overflow-hidden rounded-lg border">
          <pre
            tabIndex={0}
            aria-label={t('keys.exportPreview')}
            className={cn(
              'max-h-56 scrollbar-thin overflow-auto bg-muted/40 px-3 py-2.5 font-mono text-[0.6875rem] leading-relaxed outline-none focus-visible:ring-3 focus-visible:ring-ring/40',
              // PEM keeps its 64-column lines; single-line formats (OpenSSH, JWK values) wrap anywhere.
              current.format.endsWith('-pem') ? 'whitespace-pre' : 'break-all whitespace-pre-wrap',
            )}
          >
            {current.text}
          </pre>
          <div className="flex flex-wrap items-center gap-2 border-t px-2.5 py-2">
            <CopyButton value={current.text} onCopied={saved} />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                downloadBlob(current.text, fileName, 'text/plain;charset=utf-8')
                saved()
              }}
            >
              <DownloadSimpleIcon />
              {t('common.download')}
            </Button>
            <span className="ml-auto truncate font-mono text-[0.6875rem] text-muted-foreground">{fileName}</span>
          </div>
        </div>
      )}
    </div>
  )
}
