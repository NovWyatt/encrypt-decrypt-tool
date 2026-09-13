import { useId, useRef, useState, type FormEvent } from 'react'
import { DownloadSimpleIcon, FolderOpenIcon, UploadSimpleIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { toast } from 'sonner'
import { ErrorAlert } from '@/components/common/error-alert'
import { PasswordField } from '@/components/common/secret-fields'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Field, FieldLabel } from '@/components/ui/field'
import { Spinner } from '@/components/ui/spinner'
import { useI18n } from '@/i18n'
import { callCrypto } from '@/lib/crypto/client'
import { toBase64 } from '@/lib/crypto/encoding'
import { CryptoError } from '@/lib/crypto/errors'
import { InputProblem } from '@/lib/describe-error'
import { loadFile } from '@/lib/files'
import { addKeys, toRingKey, type MergeResult } from '@/stores/keyring'

interface ImportKeyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onImported?: (result: MergeResult) => void
}

export function ImportKeyDialog({ open, onOpenChange, onImported }: ImportKeyDialogProps) {
  const { t } = useI18n()
  const textId = useId()
  const fileInput = useRef<HTMLInputElement>(null)
  const [text, setText] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [askPassphrase, setAskPassphrase] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const showPassphrase = askPassphrase || /ENCRYPTED/.test(text)

  const reset = () => {
    setText('')
    setPassphrase('')
    setAskPassphrase(false)
    setError(null)
  }

  const setOpen = (next: boolean) => {
    if (busy) return
    onOpenChange(next)
    if (!next) reset()
  }

  const readFile = async (file: File | undefined) => {
    if (!file) return
    try {
      const loaded = await loadFile(file)
      // Binary DER files are passed on as base64, which the importer also accepts.
      setText(loaded.text ?? toBase64(loaded.bytes))
      setError(null)
    } catch (caught) {
      setError(caught)
    }
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (!text.trim()) return setError(new InputProblem('errors.emptyKeyText'))
    setBusy(true)
    setError(null)
    try {
      const infos = await callCrypto('importKeys', text, passphrase || undefined)
      const result = addKeys(
        infos.map((info) => toRingKey(info, 'imported', t('keys.importedName', { bits: info.bits }))),
      )
      if (result.added.length) toast.success(t('keys.importedToast', { count: result.added.length }))
      if (result.upgraded.length) toast.success(t('keys.upgradedToast', { count: result.upgraded.length }))
      if (!result.added.length && !result.upgraded.length) toast.info(t('keys.duplicateToast'))
      onImported?.(result)
      onOpenChange(false)
      reset()
    } catch (caught) {
      if (caught instanceof CryptoError && caught.code === 'PASSPHRASE_REQUIRED') setAskPassphrase(true)
      setError(caught)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="gap-0 p-0 sm:max-w-xl" closeLabel={t('common.close')}>
        <form onSubmit={submit}>
          <DialogHeader className="px-5 pt-5 pb-4">
            <DialogTitle className="text-lg font-semibold">{t('keys.importTitle')}</DialogTitle>
            <DialogDescription>{t('keys.importDescription')}</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-4 px-5 pb-5">
            <Field className="gap-1.5">
              <div className="flex items-center justify-between gap-2">
                <FieldLabel htmlFor={textId}>{t('keys.keyText')}</FieldLabel>
                <input
                  ref={fileInput}
                  type="file"
                  className="sr-only"
                  tabIndex={-1}
                  aria-hidden
                  accept=".pem,.key,.pub,.crt,.cer,.der,.jwk,.json,.txt"
                  onChange={(event) => {
                    void readFile(event.target.files?.[0])
                    event.target.value = ''
                  }}
                />
                <Button type="button" variant="ghost" size="sm" onClick={() => fileInput.current?.click()}>
                  <FolderOpenIcon />
                  {t('common.openFile')}
                </Button>
              </div>
              <div
                className="relative"
                onDragOver={(event) => {
                  if (!event.dataTransfer.types.includes('Files')) return
                  event.preventDefault()
                  setDragging(true)
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => {
                  event.preventDefault()
                  setDragging(false)
                  void readFile(event.dataTransfer.files[0])
                }}
              >
                <textarea
                  id={textId}
                  value={text}
                  onChange={(event) => {
                    setText(event.target.value)
                    setError(null)
                  }}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder={
                    '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA…\n-----END PUBLIC KEY-----'
                  }
                  className={cn(
                    'block h-48 w-full resize-none scrollbar-thin rounded-lg border border-input bg-transparent px-3 py-2.5 font-mono text-xs leading-relaxed break-all transition-colors outline-none placeholder:text-muted-foreground/70 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30',
                    dragging && 'border-primary ring-3 ring-primary/20',
                  )}
                />
                {dragging && (
                  <div className="pointer-events-none absolute inset-1.5 grid place-items-center rounded-md border-2 border-dashed border-primary/60 bg-background/85">
                    <span className="flex items-center gap-2 text-sm font-medium text-primary">
                      <UploadSimpleIcon weight="bold" className="size-4" />
                      {t('common.dropHere')}
                    </span>
                  </div>
                )}
              </div>
            </Field>
            {showPassphrase && (
              <PasswordField
                label={t('keys.passphrase')}
                value={passphrase}
                onChange={(value) => {
                  setPassphrase(value)
                  setError(null)
                }}
                hint={t('keys.passphraseHint')}
                autoComplete="off"
              />
            )}
            {error !== null && <ErrorAlert error={error} />}
          </div>
          <DialogFooter className="m-0 rounded-b-xl px-5 py-3.5">
            <Button type="button" variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={busy} className="min-w-32">
              {busy ? <Spinner /> : <DownloadSimpleIcon weight="bold" />}
              {busy ? t('keys.importing') : t('keys.importAction')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
