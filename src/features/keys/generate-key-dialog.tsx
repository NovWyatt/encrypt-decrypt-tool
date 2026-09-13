import { useState, type FormEvent, type ReactNode } from 'react'
import { KeyIcon } from '@phosphor-icons/react'
import { toast } from 'sonner'
import { ChoiceCards, Tag } from '@/components/common/choice'
import { ErrorAlert } from '@/components/common/error-alert'
import { Segmented } from '@/components/common/segmented'
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
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import { useI18n } from '@/i18n'
import { callCrypto } from '@/lib/crypto/client'
import { addKeys, toRingKey, type RingKey } from '@/stores/keyring'
import { useSettings } from '@/stores/settings'

type SizeOption = '1024' | '2048' | '3072' | '4096'

interface GenerateKeyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated?: (key: RingKey) => void
}

export function GenerateKeyDialog({ open, onOpenChange, onCreated }: GenerateKeyDialogProps) {
  const { t } = useI18n()
  const { level } = useSettings()
  const advanced = level === 'advanced'
  const [name, setName] = useState('')
  const [size, setSize] = useState<SizeOption>('3072')
  const [exponent, setExponent] = useState<'65537' | '3'>('65537')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const bits = Number(size === '1024' && !advanced ? '3072' : size)

  const setOpen = (next: boolean) => {
    if (busy) return
    onOpenChange(next)
    if (!next) {
      setName('')
      setError(null)
    }
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const info = await callCrypto('generateKey', bits, advanced ? Number(exponent) : 65537)
      const key = toRingKey(info, 'generated', name.trim() || t('keys.defaultName', { bits }))
      addKeys([key])
      toast.success(t('keys.generatedToast'))
      onCreated?.(key)
      onOpenChange(false)
      setName('')
    } catch (caught) {
      setError(caught)
    } finally {
      setBusy(false)
    }
  }

  const sizes: Array<{ value: SizeOption; description: string; badge?: ReactNode }> = [
    { value: '2048', description: t('keys.size2048') },
    { value: '3072', description: t('keys.size3072'), badge: <Tag tone="good">{t('common.recommended')}</Tag> },
    { value: '4096', description: t('keys.size4096') },
  ]
  if (advanced)
    sizes.unshift({
      value: '1024',
      description: t('keys.size1024'),
      badge: <Tag tone="bad">{t('common.insecure')}</Tag>,
    })

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="gap-0 p-0 sm:max-w-lg" closeLabel={t('common.close')}>
        <form onSubmit={submit}>
          <DialogHeader className="px-5 pt-5 pb-4">
            <DialogTitle className="text-lg font-semibold">{t('keys.generateTitle')}</DialogTitle>
            <DialogDescription>{t('keys.generateDescription')}</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-5 px-5 pb-5">
            <Field className="gap-1.5">
              <FieldLabel htmlFor="generate-key-name">{t('keys.name')}</FieldLabel>
              <Input
                id="generate-key-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder={t('keys.defaultName', { bits })}
                autoComplete="off"
                maxLength={80}
                className="h-9"
              />
            </Field>
            <Field className="gap-1.5">
              <FieldLabel>{t('keys.keySize')}</FieldLabel>
              <ChoiceCards<SizeOption>
                ariaLabel={t('keys.keySize')}
                value={size}
                onValueChange={setSize}
                options={sizes.map((option) => ({
                  value: option.value,
                  label: `${option.value} bit`,
                  description: option.description,
                  badge: option.badge,
                }))}
              />
            </Field>
            {advanced && (
              <Field className="gap-1.5">
                <FieldLabel>{t('keys.exponent')}</FieldLabel>
                <Segmented<'65537' | '3'>
                  ariaLabel={t('keys.exponent')}
                  size="sm"
                  value={exponent}
                  onValueChange={setExponent}
                  options={[
                    { value: '65537', label: '65537 (F4)' },
                    { value: '3', label: '3' },
                  ]}
                />
              </Field>
            )}
            {error !== null && <ErrorAlert error={error} />}
          </div>
          <DialogFooter className="m-0 rounded-b-xl px-5 py-3.5">
            <Button type="button" variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={busy} className="min-w-36">
              {busy ? <Spinner /> : <KeyIcon weight="bold" />}
              {busy ? t('keys.generating') : t('keys.generate')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
