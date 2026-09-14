import { useId, useMemo, useState } from 'react'
import { DiceFiveIcon, EyeIcon, EyeSlashIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { toast } from 'sonner'
import { Field, FieldDescription, FieldError, FieldLabel } from '@/components/ui/field'
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from '@/components/ui/input-group'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useI18n, type TKey } from '@/i18n'
import { fromBase64, isHex, toHex } from '@/lib/crypto/encoding'
import { randomBytes } from '@/lib/crypto/random'
import { estimateStrength, generatePassword } from '@/lib/password'

function IconAction({ label, onClick, children }: { label: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <InputGroupButton size="icon-xs" aria-label={label} onClick={onClick}>
          {children}
        </InputGroupButton>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

const STRENGTH_KEYS: TKey[] = ['strength.s0', 'strength.s1', 'strength.s2', 'strength.s3', 'strength.s4']
const STRENGTH_COLORS = ['bg-destructive', 'bg-destructive', 'bg-warning', 'bg-success', 'bg-success']

function StrengthMeter({ password }: { password: string }) {
  const { t } = useI18n()
  const { score } = useMemo(() => estimateStrength(password), [password])
  if (!password) return null
  return (
    <div className="flex items-center gap-2.5" aria-live="polite">
      <div className="grid flex-1 grid-cols-4 gap-1" aria-hidden>
        {[1, 2, 3, 4].map((segment) => (
          <span
            key={segment}
            className={cn(
              'h-1 rounded-full transition-colors duration-300',
              score >= segment ? STRENGTH_COLORS[score] : 'bg-muted-foreground/15',
            )}
          />
        ))}
      </div>
      <span className="min-w-16 text-right text-xs font-medium text-muted-foreground">{t(STRENGTH_KEYS[score])}</span>
    </div>
  )
}

interface PasswordFieldProps {
  label: string
  value: string
  onChange: (value: string) => void
  hint?: string
  error?: string
  showStrength?: boolean
  allowGenerate?: boolean
  autoComplete?: 'new-password' | 'current-password' | 'off'
  placeholder?: string
}

export function PasswordField({
  label,
  value,
  onChange,
  hint,
  error,
  showStrength,
  allowGenerate,
  autoComplete = 'off',
  placeholder,
}: PasswordFieldProps) {
  const { t } = useI18n()
  const id = useId()
  const [visible, setVisible] = useState(false)

  const generate = () => {
    onChange(generatePassword())
    setVisible(true)
    toast.success(t('strength.generated'))
  }

  return (
    <Field data-invalid={Boolean(error) || undefined}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <InputGroup className="h-9">
        <InputGroupInput
          id={id}
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          autoComplete={autoComplete}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          placeholder={placeholder}
          aria-invalid={Boolean(error) || undefined}
          className={cn(visible && value && 'font-mono text-[0.8125rem]')}
        />
        <InputGroupAddon align="inline-end">
          <IconAction label={visible ? t('common.hide') : t('common.show')} onClick={() => setVisible((v) => !v)}>
            {visible ? <EyeSlashIcon /> : <EyeIcon />}
          </IconAction>
          {allowGenerate && (
            <IconAction label={t('strength.generate')} onClick={generate}>
              <DiceFiveIcon />
            </IconAction>
          )}
        </InputGroupAddon>
      </InputGroup>
      {showStrength && <StrengthMeter password={value} />}
      {error ? (
        <FieldError>{error}</FieldError>
      ) : (
        hint && <FieldDescription className="text-xs">{hint}</FieldDescription>
      )}
    </Field>
  )
}

/** Byte length of a hex or base64 key string, or null when it cannot be parsed. */
function keyTextBytes(text: string): number | null {
  const trimmed = text.trim()
  if (!trimmed) return null
  if (isHex(trimmed)) return trimmed.replace(/^0x/i, '').replace(/[\s:]/g, '').length / 2
  try {
    return fromBase64(trimmed).length
  } catch {
    return null
  }
}

interface KeyFieldProps {
  label: string
  bits: number
  value: string
  onChange: (value: string) => void
  hint?: string
  error?: string
  allowGenerate?: boolean
}

export function KeyField({ label, bits, value, onChange, hint, error, allowGenerate }: KeyFieldProps) {
  const { t } = useI18n()
  const id = useId()
  const [visible, setVisible] = useState(true)
  const bytes = keyTextBytes(value)
  const expected = bits / 8
  const status = value.trim() === '' ? 'empty' : bytes === expected ? 'ok' : 'bad'

  return (
    <Field data-invalid={Boolean(error) || undefined}>
      <div className="flex items-baseline justify-between gap-2">
        <FieldLabel htmlFor={id}>{label}</FieldLabel>
        <span
          className={cn(
            'font-mono text-xs tabular-nums',
            status === 'ok' ? 'text-success' : status === 'bad' ? 'text-destructive' : 'text-muted-foreground',
          )}
        >
          {bytes ?? 0}/{expected} B
        </span>
      </div>
      <InputGroup className="h-9">
        <InputGroupInput
          id={id}
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          aria-invalid={Boolean(error) || status === 'bad' || undefined}
          className="font-mono text-[0.8125rem]"
        />
        <InputGroupAddon align="inline-end">
          <IconAction label={visible ? t('common.hide') : t('common.show')} onClick={() => setVisible((v) => !v)}>
            {visible ? <EyeSlashIcon /> : <EyeIcon />}
          </IconAction>
          {allowGenerate && (
            <IconAction label={t('aes.generateKey')} onClick={() => onChange(toHex(randomBytes(expected)))}>
              <DiceFiveIcon />
            </IconAction>
          )}
        </InputGroupAddon>
      </InputGroup>
      {error ? (
        <FieldError>{error}</FieldError>
      ) : (
        hint && <FieldDescription className="text-xs">{hint}</FieldDescription>
      )}
    </Field>
  )
}
