import type { ReactNode } from 'react'
import { DownloadSimpleIcon, KeyIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { RadioGroup as RadioGroupPrimitive } from 'radix-ui'
import { KeyIdenticon } from '@/components/crypto/key-identicon'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { useI18n } from '@/i18n'
import { groupHex } from '@/lib/format'
import type { RingKey } from '@/stores/keyring'

const ROW =
  'group/key relative flex w-full min-w-0 items-center gap-2.5 rounded-lg border bg-transparent px-2.5 py-2 text-left transition-[background-color,border-color,box-shadow] outline-none hover:bg-muted/60 has-[:focus-visible]:ring-3 has-[:focus-visible]:ring-ring/50'
const ROW_SELECTED =
  'border-primary/60 bg-primary/[0.06] shadow-[inset_0_0_0_1px_var(--primary)] hover:bg-primary/[0.08] dark:bg-primary/10'

function KeySummary({ ringKey, aside }: { ringKey: RingKey; aside?: ReactNode }) {
  return (
    <>
      <KeyIdenticon id={ringKey.id} className="size-8" />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm leading-5 font-medium">{ringKey.name}</span>
        <span className="block truncate font-mono text-[0.6875rem] leading-4 text-muted-foreground">
          RSA {ringKey.bits} · {groupHex(ringKey.id, 4)}
        </span>
      </span>
      {aside}
    </>
  )
}

interface KeyPickerProps {
  keys: readonly RingKey[]
  value: readonly string[]
  onChange: (ids: string[]) => void
  multiple?: boolean
  ariaLabel: string
  isDisabled?: (key: RingKey) => boolean
  aside?: (key: RingKey) => ReactNode
}

/** Selectable list of keyring entries: checkboxes for recipients, radio rows for a single key. */
export function KeyPicker({ keys, value, onChange, multiple, ariaLabel, isDisabled, aside }: KeyPickerProps) {
  if (multiple) {
    return (
      <div role="group" aria-label={ariaLabel} className="grid max-h-80 scrollbar-thin gap-1.5 overflow-y-auto p-px">
        {keys.map((key) => {
          const checked = value.includes(key.id)
          const disabled = isDisabled?.(key)
          return (
            <label
              key={key.id}
              className={cn(ROW, checked && ROW_SELECTED, disabled && 'pointer-events-none opacity-50')}
            >
              <Checkbox
                checked={checked}
                disabled={disabled}
                onCheckedChange={(next) =>
                  onChange(next === true ? [...value, key.id] : value.filter((id) => id !== key.id))
                }
              />
              <KeySummary ringKey={key} aside={aside?.(key)} />
            </label>
          )
        })}
      </div>
    )
  }

  return (
    <RadioGroupPrimitive.Root
      aria-label={ariaLabel}
      value={value[0] ?? ''}
      onValueChange={(id) => onChange([id])}
      className="grid max-h-80 scrollbar-thin gap-1.5 overflow-y-auto p-px"
    >
      {keys.map((key) => (
        <RadioGroupPrimitive.Item
          key={key.id}
          value={key.id}
          disabled={isDisabled?.(key)}
          className={cn(
            ROW,
            'focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50 data-[state=checked]:border-primary/60 data-[state=checked]:bg-primary/[0.06] data-[state=checked]:shadow-[inset_0_0_0_1px_var(--primary)] dark:data-[state=checked]:bg-primary/10',
          )}
        >
          <span
            aria-hidden
            className="grid size-3.5 shrink-0 place-items-center rounded-full border border-input transition-colors group-data-[state=checked]/key:border-primary group-data-[state=checked]/key:bg-primary"
          >
            <span className="size-1.5 scale-0 rounded-full bg-primary-foreground transition-transform group-data-[state=checked]/key:scale-100" />
          </span>
          <KeySummary ringKey={key} aside={aside?.(key)} />
        </RadioGroupPrimitive.Item>
      ))}
    </RadioGroupPrimitive.Root>
  )
}

/** Shown in place of a picker when no suitable key exists yet. */
export function KeyringEmpty({
  title,
  body,
  onGenerate,
  onImport,
}: {
  title: string
  body: string
  onGenerate?: () => void
  onImport?: () => void
}) {
  const { t } = useI18n()
  return (
    <div className="flex flex-col items-start gap-3 rounded-lg border border-dashed px-3.5 py-3.5">
      <div className="flex gap-2.5">
        <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground">
          <KeyIcon className="size-4" />
        </span>
        <div className="min-w-0">
          <p className="text-sm font-medium">{title}</p>
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{body}</p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        {onGenerate && (
          <Button type="button" size="sm" onClick={onGenerate}>
            <KeyIcon weight="bold" />
            {t('keys.generate')}
          </Button>
        )}
        {onImport && (
          <Button type="button" size="sm" variant="outline" onClick={onImport}>
            <DownloadSimpleIcon />
            {t('keys.import')}
          </Button>
        )}
      </div>
    </div>
  )
}
