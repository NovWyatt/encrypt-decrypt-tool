import { useId, type ReactNode } from 'react'
import { cn } from 'cn'
import { RadioGroup as RadioGroupPrimitive } from 'radix-ui'
import { Field, FieldDescription, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'

export interface ChoiceOption<T extends string> {
  value: T
  label: ReactNode
  description?: ReactNode
  badge?: ReactNode
  disabled?: boolean
}

interface ChoiceCardsProps<T extends string> {
  value: T
  onValueChange: (value: T) => void
  options: ReadonlyArray<ChoiceOption<T>>
  ariaLabel: string
  columns?: 1 | 2
  className?: string
}

/** Radio group rendered as selectable cards; roving focus and arrow keys come from Radix. */
export function ChoiceCards<T extends string>({
  value,
  onValueChange,
  options,
  ariaLabel,
  columns = 1,
  className,
}: ChoiceCardsProps<T>) {
  return (
    <RadioGroupPrimitive.Root
      value={value}
      onValueChange={(next) => onValueChange(next as T)}
      aria-label={ariaLabel}
      className={cn('grid gap-2', columns === 2 && 'grid-cols-2', className)}
    >
      {options.map((option) => (
        <RadioGroupPrimitive.Item
          key={option.value}
          value={option.value}
          disabled={option.disabled}
          className={cn(
            'group/choice relative flex w-full min-w-0 items-start gap-2.5 rounded-lg border bg-transparent px-3 py-2.5 text-left transition-[background-color,border-color,box-shadow] outline-none',
            'hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50',
            'data-[state=checked]:border-primary/60 data-[state=checked]:bg-primary/[0.06] data-[state=checked]:shadow-[inset_0_0_0_1px_var(--primary)] dark:data-[state=checked]:bg-primary/10',
          )}
        >
          <span
            aria-hidden
            className="mt-[3px] grid size-3.5 shrink-0 place-items-center rounded-full border border-input transition-colors group-data-[state=checked]/choice:border-primary group-data-[state=checked]/choice:bg-primary"
          >
            <span className="size-1.5 scale-0 rounded-full bg-primary-foreground transition-transform group-data-[state=checked]/choice:scale-100" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm leading-5 font-medium">
              {option.label}
              {option.badge}
            </span>
            {option.description && (
              <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">{option.description}</span>
            )}
          </span>
        </RadioGroupPrimitive.Item>
      ))}
    </RadioGroupPrimitive.Root>
  )
}

export function Tag({
  tone = 'neutral',
  children,
}: {
  tone?: 'neutral' | 'good' | 'bad' | 'warn'
  children: ReactNode
}) {
  return (
    <span
      className={cn(
        'inline-flex h-[18px] items-center rounded-full px-1.5 text-[0.6875rem] leading-none font-medium whitespace-nowrap',
        tone === 'neutral' && 'bg-muted text-muted-foreground',
        tone === 'good' && 'bg-success/12 text-success',
        tone === 'bad' && 'bg-destructive/12 text-destructive',
        tone === 'warn' && 'bg-warning/15 text-warning',
      )}
    >
      {children}
    </span>
  )
}

interface NumberFieldProps {
  label: string
  value: number
  onChange: (value: number) => void
  min: number
  max: number
  step?: number
  hint?: string
}

export function NumberField({ label, value, onChange, min, max, step = 1, hint }: NumberFieldProps) {
  const id = useId()
  return (
    <Field className="gap-1.5">
      <FieldLabel htmlFor={id} className="text-xs font-medium text-muted-foreground">
        {label}
      </FieldLabel>
      <Input
        id={id}
        type="number"
        inputMode="numeric"
        min={min}
        max={max}
        step={step}
        value={Number.isFinite(value) ? value : ''}
        onChange={(event) => {
          const next = Number(event.target.value)
          if (Number.isFinite(next)) onChange(next)
        }}
        onBlur={() => onChange(Math.min(max, Math.max(min, Math.round(value / step) * step || min)))}
        className="h-8 font-mono text-[0.8125rem] tabular-nums"
      />
      {hint && <FieldDescription className="text-xs">{hint}</FieldDescription>}
    </Field>
  )
}
