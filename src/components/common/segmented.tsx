import { useId, type ReactNode } from 'react'
import type { Icon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { motion } from 'motion/react'
import { ToggleGroup as ToggleGroupPrimitive } from 'radix-ui'

export interface SegmentedOption<T extends string> {
  value: T
  label: ReactNode
  icon?: Icon
  disabled?: boolean
}

interface SegmentedProps<T extends string> {
  value: T
  onValueChange: (value: T) => void
  options: ReadonlyArray<SegmentedOption<T>>
  ariaLabel: string
  size?: 'sm' | 'md' | 'lg'
  fullWidth?: boolean
  className?: string
}

const SIZES = {
  sm: 'h-7 px-2.5 text-xs gap-1',
  md: 'h-8 px-3 text-sm gap-1.5',
  lg: 'h-9 px-4 text-sm gap-2',
}

/** Single-choice control whose selection indicator glides between options. */
export function Segmented<T extends string>({
  value,
  onValueChange,
  options,
  ariaLabel,
  size = 'md',
  fullWidth,
  className,
}: SegmentedProps<T>) {
  const indicatorId = useId()
  return (
    <ToggleGroupPrimitive.Root
      type="single"
      value={value}
      onValueChange={(next) => next && onValueChange(next as T)}
      aria-label={ariaLabel}
      className={cn(
        'relative inline-flex items-center gap-0.5 rounded-lg bg-muted p-0.5 ring-1 ring-border/50 ring-inset',
        fullWidth && 'flex w-full',
        className,
      )}
    >
      {options.map((option) => {
        const active = option.value === value
        return (
          <ToggleGroupPrimitive.Item
            key={option.value}
            value={option.value}
            disabled={option.disabled}
            className={cn(
              'relative isolate inline-flex items-center justify-center rounded-md font-medium whitespace-nowrap text-muted-foreground transition-colors outline-none select-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50 data-[state=on]:text-foreground',
              SIZES[size],
              fullWidth && 'flex-1',
            )}
          >
            {active && (
              <motion.span
                layoutId={indicatorId}
                // Only animate when the selection changes, not when surrounding layout shifts.
                layoutDependency={value}
                aria-hidden
                className="absolute inset-0 -z-10 rounded-md bg-surface shadow-[0_1px_2px_oklch(0.2_0.01_286/0.08),0_0_0_1px_oklch(0.2_0.01_286/0.06)] dark:bg-accent dark:shadow-none"
                transition={{ type: 'spring', stiffness: 520, damping: 40 }}
              />
            )}
            {option.icon && <option.icon className={size === 'sm' ? 'size-3.5' : 'size-4'} weight="bold" />}
            {option.label}
          </ToggleGroupPrimitive.Item>
        )
      })}
    </ToggleGroupPrimitive.Root>
  )
}
