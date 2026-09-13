import type { ReactNode } from 'react'
import { CheckCircleIcon, InfoIcon, WarningCircleIcon, WarningIcon } from '@phosphor-icons/react'
import { cn } from 'cn'

const TONES = {
  info: {
    icon: InfoIcon,
    className: 'bg-primary/[0.07] text-foreground *:data-[slot=icon]:text-primary dark:bg-primary/10',
  },
  warn: { icon: WarningIcon, className: 'bg-warning/10 text-foreground *:data-[slot=icon]:text-warning' },
  bad: {
    icon: WarningCircleIcon,
    className: 'bg-destructive/[0.08] text-foreground *:data-[slot=icon]:text-destructive',
  },
  good: { icon: CheckCircleIcon, className: 'bg-success/10 text-foreground *:data-[slot=icon]:text-success' },
} as const

/** A tinted inline note. Use `action` for a single follow-up button. */
export function Callout({
  tone = 'info',
  title,
  children,
  action,
  className,
}: {
  tone?: keyof typeof TONES
  title?: ReactNode
  children?: ReactNode
  action?: ReactNode
  className?: string
}) {
  const { icon: Icon, className: toneClass } = TONES[tone]
  return (
    <div className={cn('flex gap-2.5 rounded-lg px-3 py-2.5 text-xs leading-relaxed', toneClass, className)}>
      <Icon data-slot="icon" weight="fill" className="mt-px size-4 shrink-0" />
      <div className="flex min-w-0 flex-1 flex-col gap-2">
        {title && <p className="text-[0.8125rem] leading-snug font-medium">{title}</p>}
        {children && <div className="text-muted-foreground">{children}</div>}
        {action && <div className="flex flex-wrap gap-2">{action}</div>}
      </div>
    </div>
  )
}
