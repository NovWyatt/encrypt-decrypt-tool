import type { ReactNode } from 'react'
import { MagnifyingGlassIcon } from '@phosphor-icons/react'
import { cn } from 'cn'

/** What was recognized in pasted ciphertext or a signature, shown at the top of a settings panel. */
export function DetectionSummary({
  recognized,
  label,
  children,
}: {
  recognized: boolean
  label: string
  /** Secondary lines: parameters, size, or why nothing was recognized. */
  children?: ReactNode
}) {
  return (
    <div className="flex items-start gap-2.5">
      <span
        className={cn(
          'grid size-8 shrink-0 place-items-center rounded-lg transition-colors',
          recognized ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground',
        )}
      >
        <MagnifyingGlassIcon weight="bold" className="size-4" />
      </span>
      <div className="min-w-0 pt-0.5">
        <p className={cn('text-sm', recognized ? 'font-medium' : 'text-muted-foreground')}>{label}</p>
        {children}
      </div>
    </div>
  )
}
