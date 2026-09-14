import type { ReactNode } from 'react'
import { cn } from 'cn'
import { useOverflow } from '@/hooks/use-overflow'

/**
 * A box that scrolls on its own, such as a wide table. Once its content overflows it becomes a
 * focusable, named region, so keyboard users can scroll it with the arrow keys.
 */
export function ScrollRegion({
  label,
  className,
  children,
}: {
  label: string
  className?: string
  children: ReactNode
}) {
  const [ref, overflows] = useOverflow<HTMLDivElement>()
  return (
    <div
      ref={ref}
      role={overflows ? 'region' : undefined}
      aria-label={overflows ? label : undefined}
      tabIndex={overflows ? 0 : undefined}
      className={cn(
        'scrollbar-thin overflow-auto outline-none focus-visible:ring-3 focus-visible:ring-ring/40',
        className,
      )}
    >
      {children}
    </div>
  )
}
