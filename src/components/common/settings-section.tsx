import type { ReactNode } from 'react'
import { cn } from 'cn'

/** A titled group inside a settings panel, separated from the previous one by a rule. */
export function SettingsSection({
  title,
  children,
  className,
}: {
  title?: string
  children: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex flex-col gap-3 border-t px-4 py-4 first:border-t-0', className)}>
      {title && <h3 className="text-[0.8125rem] font-semibold">{title}</h3>}
      {children}
    </div>
  )
}
