import { useId, type ReactNode } from 'react'
import { cn } from 'cn'
import { Panel } from '@/components/common/page'

/**
 * The settings column of a tool. Its visually hidden heading names the region and sits one level
 * above the section titles, so the page outline reads h1, h2, h3 without a visible panel title.
 */
export function SettingsPanel({ title, children }: { title: string; children: ReactNode }) {
  const id = useId()
  return (
    <Panel aria-labelledby={id} className="overflow-hidden">
      <h2 id={id} className="sr-only">
        {title}
      </h2>
      <div>{children}</div>
    </Panel>
  )
}

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
