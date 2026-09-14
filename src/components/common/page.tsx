import type { ReactNode } from 'react'
import { cn } from 'cn'

export function PageContainer({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn('mx-auto w-full max-w-[1320px] px-4 py-6 md:px-6 lg:px-10 lg:py-9', className)}>{children}</div>
  )
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
}) {
  return (
    <header className="mb-6 flex flex-col gap-4 md:mb-8 md:flex-row md:items-end md:justify-between">
      <div className="min-w-0">
        {/* Focusable from script only, so the mobile menu can hand focus to the page it opened. */}
        <h1
          tabIndex={-1}
          className="text-2xl leading-[1.2] font-semibold tracking-tight text-balance outline-none md:text-[1.75rem]"
        >
          {title}
        </h1>
        {description && (
          <p className="mt-1.5 max-w-[62ch] text-sm leading-relaxed text-pretty text-muted-foreground md:text-[0.9375rem]">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  )
}

/** A bordered surface. Used only where grouping communicates hierarchy (tool inputs and results). */
export function Panel({
  children,
  className,
  as: Tag = 'section',
  ...props
}: {
  children: ReactNode
  className?: string
  as?: 'section' | 'div' | 'aside'
} & React.HTMLAttributes<HTMLElement>) {
  return (
    <Tag
      className={cn(
        'min-w-0 rounded-xl border bg-card text-card-foreground shadow-[0_1px_2px_oklch(0.2_0.01_286/0.04)] dark:shadow-none',
        className,
      )}
      {...props}
    >
      {children}
    </Tag>
  )
}

export function PanelHeader({
  title,
  description,
  actions,
  className,
  icon,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  className?: string
  icon?: ReactNode
}) {
  return (
    <div className={cn('flex min-h-12 items-center justify-between gap-3 border-b px-4 py-2.5', className)}>
      <div className="flex min-w-0 items-center gap-2">
        {icon}
        <div className="min-w-0">
          <h2 className="truncate text-sm font-semibold">{title}</h2>
          {description && <p className="truncate text-xs text-muted-foreground">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-1">{actions}</div>}
    </div>
  )
}

export function SectionTitle({ children, aside }: { children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <h3 className="text-sm font-semibold">{children}</h3>
      {aside}
    </div>
  )
}
