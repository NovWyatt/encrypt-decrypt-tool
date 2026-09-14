import { useState, type ReactNode } from 'react'
import { CaretDownIcon, ChartBarIcon, TableIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { Segmented } from '@/components/common/segmented'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { useI18n } from '@/i18n'

/** Numbered steps joined by a thin rail, used for walkthroughs. */
export function LessonSteps({ children, className }: { children: ReactNode; className?: string }) {
  return <ol className={cn('flex flex-col', className)}>{children}</ol>
}

export function LessonStep({
  number,
  title,
  description,
  aside,
  children,
}: {
  number: number
  title: ReactNode
  description?: ReactNode
  aside?: ReactNode
  children?: ReactNode
}) {
  return (
    <li className="group/step relative grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-3.5 pb-9 last:pb-0">
      <span
        aria-hidden
        className="absolute top-9 bottom-2 left-[calc(0.875rem-0.5px)] w-px bg-border group-last/step:hidden"
      />
      <span
        aria-hidden
        className="grid size-7 place-items-center rounded-full border bg-card text-xs font-semibold text-muted-foreground tabular-nums"
      >
        {number}
      </span>
      <div className="flex min-w-0 flex-col gap-3 pt-0.5">
        <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1.5">
          <div className="min-w-0">
            <h3 className="text-[0.9375rem] leading-6 font-semibold">{title}</h3>
            {description && (
              <p className="mt-1 max-w-[68ch] text-[0.8125rem] leading-relaxed text-pretty text-muted-foreground">
                {description}
              </p>
            )}
          </div>
          {aside}
        </div>
        {children}
      </div>
    </li>
  )
}

/** A worked equation. Long numbers wrap anywhere instead of overflowing. */
export function Formula({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        'rounded-lg bg-muted/60 px-3 py-2 font-mono text-[0.8125rem] leading-6 [overflow-wrap:anywhere] dark:bg-muted/50',
        className,
      )}
    >
      {children}
    </div>
  )
}

/** A variable name inside a formula, set apart from the numbers around it. */
export function Var({ children }: { children: ReactNode }) {
  return <i className="font-sans font-medium text-foreground">{children}</i>
}

export function Muted({ children }: { children: ReactNode }) {
  return <span className="text-muted-foreground">{children}</span>
}

/** Details that are open by default at the advanced level and one click away at the basic level. */
export function MathDetails({
  defaultOpen,
  children,
  label,
}: {
  defaultOpen: boolean
  children: ReactNode
  label?: string
}) {
  const { t } = useI18n()
  const [state, setState] = useState({ open: defaultOpen, defaultOpen })
  // Switching the level resets the section to that level's default.
  if (state.defaultOpen !== defaultOpen) setState({ open: defaultOpen, defaultOpen })
  const { open } = state
  const setOpen = (next: boolean) => setState({ open: next, defaultOpen })
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="flex flex-col gap-2">
      <CollapsibleTrigger asChild>
        <Button variant="ghost" size="sm" className="-ml-2 self-start text-muted-foreground hover:text-foreground">
          <CaretDownIcon className={cn('transition-transform', !open && '-rotate-90')} />
          {label ?? (open ? t('learn.hideDetails') : t('learn.showDetails'))}
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent className="data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:animate-in data-[state=open]:fade-in-0">
        {children}
      </CollapsibleContent>
    </Collapsible>
  )
}

export type DataView = 'chart' | 'table'

export function DataViewSwitch({ value, onChange }: { value: DataView; onChange: (view: DataView) => void }) {
  const { t } = useI18n()
  return (
    <Segmented<DataView>
      size="sm"
      value={value}
      onValueChange={onChange}
      ariaLabel={`${t('learn.chart')} / ${t('learn.table')}`}
      options={[
        { value: 'chart', label: t('learn.chart'), icon: ChartBarIcon },
        { value: 'table', label: t('learn.table'), icon: TableIcon },
      ]}
    />
  )
}

/** A compact data table with a sticky header, for worked examples. */
export function LessonTable({
  head,
  children,
  className,
  caption,
  divided = true,
}: {
  head: ReactNode[]
  children: ReactNode
  className?: string
  caption?: string
  /** Rules between rows; turn off when rows are grouped under their own heading rows. */
  divided?: boolean
}) {
  return (
    <div className={cn('scrollbar-thin overflow-auto rounded-lg border', className)}>
      <table className="w-full border-collapse text-[0.8125rem]">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead className="sticky top-0 z-10 bg-muted/95 text-xs text-muted-foreground backdrop-blur-sm">
          <tr>
            {head.map((cell, index) => (
              <th key={index} scope="col" className="px-3 py-2 text-left font-medium whitespace-nowrap">
                {cell}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className={cn(divided && 'divide-y')}>{children}</tbody>
      </table>
    </div>
  )
}
