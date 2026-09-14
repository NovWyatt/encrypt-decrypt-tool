import { useEffect, useState, type ReactNode } from 'react'
import type { Icon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { useI18n } from '@/i18n'
import { formatDuration } from '@/lib/format'

export function OutputEmpty({ icon: IconComponent, title, body }: { icon: Icon; title: string; body: string }) {
  return (
    <Empty className="min-h-[220px] gap-3 py-10">
      <EmptyHeader>
        <EmptyMedia variant="icon" className="size-10 rounded-xl">
          <IconComponent className="size-5 text-muted-foreground" />
        </EmptyMedia>
        <EmptyTitle className="text-sm">{title}</EmptyTitle>
        <EmptyDescription className="text-xs">{body}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

function Elapsed({ startedAt }: { startedAt: number }) {
  const { t, formatNumber } = useI18n()
  const [now, setNow] = useState(() => performance.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(performance.now()), 100)
    return () => clearInterval(timer)
  }, [])
  return <span className="tabular-nums">{formatDuration(now - startedAt, t, formatNumber)}</span>
}

export function OutputRunning({ label, startedAt }: { label: string; startedAt: number }) {
  return (
    <div className="flex min-h-[220px] flex-col gap-4 p-4" aria-busy="true" aria-live="polite">
      <div className="flex items-center gap-2 text-sm font-medium">
        <Spinner className="size-4 text-primary" />
        <span>{label}</span>
        <span className="text-xs font-normal text-muted-foreground">
          <Elapsed startedAt={startedAt} />
        </span>
      </div>
      <div className="space-y-2.5">
        {[92, 100, 96, 100, 64].map((width, index) => (
          <Skeleton key={index} className="h-3 rounded" style={{ width: `${width}%` }} />
        ))}
      </div>
    </div>
  )
}

const DISPLAY_LIMIT = 200_000

export function OutputText({ text, cipher, className }: { text: string; cipher?: boolean; className?: string }) {
  const truncated = text.length > DISPLAY_LIMIT
  return (
    <pre
      tabIndex={0}
      className={cn(
        'max-h-[440px] min-h-[160px] scrollbar-thin overflow-auto px-4 py-3 whitespace-pre-wrap outline-none focus-visible:ring-3 focus-visible:ring-ring/40',
        cipher ? 'text-cipher text-[0.8125rem] leading-relaxed' : 'font-sans text-sm leading-relaxed break-words',
        className,
      )}
    >
      {truncated ? `${text.slice(0, DISPLAY_LIMIT)}\n…` : text}
    </pre>
  )
}

export interface DetailRow {
  label: string
  value: ReactNode
  mono?: boolean
}

/** Keeps names such as "AES-256-GCM" on one line; browsers otherwise wrap right after a hyphen. */
function keepHyphenatedWords(text: string): ReactNode {
  if (!text.includes('-')) return text
  return text.split(/(\S*-\S*)/).map((part, index) =>
    part.includes('-') ? (
      <span key={index} className="whitespace-nowrap">
        {part}
      </span>
    ) : (
      part
    ),
  )
}

export function DetailsList({ rows }: { rows: DetailRow[] }) {
  return (
    <dl className="grid grid-cols-[minmax(92px,auto)_minmax(0,1fr)] gap-x-4 gap-y-2 text-[0.8125rem]">
      {rows.map((row) => (
        <div key={row.label} className="contents">
          <dt className="text-muted-foreground">{row.label}</dt>
          <dd className={cn('min-w-0 break-words', row.mono && 'font-mono text-xs leading-5 break-all')}>
            {typeof row.value === 'string' && !row.mono ? keepHyphenatedWords(row.value) : row.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}
