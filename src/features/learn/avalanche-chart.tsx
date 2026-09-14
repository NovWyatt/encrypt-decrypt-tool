import { cn } from 'cn'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useI18n } from '@/i18n'
import { LessonTable } from './lesson-parts'

const MAX_BITS = 128
const TICKS = [0, 32, 64, 96, 128]
const RANDOM_LEVEL = 64

const percent = (bits: number) => `${(bits / MAX_BITS) * 100}%`

interface AvalancheProps {
  /** Bits that differ after each round, index = round. */
  values: readonly number[]
  /** The round shown in the stepper. */
  current: number
  onRound: (round: number) => void
}

/**
 * One series against a fixed 0–128 axis. Bars use --chart-3, validated for both themes; text stays
 * in text tokens. Every bar is a button with its own tooltip, and the table view is the twin.
 */
export function AvalancheChart({ values, current, onRound }: AvalancheProps) {
  const { t } = useI18n()
  return (
    <figure aria-label={t('aesLesson.chartLabel')} className="flex min-w-0 flex-col gap-3">
      <figcaption className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-xs">
        <span className="font-medium">{t('aesLesson.chartLabel')}</span>
        <span className="flex items-center gap-2 text-muted-foreground">
          <span aria-hidden className="h-px w-5 bg-foreground/50" />
          {t('aesLesson.randomLevel')}
        </span>
      </figcaption>
      <div className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-2">
        <div aria-hidden className="relative h-44 text-right text-[0.6875rem] text-muted-foreground tabular-nums">
          {TICKS.map((tick) => (
            <span
              key={tick}
              className="absolute right-0 translate-y-1/2 leading-none"
              style={{ bottom: percent(tick) }}
            >
              {tick}
            </span>
          ))}
        </div>
        <div className="relative h-44">
          {TICKS.map((tick) => (
            <span
              key={tick}
              aria-hidden
              className={cn('absolute inset-x-0 h-px', tick === 0 ? 'bg-foreground/20' : 'bg-border')}
              style={{ bottom: percent(tick) }}
            />
          ))}
          <div className="absolute inset-0 flex">
            {values.map((bits, round) => (
              <Tooltip key={round}>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    onClick={() => onRound(round)}
                    aria-label={`${t('aesLesson.afterRound', { round })}: ${t('aesLesson.bitsChanged', { bits })}`}
                    aria-current={round === current ? 'step' : undefined}
                    className={cn(
                      'group/bar relative flex h-full min-w-0 flex-1 items-end justify-center rounded-t-md px-[3px] outline-none focus-visible:ring-3 focus-visible:ring-ring/50',
                      round === current && 'bg-foreground/[0.05] dark:bg-foreground/[0.07]',
                    )}
                  >
                    {round === current && (
                      <span
                        className="absolute left-1/2 -translate-x-1/2 text-[0.6875rem] font-semibold tabular-nums"
                        style={{ bottom: `calc(${percent(bits)} + 4px)` }}
                      >
                        {bits}
                      </span>
                    )}
                    <span
                      className="block w-full max-w-6 rounded-t-[4px] bg-chart-3 transition-[height,filter] duration-500 ease-out group-hover/bar:brightness-110 group-focus-visible/bar:brightness-110"
                      style={{ height: percent(bits) }}
                    />
                  </button>
                </TooltipTrigger>
                <TooltipContent>
                  <span className="font-semibold tabular-nums">{t('aesLesson.bitsChanged', { bits })}</span>
                  <span className="opacity-70">{t('aesLesson.afterRound', { round })}</span>
                </TooltipContent>
              </Tooltip>
            ))}
          </div>
          {/* The reference sits above the bars so it stays readable where they cross it. */}
          <span
            aria-hidden
            className="pointer-events-none absolute inset-x-0 h-px bg-foreground/50"
            style={{ bottom: percent(RANDOM_LEVEL) }}
          />
        </div>
        <span />
        <div aria-hidden className="mt-2 flex text-[0.6875rem] text-muted-foreground tabular-nums">
          {values.map((_, round) => (
            <span
              key={round}
              className={cn('min-w-0 flex-1 text-center', round === current && 'font-semibold text-foreground')}
            >
              {round}
            </span>
          ))}
        </div>
        <span />
        <span aria-hidden className="mt-0.5 text-center text-[0.6875rem] text-muted-foreground">
          {t('aesLesson.roundAxis')}
        </span>
      </div>
    </figure>
  )
}

export function AvalancheTable({ values, current }: Omit<AvalancheProps, 'onRound'>) {
  const { t } = useI18n()
  return (
    <LessonTable
      caption={t('aesLesson.chartLabel')}
      head={[t('aesLesson.roundAxis'), t('aesLesson.bitsColumn')]}
      className="max-h-72"
    >
      {values.map((bits, round) => (
        <tr key={round} className={cn(round === current && 'bg-primary/[0.06] dark:bg-primary/10')}>
          <td className="px-3 py-1.5">{t('aesLesson.afterRound', { round })}</td>
          <td className="px-3 py-1.5 tabular-nums">{t('aesLesson.bitsChanged', { bits })}</td>
        </tr>
      ))}
    </LessonTable>
  )
}
