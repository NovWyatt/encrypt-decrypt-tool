import { Fragment, useRef, type KeyboardEvent, type ReactNode } from 'react'
import { cn } from 'cn'
import { motion } from 'motion/react'
import { ScrollRegion } from '@/components/common/scroll-region'
import { useI18n } from '@/i18n'
import { hex2, MIX_MATRIX, SBOX } from './aes-trace'

/** Cells in reading order (row by row); AES itself numbers the state column by column. */
const CELLS = Array.from({ length: 16 }, (_, order) => {
  const row = Math.floor(order / 4)
  const column = order % 4
  return { row, column, index: row + 4 * column }
})

const CELL_BASE =
  'grid size-8 place-items-center rounded-md font-mono text-[0.8125rem] tabular-nums transition-colors md:size-9'
// Forced colors drop the tints and the ring, so those tones fall back to system colors there.
const CELL_TONES = {
  plain: 'bg-muted/70 text-foreground/90 dark:bg-muted',
  related:
    'bg-primary/15 text-foreground ring-1 ring-primary/45 ring-inset dark:bg-primary/25 forced-colors:border forced-colors:border-[Highlight]',
  selected:
    'bg-primary text-primary-foreground forced-colors:bg-[Highlight] forced-colors:text-[HighlightText] forced-colors:forced-color-adjust-none',
}

interface StateGridProps {
  label: string
  bytes: Uint8Array
  /** Cells the selected result depends on. */
  related?: readonly number[]
  selected?: number
  onSelect?: (index: number) => void
  /** A note shown after each row, such as how far ShiftRows moves it. */
  rowNotes?: readonly ReactNode[]
  /** Changes with the step so the values fade in again. */
  stepKey?: string
}

export function StateGrid({ label, bytes, related = [], selected, onSelect, rowNotes, stepKey }: StateGridProps) {
  const { t } = useI18n()
  const buttons = useRef<Array<HTMLButtonElement | null>>([])

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const row = index % 4
    const column = Math.floor(index / 4)
    const moves: Record<string, [number, number]> = {
      ArrowUp: [row - 1, column],
      ArrowDown: [row + 1, column],
      ArrowLeft: [row, column - 1],
      ArrowRight: [row, column + 1],
    }
    const move = moves[event.key]
    if (!move || !onSelect) return
    // Handled here even at the edges, so arrow keys inside the grid never also change the step.
    event.preventDefault()
    const [nextRow, nextColumn] = move
    if (nextRow < 0 || nextRow > 3 || nextColumn < 0 || nextColumn > 3) return
    const next = nextRow + 4 * nextColumn
    onSelect(next)
    buttons.current[next]?.focus()
  }

  return (
    <div className="flex flex-col items-center gap-2">
      <span className="text-xs font-medium whitespace-nowrap text-muted-foreground">{label}</span>
      <div
        role="group"
        aria-label={label}
        className={cn('grid gap-1', rowNotes ? 'grid-cols-[repeat(4,auto)_2.25rem]' : 'grid-cols-4')}
      >
        {CELLS.map(({ row, column, index }) => {
          const tone = index === selected ? 'selected' : related.includes(index) ? 'related' : 'plain'
          const value = (
            <motion.span
              key={stepKey}
              initial={{ opacity: 0.2 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.28, delay: (row + column) * 0.025 }}
            >
              {hex2(bytes[index])}
            </motion.span>
          )
          const cell = onSelect ? (
            <button
              ref={(element) => {
                buttons.current[index] = element
              }}
              type="button"
              tabIndex={index === selected ? 0 : -1}
              aria-pressed={index === selected}
              aria-label={`${t('aesLesson.cellName', { row, column })}: ${hex2(bytes[index])}`}
              onClick={() => onSelect(index)}
              onKeyDown={(event) => onKeyDown(event, index)}
              className={cn(
                CELL_BASE,
                CELL_TONES[tone],
                'outline-none focus-visible:ring-3 focus-visible:ring-ring/60',
                tone === 'plain' && 'hover:bg-primary/10',
              )}
            >
              {value}
            </button>
          ) : (
            <span className={cn(CELL_BASE, CELL_TONES[tone])}>{value}</span>
          )
          return (
            <Fragment key={index}>
              {cell}
              {rowNotes && column === 3 && (
                <span className="flex items-center pl-1.5 text-[0.6875rem] whitespace-nowrap text-muted-foreground tabular-nums">
                  {rowNotes[row]}
                </span>
              )}
            </Fragment>
          )
        })}
      </div>
    </div>
  )
}

/** The symbol between two grids. On narrow screens the grids stack and it sits between them. */
export function Operator({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <div
      aria-hidden
      className="flex min-w-10 flex-col items-center justify-center gap-0.5 text-muted-foreground sm:self-stretch sm:pt-6"
    >
      <span className="flex text-xl leading-none [&_svg]:size-5">{children}</span>
      {label && <span className="text-[0.6875rem] font-medium whitespace-nowrap">{label}</span>}
    </div>
  )
}

export function MixMatrix({ label, highlightRow }: { label: string; highlightRow?: number }) {
  return (
    <div className="flex flex-col items-center gap-2">
      <span className="text-xs font-medium whitespace-nowrap text-muted-foreground">{label}</span>
      <div className="grid grid-cols-4 gap-1">
        {MIX_MATRIX.flatMap((factors, row) =>
          factors.map((factor, column) => (
            <span
              key={`${row}-${column}`}
              className={cn(CELL_BASE, row === highlightRow ? CELL_TONES.related : 'bg-muted/40 text-muted-foreground')}
            >
              {hex2(factor)}
            </span>
          )),
        )}
      </div>
    </div>
  )
}

/** The 16 input bytes in their original order, linked to the state cell they fill. */
export function ByteStrip({
  label,
  bytes,
  selected,
  onSelect,
}: {
  label: string
  bytes: Uint8Array
  selected: number
  onSelect: (index: number) => void
}) {
  return (
    <div className="flex flex-col gap-2">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <div className="grid grid-cols-8 gap-1 sm:flex sm:flex-wrap">
        {Array.from(bytes, (value, index) => (
          <button
            key={index}
            type="button"
            aria-pressed={index === selected}
            onClick={() => onSelect(index)}
            className={cn(
              'flex flex-col items-center rounded-md px-1 pt-0.5 pb-1 transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50 sm:min-w-9',
              index === selected
                ? 'bg-primary text-primary-foreground forced-colors:bg-[Highlight] forced-colors:text-[HighlightText] forced-colors:forced-color-adjust-none'
                : 'bg-muted/60 hover:bg-primary/10 dark:bg-muted',
            )}
          >
            <span className={cn('text-[0.625rem] tabular-nums', index !== selected && 'text-muted-foreground')}>
              {index}
            </span>
            <span className="font-mono text-[0.8125rem]">{hex2(value)}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

export function SboxTable({ input }: { input: number }) {
  const { t } = useI18n()
  const row = input >> 4
  const column = input & 0x0f
  const digits = Array.from({ length: 16 }, (_, digit) => digit)
  return (
    <ScrollRegion label={t('aesLesson.sboxTable')} className="rounded-lg border p-2">
      <table className="mx-auto border-collapse font-mono text-[0.6875rem] tabular-nums">
        <caption className="sr-only">{t('aesLesson.sboxTable')}</caption>
        <thead>
          <tr>
            <td />
            {digits.map((digit) => (
              <th
                key={digit}
                scope="col"
                className={cn('px-1 pb-1 font-semibold', digit === column ? 'text-primary' : 'text-muted-foreground')}
              >
                {digit.toString(16)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {digits.map((high) => (
            <tr key={high}>
              <th
                scope="row"
                className={cn('pr-1.5 font-semibold', high === row ? 'text-primary' : 'text-muted-foreground')}
              >
                {high.toString(16)}
              </th>
              {digits.map((low) => {
                const hit = high === row && low === column
                return (
                  <td
                    key={low}
                    className={cn(
                      'rounded-[3px] px-1 py-px text-center',
                      hit
                        ? 'bg-primary font-semibold text-primary-foreground forced-colors:bg-[Highlight] forced-colors:text-[HighlightText] forced-colors:forced-color-adjust-none'
                        : (high === row || low === column) && 'bg-primary/[0.08] dark:bg-primary/15',
                    )}
                  >
                    {hex2(SBOX[high * 16 + low])}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </ScrollRegion>
  )
}
