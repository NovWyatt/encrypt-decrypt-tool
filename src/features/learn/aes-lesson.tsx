import { useEffect, useMemo, useState, type KeyboardEvent } from 'react'
import type { Icon } from '@phosphor-icons/react'
import {
  ArrowRightIcon,
  BookOpenIcon,
  CaretLeftIcon,
  CaretRightIcon,
  CheckCircleIcon,
  PauseIcon,
  PlayIcon,
  ShuffleIcon,
  SkipBackIcon,
  SkipForwardIcon,
  XCircleIcon,
} from '@phosphor-icons/react'
import { cn } from 'cn'
import { Callout } from '@/components/common/callout'
import { NumberField } from '@/components/common/choice'
import { CopyButton } from '@/components/common/copy-button'
import { Panel, PanelHeader } from '@/components/common/page'
import { Segmented } from '@/components/common/segmented'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldError, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useI18n } from '@/i18n'
import { fromHex, isValidUtf8, toBufferSource, toHex, utf8Encode } from '@/lib/crypto/encoding'
import { useSettings } from '@/stores/settings'
import { ByteStrip, MixMatrix, Operator, SboxTable, StateGrid } from './aes-state-grid'
import {
  avalanche,
  gfMultiply,
  hex2,
  MIX_MATRIX,
  shiftRowsSource,
  traceEncrypt,
  type AesStep,
  type AesTrace,
} from './aes-trace'
import { AvalancheChart, AvalancheTable } from './avalanche-chart'
import { encryptBlocks } from './block-modes'
import { DataViewSwitch, Formula, LessonTable, MathDetails, type DataView } from './lesson-parts'

type BlockFormat = 'text' | 'hex'
type KeyBits = '128' | '192' | '256'

interface Lab {
  block: Uint8Array
  key: Uint8Array
  trace: AesTrace
}

// FIPS-197 appendix C: every round state of these vectors is printed in the standard.
const FIPS_BLOCK = '00112233445566778899aabbccddeeff'
const sequentialKey = (bytes: number) => toHex(Uint8Array.from({ length: bytes }, (_, index) => index))
const randomHex = (bytes: number) => toHex(crypto.getRandomValues(new Uint8Array(bytes)))
const cleanHex = (text: string) => text.replace(/[^0-9a-f]/gi, '').toLowerCase()
const binary = (value: number) => value.toString(2).padStart(8, '0')

function textBlock(text: string): Uint8Array {
  const block = new Uint8Array(16)
  block.set(utf8Encode(text).subarray(0, 16))
  return block
}

function makeLab(blockHex: string, keyHex: string): Lab {
  const block = fromHex(blockHex)
  const key = fromHex(keyHex)
  return { block, key, trace: traceEncrypt(block, key) }
}

/** The same block through a standard implementation: WebCrypto where it can, @noble/ciphers otherwise. */
async function referenceEncrypt(block: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  if (key.length !== 24) {
    try {
      const cryptoKey = await crypto.subtle.importKey('raw', toBufferSource(key), 'AES-CBC', false, ['encrypt'])
      // With a zero IV, the first CBC block is exactly the block cipher applied to the plaintext.
      const out = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: new Uint8Array(16) },
        cryptoKey,
        toBufferSource(block),
      )
      return new Uint8Array(out, 0, 16)
    } catch {
      // Fall through to the JavaScript implementation.
    }
  }
  return encryptBlocks('ECB', { key, iv: new Uint8Array(16) }, block)
}

function StepButton({
  label,
  icon: IconComponent,
  onClick,
  disabled,
}: {
  label: string
  icon: Icon
  onClick: () => void
  disabled: boolean
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* aria-disabled keeps focus on the button at either end, so arrow keys keep working. */}
        <Button
          variant="outline"
          size="icon-sm"
          aria-label={label}
          aria-disabled={disabled || undefined}
          onClick={disabled ? undefined : onClick}
          className="aria-disabled:opacity-45"
        >
          <IconComponent weight="bold" />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

function Timeline({ trace, current, onGo }: { trace: AesTrace; current: number; onGo: (index: number) => void }) {
  const { t } = useI18n()
  const step = trace.steps[current]
  const jumpToRound = (round: number) => {
    const sameKind = trace.steps.findIndex((item) => item.round === round && item.kind === step.kind)
    onGo(sameKind >= 0 ? sameKind : trace.steps.findIndex((item) => item.round === round))
  }
  const roundSteps = trace.steps.map((item, index) => ({ item, index })).filter(({ item }) => item.round === step.round)

  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex scrollbar-thin gap-1 overflow-x-auto pb-0.5">
        {Array.from({ length: trace.rounds + 1 }, (_, round) => (
          <button
            key={round}
            type="button"
            onClick={() => jumpToRound(round)}
            aria-label={t('aesLesson.round', { round })}
            aria-current={round === step.round ? 'step' : undefined}
            className={cn(
              'grid h-8 min-w-6 flex-1 place-items-center rounded-md text-xs font-medium tabular-nums transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50 sm:min-w-8',
              round === step.round
                ? 'bg-primary text-primary-foreground forced-colors:bg-[Highlight] forced-colors:text-[HighlightText] forced-colors:forced-color-adjust-none'
                : round < step.round
                  ? 'bg-primary/12 text-foreground hover:bg-primary/20 dark:bg-primary/20 dark:hover:bg-primary/30'
                  : 'bg-muted text-muted-foreground hover:text-foreground',
            )}
          >
            {round}
          </button>
        ))}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {roundSteps.map(({ item, index }) => (
          <button
            key={index}
            type="button"
            aria-pressed={index === current}
            onClick={() => onGo(index)}
            className={cn(
              'h-7 rounded-full px-3 text-xs font-medium transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50',
              index === current
                ? 'bg-foreground text-background forced-colors:bg-[Highlight] forced-colors:text-[HighlightText] forced-colors:forced-color-adjust-none'
                : 'bg-muted text-muted-foreground hover:text-foreground',
            )}
          >
            {t(`aesLesson.kinds.${item.kind}`)}
          </button>
        ))}
      </div>
    </div>
  )
}

function StepVisual({ step, cell, onCell }: { step: AesStep; cell: number; onCell: (index: number) => void }) {
  const { t } = useI18n()
  const stepKey = `${step.round}-${step.kind}`
  const column = Math.floor(cell / 4)
  const row = cell % 4
  const after = (
    <StateGrid label={t('aesLesson.after')} bytes={step.after} selected={cell} onSelect={onCell} stepKey={stepKey} />
  )

  let content
  switch (step.kind) {
    case 'input':
      content = (
        <StateGrid
          label={t('aesLesson.state')}
          bytes={step.after}
          selected={cell}
          onSelect={onCell}
          stepKey={stepKey}
        />
      )
      break
    case 'addRoundKey':
      content = (
        <>
          <StateGrid label={t('aesLesson.before')} bytes={step.before} related={[cell]} stepKey={stepKey} />
          <Operator>⊕</Operator>
          <StateGrid
            label={t('aesLesson.roundKey', { round: step.round })}
            bytes={step.roundKey!}
            related={[cell]}
            stepKey={stepKey}
          />
          <Operator>=</Operator>
          {after}
        </>
      )
      break
    case 'subBytes':
      content = (
        <>
          <StateGrid label={t('aesLesson.before')} bytes={step.before} related={[cell]} stepKey={stepKey} />
          <Operator label="S-box">
            <ArrowRightIcon className="rotate-90 sm:rotate-0" />
          </Operator>
          {after}
        </>
      )
      break
    case 'shiftRows':
      content = (
        <>
          <StateGrid
            label={t('aesLesson.before')}
            bytes={step.before}
            related={[shiftRowsSource(cell)]}
            stepKey={stepKey}
          />
          <Operator>
            <ArrowRightIcon className="rotate-90 sm:rotate-0" />
          </Operator>
          <StateGrid
            label={t('aesLesson.after')}
            bytes={step.after}
            selected={cell}
            onSelect={onCell}
            stepKey={stepKey}
            rowNotes={['', '← 1', '← 2', '← 3']}
          />
        </>
      )
      break
    case 'mixColumns':
      content = (
        <>
          <MixMatrix label={t('aesLesson.matrix')} highlightRow={row} />
          <Operator>×</Operator>
          <StateGrid
            label={t('aesLesson.before')}
            bytes={step.before}
            related={[0, 1, 2, 3].map((index) => 4 * column + index)}
            stepKey={stepKey}
          />
          <Operator>=</Operator>
          {after}
        </>
      )
      break
  }

  return (
    <div className="flex flex-col items-center gap-2 sm:flex-row sm:items-start sm:justify-center sm:gap-3">
      {content}
    </div>
  )
}

function StepDetail({
  step,
  cell,
  onCell,
  advanced,
  isLastRound,
}: {
  step: AesStep
  cell: number
  onCell: (index: number) => void
  advanced: boolean
  isLastRound: boolean
}) {
  const { t } = useI18n()
  const row = cell % 4
  const column = Math.floor(cell / 4)
  const input = step.before[cell]
  const output = step.after[cell]

  switch (step.kind) {
    case 'input':
      return (
        <div className="flex flex-col gap-3">
          <ByteStrip label={t('aesLesson.byteOrder')} bytes={step.after} selected={cell} onSelect={onCell} />
          <p className="text-[0.8125rem] text-muted-foreground">
            {t('aesLesson.cellInput', { index: cell, row, column })}
          </p>
        </div>
      )
    case 'addRoundKey': {
      const key = step.roundKey![cell]
      return (
        <div className="flex flex-col gap-2">
          <Formula>
            {hex2(input)} ⊕ {hex2(key)} = <strong className="font-semibold">{hex2(output)}</strong>
            {advanced && (
              <span className="block text-muted-foreground">
                {binary(input)} ⊕ {binary(key)} = {binary(output)}
              </span>
            )}
          </Formula>
          {isLastRound && <p className="text-[0.8125rem] text-muted-foreground">{t('aesLesson.lastRoundNote')}</p>}
        </div>
      )
    }
    case 'subBytes':
      return (
        <div className="flex flex-col gap-2">
          <Formula>
            S-box[{hex2(input)}] = <strong className="font-semibold">{hex2(output)}</strong>
          </Formula>
          <p className="text-[0.8125rem] text-muted-foreground">
            {t('aesLesson.cellSub', { row: (input >> 4).toString(16), column: (input & 0x0f).toString(16) })}
          </p>
          {advanced && (
            <MathDetails defaultOpen={false} label={t('aesLesson.sboxTable')}>
              <SboxTable input={input} />
            </MathDetails>
          )}
        </div>
      )
    case 'shiftRows':
      return (
        <div className="flex flex-col gap-2">
          <p className="text-[0.8125rem] text-muted-foreground">
            {t('aesLesson.cellShift', { row, column, from: Math.floor(shiftRowsSource(cell) / 4) })}
          </p>
          {isLastRound && <p className="text-[0.8125rem] text-muted-foreground">{t('aesLesson.lastRoundNote')}</p>}
        </div>
      )
    case 'mixColumns': {
      const factors = MIX_MATRIX[row]
      const sources = [0, 1, 2, 3].map((index) => step.before[4 * column + index])
      return (
        <div className="flex flex-col gap-1">
          <p className="text-[0.8125rem] text-muted-foreground">{t('aesLesson.cellMix', { row, column })}</p>
          <MathDetails defaultOpen={advanced}>
            <Formula>
              {sources.map((value, index) => `${hex2(factors[index])}·${hex2(value)}`).join(' ⊕ ')} ={' '}
              <strong className="font-semibold">{hex2(output)}</strong>
              <span className="block text-muted-foreground">
                = {sources.map((value, index) => hex2(gfMultiply(factors[index], value))).join(' ⊕ ')}
              </span>
            </Formula>
          </MathDetails>
        </div>
      )
    }
  }
}

function KeySchedule({ lab, round }: { lab: Lab; round: number }) {
  const { t } = useI18n()
  const nk = lab.key.length / 4
  const { keyWords, rounds } = lab.trace
  const groups = Array.from({ length: rounds + 1 }, (_, index) => keyWords.slice(4 * index, 4 * index + 4))

  return (
    <Panel>
      <PanelHeader title={t('aesLesson.keyScheduleTitle')} />
      <div className="flex flex-col gap-4 p-4 sm:p-5">
        <p className="max-w-[72ch] text-[0.8125rem] leading-relaxed text-muted-foreground">
          {t('aesLesson.keyScheduleBody', { count: rounds + 1, nk })}
        </p>
        <LessonTable
          className="max-h-96"
          divided={false}
          head={[t('aesLesson.word'), t('aesLesson.derivation'), 'Hex']}
          caption={t('aesLesson.keyScheduleTitle')}
        >
          {groups.map((words, groupRound) => [
            <tr
              key={`round-${groupRound}`}
              className={cn(
                'border-t first:border-t-0',
                groupRound === round && 'bg-primary/[0.06] dark:bg-primary/10',
              )}
            >
              <th colSpan={3} scope="rowgroup" className="px-3 pt-2.5 pb-1 text-left text-xs font-semibold">
                {t('aesLesson.roundKey', { round: groupRound })}
              </th>
            </tr>,
            ...words.map((word) => (
              <tr key={word.index} className={cn(groupRound === round && 'bg-primary/[0.06] dark:bg-primary/10')}>
                <td className="px-3 py-1.5 font-mono text-xs whitespace-nowrap">w{word.index}</td>
                <td className="px-3 py-1.5 font-mono text-xs">
                  {word.index < nk ? (
                    <span className="font-sans text-muted-foreground">{t('aesLesson.fromKey')}</span>
                  ) : word.rcon !== undefined ? (
                    <>
                      SubWord(RotWord(w{word.index - 1})) ⊕ Rcon({hex2(word.rcon)}) ⊕ w{word.index - nk}
                      <span className="block text-muted-foreground">
                        RotWord = {toHex(word.rotated!)}, SubWord = {toHex(word.substituted!)}
                      </span>
                    </>
                  ) : word.substituted ? (
                    <>
                      SubWord(w{word.index - 1}) ⊕ w{word.index - nk}
                      <span className="block text-muted-foreground">SubWord = {toHex(word.substituted)}</span>
                    </>
                  ) : (
                    <>
                      w{word.index - 1} ⊕ w{word.index - nk}
                    </>
                  )}
                </td>
                <td className="px-3 py-1.5 font-mono text-xs">{toHex(word.word)}</td>
              </tr>
            )),
          ])}
        </LessonTable>
      </div>
    </Panel>
  )
}

function Avalanche({
  lab,
  round,
  onRound,
  advanced,
}: {
  lab: Lab
  round: number
  onRound: (round: number) => void
  advanced: boolean
}) {
  const { t } = useI18n()
  const [bit, setBit] = useState(0)
  const [view, setView] = useState<DataView>('chart')
  const values = useMemo(() => avalanche(lab.block, lab.key, bit), [lab, bit])
  const flipAnother = () => {
    const next = Math.floor(Math.random() * 127)
    setBit(next >= bit ? next + 1 : next)
  }

  return (
    <Panel>
      <PanelHeader title={t('aesLesson.avalancheTitle')} actions={<DataViewSwitch value={view} onChange={setView} />} />
      <div className="grid gap-6 p-4 sm:p-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)] lg:gap-10">
        <div className="flex flex-col gap-4">
          <p className="text-[0.8125rem] leading-relaxed text-pretty text-muted-foreground">
            {t('aesLesson.avalancheBody')}
          </p>
          {advanced && (
            <div className="max-w-40">
              <NumberField
                label={t('aesLesson.bitLabel')}
                value={bit}
                min={0}
                max={127}
                onChange={(value) => setBit(Math.min(127, Math.max(0, Math.round(value))))}
              />
            </div>
          )}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <span className="text-[0.8125rem] font-medium tabular-nums">
              {t('aesLesson.flippedBit', { bit, byte: Math.floor(bit / 8) })}
            </span>
            <Button variant="outline" size="sm" onClick={flipAnother}>
              <ShuffleIcon />
              {t('aesLesson.flipAnother')}
            </Button>
          </div>
        </div>
        {view === 'chart' ? (
          <AvalancheChart values={values} current={round} onRound={onRound} />
        ) : (
          <AvalancheTable values={values} current={round} />
        )}
      </div>
    </Panel>
  )
}

export function AesLesson() {
  const { t } = useI18n()
  const { level } = useSettings()
  const advanced = level === 'advanced'

  const [format, setFormat] = useState<BlockFormat>('hex')
  const [blockHex, setBlockHex] = useState(FIPS_BLOCK)
  const [blockText, setBlockText] = useState('')
  const [keySize, setKeySize] = useState<KeyBits>('128')
  const [keyHex, setKeyHex] = useState(() => sequentialKey(16))

  const keyBits = advanced ? Number(keySize) : 128
  const shownKey = keyHex.slice(0, keyBits / 4)
  const blockValue = format === 'text' ? toHex(textBlock(blockText)) : blockHex.length === 32 ? blockHex : null
  const keyValue = shownKey.length === keyBits / 4 ? shownKey : null

  const fresh = useMemo(() => (blockValue && keyValue ? makeLab(blockValue, keyValue) : null), [blockValue, keyValue])
  // While an input is incomplete, keep showing the last valid run (dimmed) instead of emptying the page.
  const [lab, setLab] = useState<Lab>(() => makeLab(FIPS_BLOCK, sequentialKey(16)))
  if (fresh && fresh !== lab) setLab(fresh)
  const { trace } = lab

  const [stepIndex, setStepIndex] = useState(0)
  const [cell, setCell] = useState(5)
  const [playing, setPlaying] = useState(false)
  const total = trace.steps.length
  const current = Math.min(stepIndex, total - 1)
  const step = trace.steps[current]
  const atEnd = current === total - 1
  const isPlaying = playing && !atEnd

  useEffect(() => {
    if (!isPlaying) return
    const timer = setTimeout(() => setStepIndex(current + 1), 1400)
    return () => clearTimeout(timer)
  }, [isPlaying, current])

  const goTo = (index: number) => {
    setPlaying(false)
    setStepIndex(Math.max(0, Math.min(total - 1, index)))
  }
  const goToRound = (round: number) =>
    goTo(trace.steps.findLastIndex((item) => item.round === round && item.kind === 'addRoundKey'))

  const onStepKeys = (event: KeyboardEvent<HTMLElement>) => {
    const target = event.target as HTMLElement
    if (event.defaultPrevented || target.closest('input, textarea, [role="tablist"]')) return
    const moves: Record<string, number> = { ArrowLeft: current - 1, ArrowRight: current + 1, Home: 0, End: total - 1 }
    if (!(event.key in moves)) return
    event.preventDefault()
    goTo(moves[event.key])
  }

  const [check, setCheck] = useState<{ lab: Lab; ok: boolean } | null>(null)
  useEffect(() => {
    let cancelled = false
    void referenceEncrypt(lab.block, lab.key).then((output) => {
      if (!cancelled) setCheck({ lab, ok: toHex(output) === toHex(lab.trace.output) })
    })
    return () => {
      cancelled = true
    }
  }, [lab])
  const verified = check?.lab === lab ? check.ok : null

  const switchFormat = (next: BlockFormat) => {
    if (next === format) return
    if (next === 'hex') {
      setBlockHex(toHex(textBlock(blockText)))
    } else if (blockHex.length === 32) {
      const bytes = fromHex(blockHex)
      let end = bytes.length
      while (end > 0 && bytes[end - 1] === 0) end--
      const content = bytes.subarray(0, end)
      setBlockText(isValidUtf8(content) ? new TextDecoder().decode(content) : '')
    }
    setFormat(next)
  }

  const changeKeySize = (next: KeyBits) => {
    const bytes = Number(next) / 8
    // Keep the FIPS-197 example consistent across sizes; any other key is replaced by a random one.
    setKeyHex(keyHex === sequentialKey(Number(keySize) / 8) ? sequentialKey(bytes) : randomHex(bytes))
    setKeySize(next)
  }

  const loadExample = () => {
    setFormat('hex')
    setBlockHex(FIPS_BLOCK)
    setKeyHex(sequentialKey(keyBits / 8))
  }

  const blockBytes = format === 'text' ? Math.min(16, utf8Encode(blockText).length) : blockHex.length / 2
  const output = toHex(trace.output)

  return (
    <div className="grid gap-5">
      <Panel>
        <PanelHeader
          title={t('aesLesson.inputTitle')}
          actions={
            <Button variant="ghost" size="sm" onClick={loadExample}>
              <BookOpenIcon />
              {t('aesLesson.fipsExample')}
            </Button>
          }
        />
        <div className="grid gap-5 p-4 sm:p-5 lg:grid-cols-2 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)_minmax(0,1fr)]">
          <Field className="gap-1.5">
            <div className="flex min-h-7 items-center justify-between gap-2">
              <FieldLabel htmlFor="aes-lesson-block" className="text-xs font-medium text-muted-foreground">
                {t('aesLesson.block')}
              </FieldLabel>
              <Segmented<BlockFormat>
                size="sm"
                value={format}
                onValueChange={switchFormat}
                ariaLabel={t('aesLesson.block')}
                options={[
                  { value: 'hex', label: t('aesLesson.formatHex') },
                  { value: 'text', label: t('aesLesson.formatText') },
                ]}
              />
            </div>
            {format === 'text' ? (
              <Input
                id="aes-lesson-block"
                value={blockText}
                spellCheck={false}
                autoComplete="off"
                aria-describedby="aes-lesson-block-note"
                onChange={(event) => setBlockText(event.target.value)}
              />
            ) : (
              <Input
                id="aes-lesson-block"
                value={blockHex}
                spellCheck={false}
                autoComplete="off"
                maxLength={32}
                aria-invalid={blockHex.length !== 32 || undefined}
                aria-describedby="aes-lesson-block-note"
                onChange={(event) => setBlockHex(cleanHex(event.target.value).slice(0, 32))}
                className="font-mono text-[0.8125rem]"
              />
            )}
            {format === 'hex' && blockHex.length !== 32 ? (
              <FieldError id="aes-lesson-block-note" className="text-xs">
                {t('aesLesson.blockInvalid')}
              </FieldError>
            ) : (
              <FieldDescription id="aes-lesson-block-note" className="text-xs">
                {t('aesLesson.blockBytes', { count: blockBytes })}
                {format === 'text' && ` · ${t('aesLesson.blockHint')}`}
              </FieldDescription>
            )}
          </Field>

          <Field className="gap-1.5">
            <div className="flex min-h-7 items-center justify-between gap-2">
              <FieldLabel htmlFor="aes-lesson-key" className="text-xs font-medium text-muted-foreground">
                {t('aesLesson.key')}
              </FieldLabel>
              {advanced && (
                <Segmented<KeyBits>
                  size="sm"
                  value={keySize}
                  onValueChange={changeKeySize}
                  ariaLabel={t('aesLesson.keySize')}
                  options={[
                    { value: '128', label: '128' },
                    { value: '192', label: '192' },
                    { value: '256', label: '256' },
                  ]}
                />
              )}
            </div>
            <div className="flex gap-2">
              <Input
                id="aes-lesson-key"
                value={shownKey}
                spellCheck={false}
                autoComplete="off"
                maxLength={keyBits / 4}
                aria-invalid={!keyValue || undefined}
                aria-describedby="aes-lesson-key-note"
                onChange={(event) => setKeyHex(cleanHex(event.target.value).slice(0, keyBits / 4))}
                className="font-mono text-[0.8125rem]"
              />
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="outline"
                    size="icon"
                    aria-label={t('aesLesson.randomKey')}
                    onClick={() => setKeyHex(randomHex(keyBits / 8))}
                  >
                    <ShuffleIcon />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{t('aesLesson.randomKey')}</TooltipContent>
              </Tooltip>
            </div>
            {keyValue ? (
              <FieldDescription id="aes-lesson-key-note" className="text-xs">
                AES-{keyBits}, {t('aesLesson.roundCount', { rounds: keyBits / 32 + 6 })}
              </FieldDescription>
            ) : (
              <FieldError id="aes-lesson-key-note" className="text-xs">
                {t('aesLesson.keyInvalid', { bits: keyBits, hex: keyBits / 4 })}
              </FieldError>
            )}
          </Field>

          <div className="flex min-w-0 flex-col gap-1.5 lg:col-span-2 xl:col-span-1">
            <span className="flex min-h-7 items-center text-xs font-medium text-muted-foreground">
              {t('aesLesson.output')}
            </span>
            <div
              className={cn(
                'flex min-h-8 items-center gap-2 rounded-lg bg-muted/60 py-1 pr-1 pl-3 transition-opacity dark:bg-muted',
                !fresh && 'opacity-50',
              )}
            >
              <code className="min-w-0 flex-1 font-mono text-[0.8125rem] break-all">{output}</code>
              <CopyButton value={output} iconOnly variant="ghost" size="icon-xs" />
            </div>
            {fresh && verified !== null && (
              <span className={cn('flex items-center gap-1.5 text-xs', verified ? 'text-success' : 'text-destructive')}>
                {verified ? <CheckCircleIcon weight="fill" /> : <XCircleIcon weight="fill" />}
                {verified ? t('aesLesson.verified') : t('aesLesson.mismatch')}
              </span>
            )}
          </div>
        </div>
      </Panel>

      <Panel onKeyDown={onStepKeys}>
        <PanelHeader
          title={t('aesLesson.stepsTitle')}
          actions={
            <span className="text-xs text-muted-foreground tabular-nums">
              {t('aesLesson.stepCount', { current: current + 1, total })}
            </span>
          }
        />
        <div className={cn('flex flex-col gap-5 p-4 transition-opacity sm:p-5', !fresh && 'opacity-60')}>
          <Timeline trace={trace} current={current} onGo={goTo} />
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-1.5">
              <StepButton
                label={t('aesLesson.first')}
                icon={SkipBackIcon}
                onClick={() => goTo(0)}
                disabled={current === 0}
              />
              <StepButton
                label={t('aesLesson.previous')}
                icon={CaretLeftIcon}
                onClick={() => goTo(current - 1)}
                disabled={current === 0}
              />
              <Button
                size="sm"
                variant={isPlaying ? 'secondary' : 'default'}
                className="min-w-24"
                onClick={() => {
                  if (isPlaying) return setPlaying(false)
                  if (atEnd) setStepIndex(0)
                  setPlaying(true)
                }}
              >
                {isPlaying ? <PauseIcon weight="fill" /> : <PlayIcon weight="fill" />}
                {isPlaying ? t('aesLesson.pause') : t('aesLesson.play')}
              </Button>
              <StepButton
                label={t('aesLesson.next')}
                icon={CaretRightIcon}
                onClick={() => goTo(current + 1)}
                disabled={atEnd}
              />
              <StepButton
                label={t('aesLesson.last')}
                icon={SkipForwardIcon}
                onClick={() => goTo(total - 1)}
                disabled={atEnd}
              />
            </div>
            <span className="hidden text-xs text-muted-foreground md:inline">{t('aesLesson.keysHint')}</span>
          </div>

          <div className="border-t pt-5">
            <h3 aria-live="polite" className="text-base font-semibold">
              {t('aesLesson.round', { round: step.round })}
              <span className="text-muted-foreground"> · </span>
              {t(`aesLesson.kinds.${step.kind}`)}
            </h3>
            <p className="mt-1 max-w-[76ch] text-[0.8125rem] leading-relaxed text-pretty text-muted-foreground">
              {t(`aesLesson.explain.${step.kind}`)}
            </p>
          </div>

          <div className="grid items-start gap-6 xl:grid-cols-[auto_minmax(0,1fr)] xl:gap-10">
            <StepVisual step={step} cell={cell} onCell={setCell} />
            <div className="flex min-w-0 flex-col gap-2 xl:pt-6">
              <p className="text-xs text-muted-foreground">{t('aesLesson.pickCell')}</p>
              <StepDetail
                step={step}
                cell={cell}
                onCell={setCell}
                advanced={advanced}
                isLastRound={step.round === trace.rounds}
              />
            </div>
          </div>
        </div>
      </Panel>

      <Avalanche lab={lab} round={step.round} onRound={goToRound} advanced={advanced} />
      {advanced && <KeySchedule lab={lab} round={step.round} />}
      <Callout tone="info">{t('aesLesson.teachingNote')}</Callout>
    </div>
  )
}
