import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ArrowRightIcon, ArrowsClockwiseIcon, ImageSquareIcon, UploadSimpleIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { navigate } from '@/app/routes'
import { Callout } from '@/components/common/callout'
import { Tag } from '@/components/common/choice'
import { Panel, PanelHeader } from '@/components/common/page'
import { ScrollRegion } from '@/components/common/scroll-region'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { useI18n } from '@/i18n'
import { toHex, utf8Encode } from '@/lib/crypto/encoding'
import { useSettings } from '@/stores/settings'
import {
  encryptBlocks,
  encryptPixels,
  randomDemoKey,
  repeatedBlocks,
  repeatRatio,
  sampleScene,
  zeroPad,
  type DemoMode,
} from './block-modes'
import { Formula } from './lesson-parts'

interface DemoImage {
  width: number
  height: number
  pixels: Uint8ClampedArray<ArrayBuffer>
  uploaded: boolean
}

const MAX_WIDTH = 320
const MAX_HEIGHT = 240
const MAX_TEXT_BYTES = 96
const ALL_MODES: DemoMode[] = ['ECB', 'CBC', 'CTR']

const sampleImage = (): DemoImage => ({ width: 256, height: 160, pixels: sampleScene(), uploaded: false })

/** Scales an image down to demo size. Nearest-neighbour sampling keeps flat areas flat. */
async function readImage(file: File): Promise<DemoImage> {
  const bitmap = await createImageBitmap(file)
  try {
    const scale = Math.min(1, MAX_WIDTH / bitmap.width, MAX_HEIGHT / bitmap.height)
    // A width divisible by 4 keeps every 16-byte block aligned with whole pixels on each row.
    const width = Math.max(4, Math.floor((bitmap.width * scale) / 4) * 4)
    const height = Math.max(1, Math.round(bitmap.height * scale))
    const canvas = document.createElement('canvas')
    canvas.width = width
    canvas.height = height
    const context = canvas.getContext('2d', { willReadFrequently: true })
    if (!context) throw new Error('Canvas is unavailable')
    context.imageSmoothingEnabled = false
    context.drawImage(bitmap, 0, 0, width, height)
    return { width, height, pixels: context.getImageData(0, 0, width, height).data, uploaded: true }
  } finally {
    bitmap.close()
  }
}

function PixelCanvas({
  image,
  pixels,
  label,
}: {
  image: DemoImage
  pixels: Uint8ClampedArray<ArrayBuffer>
  label: string
}) {
  const ref = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const canvas = ref.current
    const context = canvas?.getContext('2d')
    if (!canvas || !context) return
    canvas.width = image.width
    canvas.height = image.height
    context.putImageData(new ImageData(pixels, image.width, image.height), 0, 0)
  }, [image, pixels])
  return (
    <canvas
      ref={ref}
      role="img"
      aria-label={label}
      className="block h-auto w-full [image-rendering:pixelated]"
      style={{ aspectRatio: `${image.width} / ${image.height}` }}
    />
  )
}

function Figure({
  title,
  tag,
  caption,
  children,
}: {
  title: string
  tag?: ReactNode
  caption: string
  children: ReactNode
}) {
  return (
    <figure className="flex min-w-0 flex-col gap-2">
      {/* A checkerboard shows transparent areas of uploaded images. */}
      <div className="overflow-hidden rounded-lg border bg-[repeating-conic-gradient(var(--muted)_0_25%,transparent_0_50%)] bg-size-[16px_16px]">
        {children}
      </div>
      <figcaption className="flex flex-col gap-1">
        <span className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
          <span className="text-sm font-medium">{title}</span>
          {tag}
        </span>
        <span className="text-xs text-muted-foreground tabular-nums">{caption}</span>
      </figcaption>
    </figure>
  )
}

function ImageDemo({ modes }: { modes: DemoMode[] }) {
  const { t, formatNumber } = useI18n()
  const [image, setImage] = useState(sampleImage)
  const [demoKey, setDemoKey] = useState(randomDemoKey)
  const [failed, setFailed] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  const original = useMemo(() => repeatRatio(new Uint8Array(image.pixels.buffer)), [image])
  const encrypted = useMemo(
    () =>
      ALL_MODES.map((mode) => {
        const pixels = encryptPixels(mode, demoKey, image.pixels)
        return { mode, pixels, ratio: mode === 'ECB' ? original : repeatRatio(new Uint8Array(pixels.buffer)) }
      }),
    [demoKey, image, original],
  )
  const percent = (ratio: number) => formatNumber(ratio, { style: 'percent', maximumFractionDigits: 0 })

  return (
    <Panel>
      <PanelHeader
        title={t('modes.imageTitle')}
        icon={<ImageSquareIcon className="size-4.5 text-muted-foreground" />}
        actions={
          <Button variant="ghost" size="sm" onClick={() => setDemoKey(randomDemoKey())}>
            <ArrowsClockwiseIcon />
            {t('modes.newKey')}
          </Button>
        }
      />
      <div className="flex flex-col gap-5 p-4 sm:p-5">
        <p className="max-w-[72ch] text-[0.8125rem] leading-relaxed text-pretty text-muted-foreground">
          {t('modes.imageBody')}
        </p>
        <div
          className={cn(
            'grid grid-cols-2 gap-x-3 gap-y-5 sm:gap-x-4',
            modes.length === 3 ? 'lg:grid-cols-4' : 'lg:grid-cols-3',
          )}
        >
          <Figure title={t('modes.original')} caption={t('modes.repeats', { percent: percent(original) })}>
            <PixelCanvas image={image} pixels={image.pixels} label={t('modes.original')} />
          </Figure>
          {encrypted
            .filter((entry) => modes.includes(entry.mode))
            .map(({ mode, pixels, ratio }) => (
              <Figure
                key={mode}
                title={`AES-${mode}`}
                caption={t('modes.repeats', { percent: percent(ratio) })}
                tag={
                  mode !== 'ECB' ? (
                    <Tag tone="good">{t('modes.hides')}</Tag>
                  ) : ratio >= 0.02 ? (
                    <Tag tone="bad">{t('modes.leaks')}</Tag>
                  ) : undefined
                }
              >
                <PixelCanvas image={image} pixels={pixels} label={`AES-${mode}`} />
              </Figure>
            ))}
        </div>
        <div className="flex flex-col gap-2 border-t pt-4 sm:flex-row sm:items-center sm:gap-3">
          <div className="flex shrink-0 flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => fileInput.current?.click()}>
              <UploadSimpleIcon />
              {t('modes.upload')}
            </Button>
            {image.uploaded && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setImage(sampleImage())
                  setFailed(false)
                }}
              >
                <ImageSquareIcon />
                {t('modes.sample')}
              </Button>
            )}
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">{t('modes.uploadHint')}</p>
          <input
            ref={fileInput}
            type="file"
            accept="image/*"
            hidden
            onChange={(event) => {
              const file = event.target.files?.[0]
              event.target.value = ''
              if (!file) return
              readImage(file)
                .then((next) => {
                  setImage(next)
                  setFailed(false)
                })
                .catch(() => setFailed(true))
            }}
          />
        </div>
        {failed && <Callout tone="bad">{t('modes.imageError')}</Callout>}
      </div>
    </Panel>
  )
}

/** Plaintext of one block: the text itself, then how many padding bytes were added. */
function BlockText({ block }: { block: Uint8Array }) {
  let end = block.length
  while (end > 0 && block[end - 1] === 0) end--
  const padding = block.length - end
  return (
    <span className="font-mono text-xs whitespace-pre">
      {new TextDecoder().decode(block.subarray(0, end))}
      {padding > 0 && <span className="text-muted-foreground"> +{padding}×00</span>}
    </span>
  )
}

function TextDemo({ modes }: { modes: DemoMode[] }) {
  const { t } = useI18n()
  const [edited, setEdited] = useState<string | null>(null)
  const [demoKey] = useState(randomDemoKey)
  const text = edited ?? t('modes.textDefault')

  const bytes = utf8Encode(text)
  const plainBlocks = repeatedBlocks(zeroPad(bytes)).blocks
  const ciphers = modes.map((mode) => ({ mode, ...repeatedBlocks(encryptBlocks(mode, demoKey, bytes)) }))
  const repeats = ciphers[0].firstSeen.filter((index) => index >= 0).length
  const chained = modes.filter((mode) => mode !== 'ECB')

  return (
    <Panel>
      <PanelHeader title={t('modes.textTitle')} />
      <div className="flex flex-col gap-4 p-4 sm:p-5">
        <p className="max-w-[72ch] text-[0.8125rem] leading-relaxed text-pretty text-muted-foreground">
          {t('modes.textBody')}
        </p>
        <Field className="gap-1.5">
          <FieldLabel htmlFor="modes-text" className="text-xs font-medium text-muted-foreground">
            {t('modes.textLabel')}
          </FieldLabel>
          <Input
            id="modes-text"
            aria-describedby="modes-text-hint"
            value={text}
            spellCheck={false}
            autoComplete="off"
            onChange={(event) => {
              let next = event.target.value
              while (utf8Encode(next).length > MAX_TEXT_BYTES) next = next.slice(0, -1)
              setEdited(next)
            }}
            className="font-mono md:text-[0.8125rem]"
          />
          <FieldDescription id="modes-text-hint" className="text-xs">
            {t('modes.textHint', { max: MAX_TEXT_BYTES })}
          </FieldDescription>
        </Field>

        {plainBlocks.length > 0 && (
          <ScrollRegion label={t('modes.textTitle')} className="rounded-lg border">
            <table className="w-full border-collapse text-[0.8125rem]">
              <caption className="sr-only">{t('modes.textTitle')}</caption>
              <thead className="bg-muted/60 text-xs text-muted-foreground">
                <tr>
                  <th scope="col" className="w-12 px-3 py-2 text-left font-medium">
                    {t('modes.block')}
                  </th>
                  <th scope="col" className="px-3 py-2 text-left font-medium">
                    {t('modes.plaintext')}
                  </th>
                  {ciphers.map(({ mode }) => (
                    <th key={mode} scope="col" className="px-3 py-2 text-left font-medium">
                      {mode}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y">
                {plainBlocks.map((block, index) => (
                  <tr key={index}>
                    <td className="px-3 py-2 text-xs text-muted-foreground tabular-nums">#{index + 1}</td>
                    <td className="px-3 py-2">
                      <BlockText block={block} />
                    </td>
                    {ciphers.map(({ mode, blocks, firstSeen }) => {
                      const same = firstSeen[index]
                      return (
                        <td key={mode} className="px-2 py-1.5">
                          <span
                            title={toHex(blocks[index])}
                            className={cn(
                              'inline-flex flex-col rounded-md px-1.5 py-0.5',
                              same >= 0 && 'bg-destructive/10 ring-1 ring-destructive/30 ring-inset',
                            )}
                          >
                            <span className="font-mono text-xs whitespace-nowrap">
                              {toHex(blocks[index].subarray(0, 4))}…
                            </span>
                            {same >= 0 && (
                              <span className="text-[0.6875rem] whitespace-nowrap text-destructive">
                                {t('modes.sameAs', { index: same + 1 })}
                              </span>
                            )}
                          </span>
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollRegion>
        )}

        {repeats > 0 ? (
          <div className="flex flex-col gap-2">
            <Callout tone="bad">{t('modes.ecbLeak', { count: repeats, total: plainBlocks.length })}</Callout>
            <Callout tone="good">{t('modes.chainNoLeak', { modes: chained.join(', ') })}</Callout>
          </div>
        ) : (
          <Callout tone="info">{t('modes.ecbNoLeak')}</Callout>
        )}
      </div>
    </Panel>
  )
}

function ModeExplainer({ modes }: { modes: DemoMode[] }) {
  const { t } = useI18n()
  const formulas: Record<DemoMode, ReactNode> = {
    ECB: (
      <>
        C<sub>i</sub> = AES<sub>K</sub>(P<sub>i</sub>)
      </>
    ),
    CBC: (
      <>
        C<sub>i</sub> = AES<sub>K</sub>(P<sub>i</sub> ⊕ C<sub>i−1</sub>), C<sub>0</sub> = IV
      </>
    ),
    CTR: (
      <>
        C<sub>i</sub> = P<sub>i</sub> ⊕ AES<sub>K</sub>(IV + i)
      </>
    ),
  }
  const body: Record<DemoMode, string> = {
    ECB: t('modes.whyEcb'),
    CBC: t('modes.whyCbc'),
    CTR: t('modes.whyCtr'),
  }
  return (
    <Panel>
      <PanelHeader title={t('modes.whyTitle')} />
      <div className="flex flex-col gap-4 p-4 sm:p-5">
        <div className={cn('grid gap-3', modes.length === 3 ? 'lg:grid-cols-3' : 'md:grid-cols-2')}>
          {modes.map((mode) => (
            <div key={mode} className="flex flex-col gap-2.5 rounded-lg border p-3.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold">{mode}</span>
                {mode === 'ECB' ? <Tag tone="bad">{t('modes.leaks')}</Tag> : <Tag tone="good">{t('modes.hides')}</Tag>}
              </div>
              <Formula>{formulas[mode]}</Formula>
              <p className="text-[0.8125rem] leading-relaxed text-muted-foreground">{body[mode]}</p>
            </div>
          ))}
        </div>
        <Callout
          tone="info"
          action={
            <Button variant="outline" size="sm" onClick={() => navigate('aes')}>
              {t('modes.openAes')}
              <ArrowRightIcon data-icon="inline-end" />
            </Button>
          }
        >
          {t('modes.takeaway')}
        </Callout>
      </div>
    </Panel>
  )
}

export function BlockModesLesson() {
  const { level } = useSettings()
  const modes: DemoMode[] = level === 'advanced' ? ALL_MODES : ['ECB', 'CBC']
  return (
    <div className="grid gap-5">
      <ImageDemo modes={modes} />
      <TextDemo modes={modes} />
      <ModeExplainer modes={modes} />
    </div>
  )
}
