import { useState, type ReactNode } from 'react'
import { ArrowsDownUpIcon, CaretDownIcon, DownloadSimpleIcon, type Icon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { motion } from 'motion/react'
import { CopyButton } from '@/components/common/copy-button'
import { ErrorAlert } from '@/components/common/error-alert'
import { OutputEmpty, OutputRunning, OutputText } from '@/components/common/output'
import { Panel } from '@/components/common/page'
import { Button } from '@/components/ui/button'
import { ButtonGroup } from '@/components/ui/button-group'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import type { OperationState } from '@/hooks/use-operation'
import { useI18n } from '@/i18n'
import { decryptedFileName, downloadBlob, encryptedFileName } from '@/lib/files'
import { formatSize } from '@/lib/format'

interface ResultPanelProps<T, Stage extends string> {
  state: OperationState<T, Stage>
  /** Distinguishes views that share the panel (for example encrypt and decrypt) so they animate separately. */
  view?: string
  title?: string
  status?: (data: T) => ReactNode
  meta?: (data: T) => ReactNode
  empty: { icon: Icon; title: string; body: string }
  stageLabel: (stage: Stage) => string
  children: (data: T) => ReactNode
}

/** The output surface shared by every tool: empty, running, error and success states. */
export function ResultPanel<T, Stage extends string>({
  state,
  view = 'default',
  title,
  status,
  meta,
  empty,
  stageLabel,
  children,
}: ResultPanelProps<T, Stage>) {
  const { t } = useI18n()
  const key = `${view}-${state.status}-${'id' in state ? state.id : 0}`
  // The body the panel mounts with arrives with its page. Once the body has changed, each new one fades in.
  const [mountKey, setMountKey] = useState<string | null>(key)
  if (mountKey !== null && key !== mountKey) setMountKey(null)

  let body: ReactNode
  if (state.status === 'idle') body = <OutputEmpty icon={empty.icon} title={empty.title} body={empty.body} />
  else if (state.status === 'running')
    body = <OutputRunning label={stageLabel(state.stage)} startedAt={state.startedAt} />
  else if (state.status === 'error') {
    body = (
      <div className="p-4">
        <ErrorAlert error={state.error} />
      </div>
    )
  } else body = children(state.data)

  return (
    <Panel className="overflow-hidden">
      <div className="flex min-h-12 flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b px-4 py-2">
        <div className="flex min-w-0 items-center gap-2" role="status">
          <h2 className="text-sm font-semibold">{title ?? t('aes.resultTitle')}</h2>
          {state.status === 'running' && <span className="sr-only">{stageLabel(state.stage)}</span>}
          {state.status === 'success' && status?.(state.data)}
        </div>
        {state.status === 'success' && meta && (
          <p className="text-xs text-muted-foreground tabular-nums">{meta(state.data)}</p>
        )}
      </div>
      {/* No exit animation: the key swaps the body in the same commit as the header. AnimatePresence in "wait" mode
          could leave an old body on screen for good when an operation finished while that body was leaving. */}
      <motion.div
        key={key}
        initial={mountKey === null && { opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
      >
        {body}
      </motion.div>
    </Panel>
  )
}

export function ActionBar({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-2 border-t px-4 py-3">{children}</div>
}

/** Collapsible "Parameters" section under a result. */
export function ResultDetails({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="border-t">
      <CollapsibleTrigger className="flex w-full items-center justify-between px-4 py-3 text-left text-sm font-medium outline-none hover:bg-muted/40 focus-visible:bg-muted/60">
        {t('aes.summary')}
        <CaretDownIcon
          className={cn('size-4 text-muted-foreground transition-transform duration-200', open && 'rotate-180')}
        />
      </CollapsibleTrigger>
      <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down">
        <div className="flex flex-col gap-4 px-4 pb-4">{children}</div>
      </CollapsibleContent>
    </Collapsible>
  )
}

interface CiphertextOutputProps {
  text: string
  bytes: Uint8Array<ArrayBuffer>
  sourceName?: string
  textExtension: string
  binaryExtension: string
  /** OpenSSL and raw tools expect binary files; armored text is the portable default. */
  preferBinary?: boolean
  /** Rendered between the text and the actions, for example the IV of raw output. */
  extra?: ReactNode
  switchLabel?: string
  onSwitch?: () => void
  details?: ReactNode
}

export function CiphertextOutput({
  text,
  bytes,
  sourceName,
  textExtension,
  binaryExtension,
  preferBinary,
  extra,
  switchLabel,
  onSwitch,
  details,
}: CiphertextOutputProps) {
  const { t } = useI18n()
  const textName = encryptedFileName(sourceName, textExtension)
  const binaryName = encryptedFileName(sourceName, binaryExtension)
  const downloadText = () => downloadBlob(text, textName, 'text/plain;charset=utf-8')
  const downloadBinary = () => downloadBlob(bytes, binaryName, 'application/octet-stream')

  return (
    <div>
      <OutputText text={text} cipher />
      {extra}
      <ActionBar>
        <CopyButton value={text} />
        <ButtonGroup>
          <Button variant="outline" size="sm" onClick={preferBinary ? downloadBinary : downloadText}>
            <DownloadSimpleIcon />
            {t('common.download')}
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="icon-sm" aria-label={t('common.moreOptions')}>
                <CaretDownIcon />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={downloadText}>
                {t('common.downloadText')}
                <span className="ml-auto pl-4 font-mono text-xs text-muted-foreground">{textExtension}</span>
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={downloadBinary}>
                {t('common.downloadBinary')}
                <span className="ml-auto pl-4 font-mono text-xs text-muted-foreground">{binaryExtension}</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </ButtonGroup>
        {onSwitch && switchLabel && (
          <Button variant="ghost" size="sm" className="ml-auto" onClick={onSwitch}>
            <ArrowsDownUpIcon />
            {switchLabel}
          </Button>
        )}
      </ActionBar>
      {details && <ResultDetails>{details}</ResultDetails>}
    </div>
  )
}

interface PlaintextOutputProps {
  text: string | null
  bytes: Uint8Array<ArrayBuffer>
  sourceName?: string
  /** Rendered above the text, for example which key decrypted it. */
  banner?: ReactNode
  switchLabel?: string
  onSwitch?: () => void
  details?: ReactNode
}

export function PlaintextOutput({
  text,
  bytes,
  sourceName,
  banner,
  switchLabel,
  onSwitch,
  details,
}: PlaintextOutputProps) {
  const { t, formatNumber } = useI18n()
  const fileName = decryptedFileName(sourceName, text !== null)
  const download = () =>
    downloadBlob(bytes, fileName, text !== null ? 'text/plain;charset=utf-8' : 'application/octet-stream')
  return (
    <div>
      {banner}
      {text !== null ? (
        <OutputText text={text} />
      ) : (
        <p className="px-4 py-10 text-center text-sm text-muted-foreground">
          {t('aes.binaryResult', { size: formatSize(bytes.length, formatNumber) })}
        </p>
      )}
      <ActionBar>
        {text !== null && <CopyButton value={text} />}
        <Button variant="outline" size="sm" onClick={download}>
          <DownloadSimpleIcon />
          {t('common.download')}
        </Button>
        {text !== null && onSwitch && switchLabel && (
          <Button variant="ghost" size="sm" className="ml-auto" onClick={onSwitch}>
            <ArrowsDownUpIcon />
            {switchLabel}
          </Button>
        )}
      </ActionBar>
      {details && <ResultDetails>{details}</ResultDetails>}
    </div>
  )
}
