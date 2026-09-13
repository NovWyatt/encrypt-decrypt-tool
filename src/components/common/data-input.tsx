import { useId, useRef, useState, type ReactNode } from 'react'
import { FileIcon, FileTextIcon, FolderOpenIcon, TrashIcon, UploadSimpleIcon, XIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { AnimatePresence, motion } from 'motion/react'
import { Panel } from '@/components/common/page'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useI18n } from '@/i18n'
import { EMPTY_INPUT, inputFromFile, loadFile, type InputValue } from '@/lib/files'
import { formatSize } from '@/lib/format'

interface DataInputProps {
  label: string
  value: InputValue
  onChange: (value: InputValue) => void
  placeholder: string
  monospace?: boolean
  /** Rendered at the bottom right, typically the primary action. */
  action?: ReactNode
  /** Rendered next to the label, for example the detected format. */
  badge?: ReactNode
  onError: (error: unknown) => void
  onSubmit?: () => void
}

const DISPLAY_LIMIT = 400_000

export function DataInput({
  label,
  value,
  onChange,
  placeholder,
  monospace,
  action,
  badge,
  onError,
  onSubmit,
}: DataInputProps) {
  const { t, formatNumber } = useI18n()
  const id = useId()
  const fileInput = useRef<HTMLInputElement>(null)
  const dragDepth = useRef(0)
  const [dragging, setDragging] = useState(false)

  const openFile = async (file: File | undefined) => {
    if (!file) return
    try {
      onChange(inputFromFile(await loadFile(file)))
    } catch (error) {
      onError(error)
    }
  }

  const file = value.kind === 'binary' ? value.file : value.file
  const tooLongToEdit = value.kind === 'text' && value.text.length > DISPLAY_LIMIT

  return (
    <Panel
      className={cn(
        'relative flex flex-col transition-[border-color,box-shadow] focus-within:border-ring/60 focus-within:ring-3 focus-within:ring-ring/20',
        dragging && 'border-primary ring-3 ring-primary/20',
      )}
      onDragEnter={(event) => {
        if (!event.dataTransfer.types.includes('Files')) return
        event.preventDefault()
        dragDepth.current++
        setDragging(true)
      }}
      onDragOver={(event) => {
        if (event.dataTransfer.types.includes('Files')) event.preventDefault()
      }}
      onDragLeave={() => {
        dragDepth.current = Math.max(0, dragDepth.current - 1)
        if (dragDepth.current === 0) setDragging(false)
      }}
      onDrop={(event) => {
        event.preventDefault()
        dragDepth.current = 0
        setDragging(false)
        void openFile(event.dataTransfer.files[0])
      }}
    >
      <div className="flex min-h-12 flex-wrap items-center justify-between gap-2 border-b px-4 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <label htmlFor={id} className="text-sm font-semibold">
            {label}
          </label>
          {badge}
        </div>
        <div className="flex items-center gap-1">
          <input
            ref={fileInput}
            type="file"
            className="sr-only"
            tabIndex={-1}
            aria-hidden
            onChange={(event) => {
              void openFile(event.target.files?.[0])
              event.target.value = ''
            }}
          />
          <Button variant="ghost" size="sm" onClick={() => fileInput.current?.click()}>
            <FolderOpenIcon />
            {t('common.openFile')}
          </Button>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={t('common.clear')}
                disabled={value.kind === 'text' && !value.text && !value.file}
                onClick={() => onChange(EMPTY_INPUT)}
              >
                <TrashIcon />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{t('common.clear')}</TooltipContent>
          </Tooltip>
        </div>
      </div>

      {file && (
        <div className="flex items-center gap-2.5 border-b bg-muted/40 px-4 py-2 text-sm">
          {value.kind === 'binary' ? (
            <FileIcon className="size-4 shrink-0 text-muted-foreground" />
          ) : (
            <FileTextIcon className="size-4 shrink-0 text-muted-foreground" />
          )}
          <span className="min-w-0 truncate font-medium">{file.name}</span>
          <span className="shrink-0 text-xs text-muted-foreground tabular-nums">
            {formatSize(file.size, formatNumber)}
          </span>
          <Button
            variant="ghost"
            size="icon-xs"
            className="ml-auto"
            aria-label={t('common.removeFile')}
            onClick={() => onChange(EMPTY_INPUT)}
          >
            <XIcon />
          </Button>
        </div>
      )}

      <div className="relative flex-1">
        {value.kind === 'binary' ? (
          <div className="flex min-h-[220px] flex-col items-center justify-center gap-2 px-6 py-8 text-center">
            <span className="grid size-10 place-items-center rounded-xl bg-muted text-muted-foreground">
              <FileIcon className="size-5" />
            </span>
            <p className="max-w-[46ch] text-sm text-muted-foreground">{t('aes.binaryNotice')}</p>
          </div>
        ) : (
          <textarea
            id={id}
            value={tooLongToEdit ? `${value.text.slice(0, DISPLAY_LIMIT)}\n…` : value.text}
            readOnly={tooLongToEdit}
            onChange={(event) =>
              onChange({
                kind: 'text',
                text: event.target.value,
                file: value.file ? { ...value.file, pristine: false } : undefined,
              })
            }
            onKeyDown={(event) => {
              if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                event.preventDefault()
                onSubmit?.()
              }
            }}
            onPaste={(event) => {
              const pasted = event.clipboardData.files[0]
              if (pasted) {
                event.preventDefault()
                void openFile(pasted)
              }
            }}
            placeholder={placeholder}
            spellCheck={false}
            className={cn(
              'scrollbar-thin block max-h-[440px] min-h-[220px] w-full resize-y bg-transparent px-4 py-3 text-sm leading-relaxed outline-none placeholder:text-muted-foreground/80',
              monospace && 'text-cipher text-[0.8125rem]',
            )}
          />
        )}

        <AnimatePresence>
          {dragging && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="pointer-events-none absolute inset-2 grid place-items-center rounded-lg border-2 border-dashed border-primary/60 bg-background/85 backdrop-blur-[2px]"
            >
              <span className="flex items-center gap-2 text-sm font-medium text-primary">
                <UploadSimpleIcon weight="bold" className="size-4" />
                {t('common.dropHere')}
              </span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div className="flex min-h-14 flex-wrap items-center justify-between gap-3 border-t px-4 py-2.5">
        <p className="text-xs text-muted-foreground tabular-nums">
          {value.kind === 'text'
            ? t('common.chars', { count: formatNumber([...value.text].length) })
            : formatSize(value.file.size, formatNumber)}
        </p>
        {action}
      </div>
    </Panel>
  )
}
