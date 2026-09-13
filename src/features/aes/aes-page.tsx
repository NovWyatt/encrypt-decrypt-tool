import { useCallback, useEffect, useState, type ReactNode } from 'react'
import {
  ArrowsDownUpIcon,
  CaretDownIcon,
  DownloadSimpleIcon,
  LockKeyIcon,
  LockKeyOpenIcon,
  TextAlignLeftIcon,
} from '@phosphor-icons/react'
import { cn } from 'cn'
import { AnimatePresence, motion } from 'motion/react'
import { Tag } from '@/components/common/choice'
import { CopyButton } from '@/components/common/copy-button'
import { DataInput } from '@/components/common/data-input'
import { ErrorAlert } from '@/components/common/error-alert'
import { DetailsList, OutputEmpty, OutputRunning, OutputText, type DetailRow } from '@/components/common/output'
import { PageContainer, PageHeader, Panel } from '@/components/common/page'
import { Segmented } from '@/components/common/segmented'
import { Button } from '@/components/ui/button'
import { ButtonGroup } from '@/components/ui/button-group'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Kbd, KbdGroup } from '@/components/ui/kbd'
import { useFitsViewport } from '@/hooks/use-fits-viewport'
import { useOperation } from '@/hooks/use-operation'
import { usePersistentState } from '@/hooks/use-persistent-state'
import { useI18n, type TFunction } from '@/i18n'
import { callCrypto } from '@/lib/crypto/client'
import { utf8Encode } from '@/lib/crypto/encoding'
import { InputProblem } from '@/lib/describe-error'
import type {
  AesDecryptRequest,
  CipherSummary,
  DataInput as CryptoDataInput,
  DecryptResponse,
  EncryptResponse,
} from '@/lib/crypto/service'
import {
  decryptedFileName,
  downloadBlob,
  EMPTY_INPUT,
  encryptedFileName,
  inputFileName,
  isInputEmpty,
  type InputValue,
} from '@/lib/files'
import { algorithmLabel, describeKdf, formatDuration, formatSize, groupHex } from '@/lib/format'
import { useSettings } from '@/stores/settings'
import { DecryptSettings, EncryptSettings } from './aes-settings'
import {
  decryptSecretKind,
  DEFAULT_AES_OPTIONS,
  effectiveOptions,
  encryptSecretKind,
  isAesOptions,
  selectedKdf,
  type AesOptions,
  type InspectState,
  type OpenSslDecryptOptions,
  type RawDecryptOptions,
  type SecretState,
} from './options'

type Direction = 'encrypt' | 'decrypt'
type Stage = 'kdf' | 'encrypt' | 'decrypt'
type NumberFormatter = (value: number, options?: Intl.NumberFormatOptions) => string

const EMPTY_SECRET: SecretState = { kind: 'password', password: '', keyText: '', aad: '', iv: '' }
const DEFAULT_OPENSSL_DECRYPT: OpenSslDecryptOptions = {
  auto: true,
  mode: 'CBC',
  keyBits: 256,
  kdf: 'pbkdf2',
  iterations: 10_000,
}
const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.userAgent)

function encryptData(value: InputValue): Uint8Array<ArrayBuffer> {
  if (value.kind === 'binary') return value.file.bytes
  // An untouched text file is encrypted byte for byte, keeping its BOM and line endings.
  return value.file?.pristine ? value.file.bytes : utf8Encode(value.text)
}

function decryptData(value: InputValue): CryptoDataInput {
  if (value.kind === 'binary') return { bytes: value.file.bytes }
  // Files go through byte detection, which also recognizes binary containers that happen to be valid UTF-8.
  return value.file?.pristine ? { bytes: value.file.bytes } : { text: value.text }
}

function summaryRows(summary: CipherSummary, t: TFunction, formatNumber: NumberFormatter): DetailRow[] {
  const rows: DetailRow[] = [
    { label: t('aes.sumAlgorithm'), value: algorithmLabel(summary) },
    {
      label: t('aes.sumContainer'),
      value: { edt: t('aes.formatEdt'), openssl: t('aes.formatOpenssl'), raw: t('aes.formatRaw') }[summary.container],
    },
  ]
  if (summary.keySource) {
    const sources = { password: t('aes.keyFromPassword'), raw: t('aes.keyFromRaw'), rsa: t('aes.keyFromRsa') }
    rows.push({ label: t('aes.sumKey'), value: sources[summary.keySource] })
  }
  if (summary.kdf) rows.push({ label: t('aes.sumKdf'), value: describeKdf(summary.kdf, formatNumber) })
  if (summary.openssl) {
    const { kdf } = summary.openssl
    rows.push({
      label: t('aes.sumKdf'),
      value: kdf.kind === 'md5' ? 'EVP_BytesToKey (MD5)' : `PBKDF2-HMAC-${kdf.hash}, ${formatNumber(kdf.iterations)}`,
    })
  }
  const integrity = {
    aead: t('aes.integrityAead'),
    hmac: t('aes.integrityHmac'),
    check: t('aes.integrityCheck'),
    label: t('aes.integrityLabel'),
    none: t('aes.integrityNone'),
  }[summary.integrity]
  const authenticated = summary.integrity === 'aead' || summary.integrity === 'hmac'
  rows.push({
    label: t('aes.sumIntegrity'),
    value: (
      <span className="inline-flex flex-wrap items-center gap-1.5">
        {integrity}
        {!authenticated && <Tag tone="warn">{t('common.insecure')}</Tag>}
      </span>
    ),
  })
  if (summary.ivHex) rows.push({ label: t('aes.sumIv'), value: groupHex(summary.ivHex), mono: true })
  if (summary.saltHex) rows.push({ label: t('aes.sumSalt'), value: groupHex(summary.saltHex), mono: true })
  return rows
}

/** The `openssl enc` command that decrypts the downloaded binary file. */
function opensslCommand(summary: CipherSummary, fileName: string): string | null {
  const options = summary.openssl
  if (!options) return null
  const kdf = options.kdf.kind === 'md5' ? '-md md5' : `-pbkdf2 -iter ${options.kdf.iterations}`
  const cipher = `aes-${options.keyBits}-${options.mode.toLowerCase()}`
  return `openssl enc -d -${cipher} ${kdf} -in ${fileName} -out ${decryptedFileName(fileName, true)}`
}

function isAutoDetectable(options: NonNullable<CipherSummary['openssl']>): boolean {
  if (options.mode !== 'CBC') return false
  return options.kdf.kind === 'md5' || (options.kdf.hash === 'SHA-256' && options.kdf.iterations === 10_000)
}

export function AesPage() {
  const { t, formatNumber } = useI18n()
  const { level } = useSettings()
  const [direction, setDirection] = useState<Direction>('encrypt')
  const [savedOptions, setSavedOptions] = usePersistentState<AesOptions>(
    'edt.aes.options',
    DEFAULT_AES_OPTIONS,
    isAesOptions,
  )
  const options = effectiveOptions(savedOptions, level)
  const patchOptions = useCallback(
    (patch: Partial<AesOptions>) => setSavedOptions((current) => ({ ...current, ...patch })),
    [setSavedOptions],
  )

  const [encryptInput, setEncryptInput] = useState<InputValue>(EMPTY_INPUT)
  const [decryptInput, setDecryptInput] = useState<InputValue>(EMPTY_INPUT)
  const [encryptSecret, setEncryptSecret] = useState<SecretState>(EMPTY_SECRET)
  const [decryptSecret, setDecryptSecret] = useState<SecretState>(EMPTY_SECRET)
  const [encryptErrors, setEncryptErrors] = useState<{ password?: string; key?: string }>({})
  const [decryptErrors, setDecryptErrors] = useState<{ password?: string; key?: string }>({})
  const [lastInspection, setInspection] = useState<InspectState>({ status: 'empty' })
  // While new input is being inspected the previous result stays visible, which avoids flicker.
  const inspection: InspectState = isInputEmpty(decryptInput) ? { status: 'empty' } : lastInspection
  const [opensslOptions, setOpensslOptions] = useState<OpenSslDecryptOptions>(DEFAULT_OPENSSL_DECRYPT)
  const [rawOptions, setRawOptions] = useState<RawDecryptOptions>({ mode: 'GCM', keyBits: 256, iv: '' })

  const encryptOp = useOperation<EncryptResponse, Stage>()
  const decryptOp = useOperation<DecryptResponse, Stage>()
  const [asideRef, asideFits] = useFitsViewport<HTMLDivElement>()

  // Describe the ciphertext as soon as it arrives, so the form can ask for the right secret.
  useEffect(() => {
    if (isInputEmpty(decryptInput)) return
    let cancelled = false
    const timer = setTimeout(() => {
      callCrypto('inspectCiphertext', decryptData(decryptInput)).then(
        (result) => !cancelled && setInspection({ status: 'ok', result }),
        (error: unknown) => !cancelled && setInspection({ status: 'invalid', error }),
      )
    }, 200)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [decryptInput])

  const patchEncryptSecret = (patch: Partial<SecretState>) => {
    setEncryptSecret((current) => ({ ...current, ...patch }))
    setEncryptErrors({})
  }
  const patchDecryptSecret = (patch: Partial<SecretState>) => {
    setDecryptSecret((current) => ({ ...current, ...patch }))
    setDecryptErrors({})
  }

  const submitEncrypt = () => {
    if (encryptOp.state.status === 'running') return
    if (isInputEmpty(encryptInput)) return encryptOp.fail(new InputProblem('errors.emptyInput'))
    const kind = encryptSecretKind(level, options, encryptSecret)
    if (kind === 'password' && !encryptSecret.password) {
      return setEncryptErrors({ password: t('errors.emptyPassword') })
    }
    if (kind === 'raw' && !encryptSecret.keyText.trim()) return setEncryptErrors({ key: t('errors.emptyKey') })

    // Basic level never sends advanced-only fields, even if they were filled in earlier.
    const advanced = level === 'advanced' && options.format !== 'openssl'
    void encryptOp.run(kind === 'password' && options.format === 'edt' ? 'kdf' : 'encrypt', () =>
      callCrypto('encryptAes', {
        data: encryptData(encryptInput),
        format: options.format,
        secret:
          kind === 'password'
            ? { kind: 'password', password: encryptSecret.password }
            : { kind: 'raw', keyText: encryptSecret.keyText },
        mode: options.mode,
        keyBits: options.keyBits,
        kdf: selectedKdf(options),
        mac: options.mac,
        aad: advanced && options.mode === 'GCM' ? encryptSecret.aad || undefined : undefined,
        iv: advanced ? encryptSecret.iv || undefined : undefined,
        opensslKdf:
          options.opensslKdf === 'md5'
            ? { kind: 'md5' }
            : { kind: 'pbkdf2', hash: 'SHA-256', iterations: options.opensslIterations },
        encoding: options.encoding,
        wrapLines: options.wrapLines,
      }),
    )
  }

  const submitDecrypt = () => {
    if (decryptOp.state.status === 'running') return
    if (isInputEmpty(decryptInput)) return decryptOp.fail(new InputProblem('errors.emptyInput'))
    const result = inspection.status === 'ok' ? inspection.result : null
    const summary = result && result.container !== 'raw' ? result.summary : null
    if (summary && summary.container === 'edt' && summary.kind !== 'aes') {
      return decryptOp.fail(new InputProblem('errors.notAesMessage'))
    }
    const kind = decryptSecretKind(inspection, decryptSecret)
    if (kind === 'password' && !decryptSecret.password) {
      return setDecryptErrors({ password: t('errors.emptyPassword') })
    }
    if (kind === 'raw' && !decryptSecret.keyText.trim()) return setDecryptErrors({ key: t('errors.emptyKey') })

    const manualOpenssl = level === 'advanced' && !opensslOptions.auto
    const request: AesDecryptRequest = {
      input: decryptData(decryptInput),
      secret:
        kind === 'password'
          ? { kind: 'password', password: decryptSecret.password }
          : { kind: 'raw', keyText: decryptSecret.keyText },
      aad: decryptSecret.aad || undefined,
      openssl: manualOpenssl
        ? {
            mode: opensslOptions.mode,
            keyBits: opensslOptions.keyBits,
            kdf:
              opensslOptions.kdf === 'md5'
                ? { kind: 'md5' }
                : { kind: 'pbkdf2', hash: 'SHA-256', iterations: opensslOptions.iterations },
          }
        : undefined,
      raw: rawOptions,
    }
    void decryptOp.run(summary?.kdf ? 'kdf' : 'decrypt', () => callCrypto('decryptAes', request))
  }

  const sendToDecrypt = (result: EncryptResponse) => {
    const { summary } = result
    const name = inputFileName(encryptInput)
    const extension = summary.container === 'edt' ? '.edt' : options.encoding === 'hex' ? '.hex' : '.b64'
    const bytes = utf8Encode(result.text)
    setDecryptInput({
      kind: 'text',
      text: result.text,
      file: name ? { name: encryptedFileName(name, extension), size: bytes.length, bytes, pristine: false } : undefined,
    })
    setDecryptSecret({ ...encryptSecret })
    setDecryptErrors({})
    if (summary.container === 'raw' && summary.mode && summary.keyBits) {
      setRawOptions({ mode: summary.mode, keyBits: summary.keyBits, iv: result.extras?.ivHex ?? '' })
    }
    if (summary.openssl) {
      const { mode, keyBits, kdf } = summary.openssl
      setOpensslOptions(
        isAutoDetectable(summary.openssl)
          ? DEFAULT_OPENSSL_DECRYPT
          : {
              auto: false,
              mode,
              keyBits,
              kdf: kdf.kind,
              iterations: kdf.kind === 'pbkdf2' ? kdf.iterations : 10_000,
            },
      )
    }
    decryptOp.reset()
    setDirection('decrypt')
  }

  const sendToEncrypt = (result: DecryptResponse) => {
    if (result.text === null) return
    setEncryptInput({ kind: 'text', text: result.text })
    encryptOp.reset()
    setDirection('encrypt')
  }

  const op = direction === 'encrypt' ? encryptOp : decryptOp
  const submit = direction === 'encrypt' ? submitEncrypt : submitDecrypt
  const stageLabel = (stage: Stage) =>
    ({ kdf: t('aes.stageKdf'), encrypt: t('aes.stageEncrypt'), decrypt: t('aes.stageDecrypt') })[stage]

  const runButton = (
    <div className="flex items-center gap-3">
      <KbdGroup className="hidden text-muted-foreground sm:inline-flex" aria-hidden>
        <Kbd>{IS_MAC ? '⌘' : 'Ctrl'}</Kbd>
        <Kbd>Enter</Kbd>
      </KbdGroup>
      <Button size="lg" onClick={submit} disabled={op.state.status === 'running'} className="min-w-32 px-4">
        {direction === 'encrypt' ? <LockKeyIcon weight="bold" /> : <LockKeyOpenIcon weight="bold" />}
        {direction === 'encrypt' ? t('aes.runEncrypt') : t('aes.runDecrypt')}
      </Button>
    </div>
  )

  let detectionBadge: ReactNode = null
  if (inspection.status === 'invalid') {
    detectionBadge = <Tag tone="warn">{t('aes.detectInvalid')}</Tag>
  } else if (inspection.status === 'ok') {
    const { result } = inspection
    detectionBadge = (
      <Tag>{result.container === 'edt' ? 'EDT' : result.container === 'openssl' ? 'OpenSSL' : result.encoding}</Tag>
    )
  }

  const encryptState = encryptOp.state
  const decryptState = decryptOp.state
  let status: ReactNode = null
  let meta: string | null = null
  let body: ReactNode

  if (direction === 'encrypt') {
    if (encryptState.status === 'idle') {
      body = <OutputEmpty icon={LockKeyIcon} title={t('aes.emptyEncryptTitle')} body={t('aes.emptyEncryptBody')} />
    } else if (encryptState.status === 'running') {
      body = <OutputRunning label={stageLabel(encryptState.stage)} startedAt={encryptState.startedAt} />
    } else if (encryptState.status === 'error') {
      body = (
        <div className="p-4">
          <ErrorAlert error={encryptState.error} />
        </div>
      )
    } else {
      const { data } = encryptState
      status = <Tag tone="good">{t('aes.doneEncrypt')}</Tag>
      meta = `${formatSize(data.inputBytes, formatNumber)} → ${formatSize(data.bytes.length, formatNumber)}, ${formatDuration(data.kdfMs + data.cipherMs, t, formatNumber)}`
      body = (
        <EncryptResult
          result={data}
          sourceName={inputFileName(encryptInput)}
          encoding={options.encoding}
          rows={summaryRows(data.summary, t, formatNumber)}
          onSendToDecrypt={sendToDecrypt}
        />
      )
    }
  } else if (decryptState.status === 'idle') {
    body = <OutputEmpty icon={TextAlignLeftIcon} title={t('aes.emptyDecryptTitle')} body={t('aes.emptyDecryptBody')} />
  } else if (decryptState.status === 'running') {
    body = <OutputRunning label={stageLabel(decryptState.stage)} startedAt={decryptState.startedAt} />
  } else if (decryptState.status === 'error') {
    body = (
      <div className="p-4">
        <ErrorAlert error={decryptState.error} />
      </div>
    )
  } else {
    const { data } = decryptState
    status = <Tag tone="good">{t('aes.doneDecrypt')}</Tag>
    meta = `${formatSize(data.bytes.length, formatNumber)}, ${formatDuration(data.kdfMs + data.cipherMs, t, formatNumber)}`
    body = (
      <DecryptResult
        result={data}
        sourceName={inputFileName(decryptInput)}
        rows={summaryRows(data.summary, t, formatNumber)}
        onSendToEncrypt={sendToEncrypt}
      />
    )
  }

  return (
    <PageContainer>
      <PageHeader
        title={t('aes.title')}
        description={t('aes.description')}
        actions={
          <Segmented<Direction>
            size="lg"
            ariaLabel={t('aes.title')}
            value={direction}
            onValueChange={setDirection}
            options={[
              { value: 'encrypt', label: t('common.encrypt'), icon: LockKeyIcon },
              { value: 'decrypt', label: t('common.decrypt'), icon: LockKeyOpenIcon },
            ]}
          />
        }
      />

      <div className="grid items-start gap-5 lg:grid-cols-[minmax(300px,360px)_minmax(0,1fr)] xl:grid-cols-[380px_minmax(0,1fr)]">
        <div ref={asideRef} className={cn(asideFits && 'lg:sticky lg:top-6')}>
          {direction === 'encrypt' ? (
            <EncryptSettings
              level={level}
              options={options}
              onOptions={patchOptions}
              secret={encryptSecret}
              onSecret={patchEncryptSecret}
              errors={encryptErrors}
            />
          ) : (
            <DecryptSettings
              level={level}
              inspection={inspection}
              secret={decryptSecret}
              onSecret={patchDecryptSecret}
              openssl={opensslOptions}
              onOpenssl={(patch) => setOpensslOptions((current) => ({ ...current, ...patch }))}
              raw={rawOptions}
              onRaw={(patch) => setRawOptions((current) => ({ ...current, ...patch }))}
              errors={decryptErrors}
            />
          )}
        </div>

        <div className="grid min-w-0 gap-5">
          {direction === 'encrypt' ? (
            <DataInput
              label={t('aes.inputEncrypt')}
              value={encryptInput}
              onChange={(value) => {
                setEncryptInput(value)
                if (encryptOp.state.status === 'error') encryptOp.reset()
              }}
              placeholder={t('aes.placeholderEncrypt')}
              action={runButton}
              onError={encryptOp.fail}
              onSubmit={submitEncrypt}
            />
          ) : (
            <DataInput
              label={t('aes.inputDecrypt')}
              value={decryptInput}
              onChange={(value) => {
                setDecryptInput(value)
                if (isInputEmpty(value)) setInspection({ status: 'empty' })
                if (decryptOp.state.status === 'error') decryptOp.reset()
              }}
              placeholder={t('aes.placeholderDecrypt')}
              monospace
              badge={detectionBadge}
              action={runButton}
              onError={decryptOp.fail}
              onSubmit={submitDecrypt}
            />
          )}

          <Panel className="overflow-hidden">
            <div className="flex min-h-12 flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b px-4 py-2">
              <div className="flex min-w-0 items-center gap-2" role="status">
                <h2 className="text-sm font-semibold">{t('aes.resultTitle')}</h2>
                {status}
              </div>
              {meta && <p className="text-xs text-muted-foreground tabular-nums">{meta}</p>}
            </div>
            <AnimatePresence mode="wait" initial={false}>
              <motion.div
                key={`${direction}-${op.state.status}-${'id' in op.state ? op.state.id : 0}`}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, transition: { duration: 0.08 } }}
                transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              >
                {body}
              </motion.div>
            </AnimatePresence>
          </Panel>
        </div>
      </div>
    </PageContainer>
  )
}

function ResultDetails({ rows, children }: { rows: DetailRow[]; children?: ReactNode }) {
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
        <div className="flex flex-col gap-4 px-4 pb-4">
          <DetailsList rows={rows} />
          {children}
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}

function ActionBar({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-2 border-t px-4 py-3">{children}</div>
}

function EncryptResult({
  result,
  sourceName,
  encoding,
  rows,
  onSendToDecrypt,
}: {
  result: EncryptResponse
  sourceName?: string
  encoding: 'base64' | 'hex'
  rows: DetailRow[]
  onSendToDecrypt: (result: EncryptResponse) => void
}) {
  const { t } = useI18n()
  const { container } = result.summary
  const textExtension = container === 'edt' ? '.edt' : encoding === 'hex' ? '.hex' : '.b64'
  const binaryExtension = { edt: '.edt.bin', openssl: '.enc', raw: '.bin' }[container]
  const textName = encryptedFileName(sourceName, textExtension)
  const binaryName = encryptedFileName(sourceName, binaryExtension)
  const downloadText = () => downloadBlob(result.text, textName, 'text/plain;charset=utf-8')
  const downloadBinary = () => downloadBlob(result.bytes, binaryName, 'application/octet-stream')
  // Armored EDT text is the portable default; OpenSSL and raw tools expect the binary file.
  const primaryDownload = container === 'edt' ? downloadText : downloadBinary
  const command = container === 'openssl' ? opensslCommand(result.summary, binaryName) : null
  const ivHex = result.extras?.ivHex

  return (
    <div>
      <OutputText text={result.text} cipher />
      {ivHex && (
        <div className="flex items-center gap-3 border-t bg-muted/30 py-1.5 pr-2 pl-4">
          <span className="text-xs font-medium text-muted-foreground">IV</span>
          <code className="min-w-0 flex-1 truncate font-mono text-xs">{ivHex}</code>
          <CopyButton value={ivHex} iconOnly variant="ghost" size="icon-xs" />
        </div>
      )}
      <ActionBar>
        <CopyButton value={result.text} />
        <ButtonGroup>
          <Button variant="outline" size="sm" onClick={primaryDownload}>
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
        <Button variant="ghost" size="sm" className="ml-auto" onClick={() => onSendToDecrypt(result)}>
          <ArrowsDownUpIcon />
          {t('common.useAsInput')}
        </Button>
      </ActionBar>
      <ResultDetails rows={rows}>
        {container === 'raw' && (
          <p className="text-xs leading-relaxed text-muted-foreground">{t('aes.rawOutputNote')}</p>
        )}
        {command && (
          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-muted-foreground">{t('aes.opensslCommand')}</span>
            <div className="flex items-start gap-2 rounded-md bg-muted/60 py-2 pr-1.5 pl-3">
              <code className="min-w-0 flex-1 py-0.5 font-mono text-xs leading-5 break-all">{command}</code>
              <CopyButton value={command} iconOnly variant="ghost" size="icon-xs" />
            </div>
          </div>
        )}
      </ResultDetails>
    </div>
  )
}

function DecryptResult({
  result,
  sourceName,
  rows,
  onSendToEncrypt,
}: {
  result: DecryptResponse
  sourceName?: string
  rows: DetailRow[]
  onSendToEncrypt: (result: DecryptResponse) => void
}) {
  const { t, formatNumber } = useI18n()
  const { text } = result
  const fileName = decryptedFileName(sourceName, text !== null)
  const download = () =>
    downloadBlob(result.bytes, fileName, text !== null ? 'text/plain;charset=utf-8' : 'application/octet-stream')
  return (
    <div>
      {text !== null ? (
        <OutputText text={text} />
      ) : (
        <p className="px-4 py-10 text-center text-sm text-muted-foreground">
          {t('aes.binaryResult', { size: formatSize(result.bytes.length, formatNumber) })}
        </p>
      )}
      <ActionBar>
        {text !== null && <CopyButton value={text} />}
        <Button variant="outline" size="sm" onClick={download}>
          <DownloadSimpleIcon />
          {t('common.download')}
        </Button>
        {text !== null && (
          <Button variant="ghost" size="sm" className="ml-auto" onClick={() => onSendToEncrypt(result)}>
            <ArrowsDownUpIcon />
            {t('common.useAsInputEncrypt')}
          </Button>
        )}
      </ActionBar>
      <ResultDetails rows={rows} />
    </div>
  )
}
