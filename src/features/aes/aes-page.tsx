import { useCallback, useState, type ReactNode } from 'react'
import { LockKeyIcon, LockKeyOpenIcon, TextAlignLeftIcon } from '@phosphor-icons/react'
import { Tag } from '@/components/common/choice'
import { CopyButton } from '@/components/common/copy-button'
import { DataInput } from '@/components/common/data-input'
import { PageContainer, PageHeader } from '@/components/common/page'
import { Segmented } from '@/components/common/segmented'
import { CiphertextOutput, PlaintextOutput, ResultPanel } from '@/components/crypto/result'
import { RunButton } from '@/components/crypto/run-button'
import { SummaryDetails } from '@/components/crypto/summary-details'
import { ToolLayout } from '@/components/crypto/tool-layout'
import { useInspection } from '@/hooks/use-inspection'
import { useOperation } from '@/hooks/use-operation'
import { usePersistentState } from '@/hooks/use-persistent-state'
import { useI18n } from '@/i18n'
import { callCrypto } from '@/lib/crypto/client'
import type { AesDecryptRequest, CipherSummary, DecryptResponse, EncryptResponse } from '@/lib/crypto/service'
import { InputProblem } from '@/lib/describe-error'
import {
  decryptedFileName,
  EMPTY_INPUT,
  encryptedFileName,
  inputFileName,
  isInputEmpty,
  type InputValue,
} from '@/lib/files'
import { formatDuration, formatSize } from '@/lib/format'
import { inputBytes, inputForDetection, textInput } from '@/lib/input-data'
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
  type OpenSslDecryptOptions,
  type RawDecryptOptions,
  type SecretState,
} from './options'

type Direction = 'encrypt' | 'decrypt'
type Stage = 'kdf' | 'encrypt' | 'decrypt'

const EMPTY_SECRET: SecretState = { kind: 'password', password: '', keyText: '', aad: '', iv: '' }
const DEFAULT_OPENSSL_DECRYPT: OpenSslDecryptOptions = {
  auto: true,
  mode: 'CBC',
  keyBits: 256,
  kdf: 'pbkdf2',
  iterations: 10_000,
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

function textExtension(summary: CipherSummary, encoding: 'base64' | 'hex'): string {
  if (summary.container === 'edt') return '.edt'
  return encoding === 'hex' ? '.hex' : '.b64'
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
  const [inspection, resetInspection] = useInspection(decryptInput)
  const [opensslOptions, setOpensslOptions] = useState<OpenSslDecryptOptions>(DEFAULT_OPENSSL_DECRYPT)
  const [rawOptions, setRawOptions] = useState<RawDecryptOptions>({ mode: 'GCM', keyBits: 256, iv: '' })

  const encryptOp = useOperation<EncryptResponse, Stage>()
  const decryptOp = useOperation<DecryptResponse, Stage>()

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
        data: inputBytes(encryptInput),
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
      input: inputForDetection(decryptInput),
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
    setDecryptInput(textInput(result.text, name && encryptedFileName(name, textExtension(summary, options.encoding))))
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

  const sendToEncrypt = (text: string) => {
    setEncryptInput({ kind: 'text', text })
    encryptOp.reset()
    setDirection('encrypt')
  }

  const stageLabel = (stage: Stage) =>
    ({ kdf: t('aes.stageKdf'), encrypt: t('aes.stageEncrypt'), decrypt: t('aes.stageDecrypt') })[stage]

  let detectionBadge: ReactNode = null
  if (inspection.status === 'invalid') {
    detectionBadge = <Tag tone="warn">{t('aes.detectInvalid')}</Tag>
  } else if (inspection.status === 'ok') {
    const { result } = inspection
    detectionBadge = (
      <Tag>{result.container === 'edt' ? 'EDT' : result.container === 'openssl' ? 'OpenSSL' : result.encoding}</Tag>
    )
  }

  const timing = (data: { kdfMs: number; cipherMs: number }) =>
    formatDuration(data.kdfMs + data.cipherMs, t, formatNumber)

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

      {direction === 'encrypt' ? (
        <ToolLayout
          aside={
            <EncryptSettings
              level={level}
              options={options}
              onOptions={patchOptions}
              secret={encryptSecret}
              onSecret={patchEncryptSecret}
              errors={encryptErrors}
            />
          }
        >
          <DataInput
            label={t('aes.inputEncrypt')}
            value={encryptInput}
            onChange={(value) => {
              setEncryptInput(value)
              if (encryptOp.state.status === 'error') encryptOp.reset()
            }}
            placeholder={t('aes.placeholderEncrypt')}
            action={
              <RunButton
                icon={LockKeyIcon}
                label={t('aes.runEncrypt')}
                onClick={submitEncrypt}
                disabled={encryptOp.state.status === 'running'}
              />
            }
            onError={encryptOp.fail}
            onSubmit={submitEncrypt}
          />
          <ResultPanel
            state={encryptOp.state}
            view="encrypt"
            empty={{ icon: LockKeyIcon, title: t('aes.emptyEncryptTitle'), body: t('aes.emptyEncryptBody') }}
            stageLabel={stageLabel}
            status={() => <Tag tone="good">{t('aes.doneEncrypt')}</Tag>}
            meta={(data) =>
              `${formatSize(data.inputBytes, formatNumber)} → ${formatSize(data.bytes.length, formatNumber)}, ${timing(data)}`
            }
          >
            {(data) => {
              const sourceName = inputFileName(encryptInput)
              const { container } = data.summary
              const binaryExtension = { edt: '.edt.bin', openssl: '.enc', raw: '.bin' }[container]
              const command =
                container === 'openssl'
                  ? opensslCommand(data.summary, encryptedFileName(sourceName, binaryExtension))
                  : null
              const ivHex = data.extras?.ivHex
              return (
                <CiphertextOutput
                  text={data.text}
                  bytes={data.bytes}
                  sourceName={sourceName}
                  textExtension={textExtension(data.summary, options.encoding)}
                  binaryExtension={binaryExtension}
                  preferBinary={container !== 'edt'}
                  switchLabel={t('common.useAsInput')}
                  onSwitch={() => sendToDecrypt(data)}
                  extra={
                    ivHex && (
                      <div className="flex items-center gap-3 border-t bg-muted/30 py-1.5 pr-2 pl-4">
                        <span className="text-xs font-medium text-muted-foreground">IV</span>
                        <code className="min-w-0 flex-1 truncate font-mono text-xs">{ivHex}</code>
                        <CopyButton value={ivHex} iconOnly variant="ghost" size="icon-xs" />
                      </div>
                    )
                  }
                  details={
                    <>
                      <SummaryDetails summary={data.summary} />
                      {container === 'raw' && (
                        <p className="text-xs leading-relaxed text-muted-foreground">{t('aes.rawOutputNote')}</p>
                      )}
                      {command && (
                        <div className="flex flex-col gap-1.5">
                          <span className="text-xs text-muted-foreground">{t('aes.opensslCommand')}</span>
                          <div className="flex items-start gap-2 rounded-md bg-muted/60 py-2 pr-1.5 pl-3">
                            <code className="min-w-0 flex-1 py-0.5 font-mono text-xs leading-5 break-all">
                              {command}
                            </code>
                            <CopyButton value={command} iconOnly variant="ghost" size="icon-xs" />
                          </div>
                        </div>
                      )}
                    </>
                  }
                />
              )
            }}
          </ResultPanel>
        </ToolLayout>
      ) : (
        <ToolLayout
          aside={
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
          }
        >
          <DataInput
            label={t('aes.inputDecrypt')}
            value={decryptInput}
            onChange={(value) => {
              setDecryptInput(value)
              if (isInputEmpty(value)) resetInspection()
              if (decryptOp.state.status === 'error') decryptOp.reset()
            }}
            placeholder={t('aes.placeholderDecrypt')}
            monospace
            badge={detectionBadge}
            action={
              <RunButton
                icon={LockKeyOpenIcon}
                label={t('aes.runDecrypt')}
                onClick={submitDecrypt}
                disabled={decryptOp.state.status === 'running'}
              />
            }
            onError={decryptOp.fail}
            onSubmit={submitDecrypt}
          />
          <ResultPanel
            state={decryptOp.state}
            view="decrypt"
            empty={{ icon: TextAlignLeftIcon, title: t('aes.emptyDecryptTitle'), body: t('aes.emptyDecryptBody') }}
            stageLabel={stageLabel}
            status={() => <Tag tone="good">{t('aes.doneDecrypt')}</Tag>}
            meta={(data) => `${formatSize(data.bytes.length, formatNumber)}, ${timing(data)}`}
          >
            {(data) => (
              <PlaintextOutput
                text={data.text}
                bytes={data.bytes}
                sourceName={inputFileName(decryptInput)}
                switchLabel={t('common.useAsInputEncrypt')}
                onSwitch={() => data.text !== null && sendToEncrypt(data.text)}
                details={<SummaryDetails summary={data.summary} />}
              />
            )}
          </ResultPanel>
        </ToolLayout>
      )}
    </PageContainer>
  )
}
