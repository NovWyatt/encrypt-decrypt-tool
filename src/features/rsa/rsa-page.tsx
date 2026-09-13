import { useCallback, useState, type ReactNode } from 'react'
import { KeyIcon, LockKeyIcon, LockKeyOpenIcon, TextAlignLeftIcon } from '@phosphor-icons/react'
import { Tag } from '@/components/common/choice'
import { DataInput } from '@/components/common/data-input'
import { PageContainer, PageHeader } from '@/components/common/page'
import { Segmented } from '@/components/common/segmented'
import { CiphertextOutput, PlaintextOutput, ResultPanel } from '@/components/crypto/result'
import { RunButton } from '@/components/crypto/run-button'
import { KeyReference, SummaryDetails } from '@/components/crypto/summary-details'
import { ToolLayout } from '@/components/crypto/tool-layout'
import { GenerateKeyDialog } from '@/features/keys/generate-key-dialog'
import { ImportKeyDialog } from '@/features/keys/import-key-dialog'
import { useInspection } from '@/hooks/use-inspection'
import { useOperation } from '@/hooks/use-operation'
import { usePersistentState } from '@/hooks/use-persistent-state'
import { useI18n } from '@/i18n'
import { callCrypto } from '@/lib/crypto/client'
import { oaepMaxMessageBytes, type RsaHash } from '@/lib/crypto/rsa-params'
import type { DecryptResponse, EncryptResponse } from '@/lib/crypto/service'
import { InputProblem } from '@/lib/describe-error'
import { EMPTY_INPUT, encryptedFileName, inputFileName, isInputEmpty, type InputValue } from '@/lib/files'
import { formatDuration, formatSize } from '@/lib/format'
import { inputBytes, inputForDetection, textInput } from '@/lib/input-data'
import { useKeyring } from '@/stores/keyring'
import { updateSelection, useSelection } from '@/stores/selection'
import { useSettings } from '@/stores/settings'
import { DEFAULT_RSA_OPTIONS, effectiveRsaOptions, fitsOaep, isRsaOptions, type RsaOptions } from './options'
import { RsaDecryptSettings, RsaEncryptSettings } from './rsa-settings'

type Direction = 'encrypt' | 'decrypt'
type Stage = 'encrypt' | 'decrypt'

export function RsaPage() {
  const { t, formatNumber } = useI18n()
  const { level } = useSettings()
  const keys = useKeyring()
  const selection = useSelection()
  const [direction, setDirection] = useState<Direction>('encrypt')
  const [savedOptions, setSavedOptions] = usePersistentState<RsaOptions>(
    'edt.rsa.options',
    DEFAULT_RSA_OPTIONS,
    isRsaOptions,
  )
  const options = effectiveRsaOptions(savedOptions, level)
  const patchOptions = useCallback(
    (patch: Partial<RsaOptions>) => setSavedOptions((current) => ({ ...current, ...patch })),
    [setSavedOptions],
  )

  const [encryptInput, setEncryptInput] = useState<InputValue>(EMPTY_INPUT)
  const [decryptInput, setDecryptInput] = useState<InputValue>(EMPTY_INPUT)
  const [rawHash, setRawHash] = useState<RsaHash>('SHA-256')
  const [dialog, setDialog] = useState<'generate' | 'import' | null>(null)
  const [inspection, resetInspection] = useInspection(decryptInput)
  const encryptOp = useOperation<EncryptResponse, Stage>()
  const decryptOp = useOperation<DecryptResponse, Stage>()

  // Selections can outlive keys deleted in the keyring.
  const recipients = selection.recipients.filter((id) => keys.some((key) => key.id === id))
  const privateKeys = keys.filter((key) => key.pkcs8)
  const rawKeyId = privateKeys.some((key) => key.id === selection.rawDecryptKey)
    ? selection.rawDecryptKey
    : privateKeys.length === 1
      ? privateKeys[0].id
      : null

  const submitEncrypt = () => {
    if (encryptOp.state.status === 'running') return
    if (isInputEmpty(encryptInput)) return encryptOp.fail(new InputProblem('errors.emptyInput'))
    const chosen = (options.scheme === 'direct' ? recipients.slice(0, 1) : recipients).map((id) =>
      keys.find((key) => key.id === id)!,
    )
    if (chosen.length === 0) return encryptOp.fail(new InputProblem('errors.noRecipients'))
    const tooSmall = chosen.find((key) => !fitsOaep(key.bits, options.hash, options.scheme))
    if (tooSmall) {
      return encryptOp.fail(
        new InputProblem('rsa.keyTooSmall', { name: tooSmall.name, bits: tooSmall.bits, hash: options.hash }),
      )
    }
    const data = inputBytes(encryptInput)
    const max = oaepMaxMessageBytes(chosen[0].bits, options.hash)
    if (options.scheme === 'direct' && data.length > max) {
      return encryptOp.fail(
        new InputProblem('rsa.tooLong', { size: formatNumber(data.length), max: formatNumber(max) }),
      )
    }
    void encryptOp.run('encrypt', () =>
      callCrypto('encryptRsa', {
        data,
        recipients: chosen.map((key) => ({ spki: key.spki, hash: options.hash })),
        scheme: options.scheme,
        format: options.format,
        encoding: options.encoding,
      }),
    )
  }

  const submitDecrypt = () => {
    if (decryptOp.state.status === 'running') return
    if (isInputEmpty(decryptInput)) return decryptOp.fail(new InputProblem('errors.emptyInput'))
    const result = inspection.status === 'ok' ? inspection.result : null
    if (
      result?.container === 'openssl' ||
      (result?.container === 'edt' && !['rsa', 'rsa-hybrid'].includes(result.summary.kind))
    ) {
      return decryptOp.fail(new InputProblem('errors.notRsaMessage'))
    }
    const raw = result?.container === 'raw'
    if (raw && level === 'basic') return decryptOp.fail(new InputProblem('errors.rawNeedsAdvanced'))
    const candidates = raw ? privateKeys.filter((key) => key.id === rawKeyId) : privateKeys
    if (candidates.length === 0) return decryptOp.fail(new InputProblem('errors.PRIVATE_KEY_REQUIRED'))
    void decryptOp.run('decrypt', () =>
      callCrypto('decryptRsa', {
        input: inputForDetection(decryptInput),
        keys: candidates.map((key) => ({ spki: key.spki, pkcs8: key.pkcs8 })),
        rawHash: raw ? rawHash : undefined,
      }),
    )
  }

  const sendToDecrypt = (result: EncryptResponse) => {
    const name = inputFileName(encryptInput)
    const extension = result.summary.container === 'edt' ? '.edt' : options.encoding === 'hex' ? '.hex' : '.b64'
    setDecryptInput(textInput(result.text, name && encryptedFileName(name, extension)))
    if (result.summary.container === 'raw') {
      updateSelection({ rawDecryptKey: recipients[0] ?? null })
      setRawHash(options.hash)
    }
    decryptOp.reset()
    setDirection('decrypt')
  }

  const sendToEncrypt = (text: string) => {
    setEncryptInput({ kind: 'text', text })
    encryptOp.reset()
    setDirection('encrypt')
  }

  let detectionBadge: ReactNode = null
  if (inspection.status === 'invalid') detectionBadge = <Tag tone="warn">{t('aes.detectInvalid')}</Tag>
  else if (inspection.status === 'ok') {
    const { result } = inspection
    detectionBadge = (
      <Tag>{result.container === 'edt' ? 'EDT' : result.container === 'openssl' ? 'OpenSSL' : result.encoding}</Tag>
    )
  }

  const stageLabel = (stage: Stage) => (stage === 'encrypt' ? t('aes.stageEncrypt') : t('aes.stageDecrypt'))
  const timing = (data: { cipherMs: number }) => formatDuration(data.cipherMs, t, formatNumber)

  return (
    <PageContainer>
      <PageHeader
        title={t('rsa.title')}
        description={t('rsa.description')}
        actions={
          <Segmented<Direction>
            size="lg"
            ariaLabel={t('rsa.title')}
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
            <RsaEncryptSettings
              level={level}
              options={options}
              onOptions={patchOptions}
              keys={keys}
              recipients={recipients}
              onRecipients={(ids) => {
                updateSelection({ recipients: ids })
                if (encryptOp.state.status === 'error') encryptOp.reset()
              }}
              onGenerate={() => setDialog('generate')}
              onImport={() => setDialog('import')}
            />
          }
        >
          <DataInput
            label={t('rsa.inputEncrypt')}
            value={encryptInput}
            onChange={(value) => {
              setEncryptInput(value)
              if (encryptOp.state.status === 'error') encryptOp.reset()
            }}
            placeholder={t('rsa.placeholderEncrypt')}
            action={
              <RunButton
                icon={LockKeyIcon}
                label={t('rsa.runEncrypt')}
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
            empty={{ icon: KeyIcon, title: t('rsa.emptyEncryptTitle'), body: t('rsa.emptyEncryptBody') }}
            stageLabel={stageLabel}
            status={() => <Tag tone="good">{t('aes.doneEncrypt')}</Tag>}
            meta={(data) =>
              `${formatSize(data.inputBytes, formatNumber)} → ${formatSize(data.bytes.length, formatNumber)}, ${timing(data)}`
            }
          >
            {(data) => (
              <CiphertextOutput
                text={data.text}
                bytes={data.bytes}
                sourceName={inputFileName(encryptInput)}
                textExtension={data.summary.container === 'edt' ? '.edt' : options.encoding === 'hex' ? '.hex' : '.b64'}
                binaryExtension={data.summary.container === 'edt' ? '.edt.bin' : '.bin'}
                preferBinary={data.summary.container === 'raw'}
                switchLabel={t('common.useAsInput')}
                onSwitch={() => sendToDecrypt(data)}
                details={<SummaryDetails summary={data.summary} />}
              />
            )}
          </ResultPanel>
        </ToolLayout>
      ) : (
        <ToolLayout
          aside={
            <RsaDecryptSettings
              level={level}
              inspection={inspection}
              keys={keys}
              rawKeyId={rawKeyId}
              onRawKey={(id) => updateSelection({ rawDecryptKey: id })}
              rawHash={rawHash}
              onRawHash={setRawHash}
              onImport={() => setDialog('import')}
            />
          }
        >
          <DataInput
            label={t('rsa.inputDecrypt')}
            value={decryptInput}
            onChange={(value) => {
              setDecryptInput(value)
              if (isInputEmpty(value)) resetInspection()
              if (decryptOp.state.status === 'error') decryptOp.reset()
            }}
            placeholder={t('rsa.placeholderDecrypt')}
            monospace
            badge={detectionBadge}
            action={
              <RunButton
                icon={LockKeyOpenIcon}
                label={t('rsa.runDecrypt')}
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
            empty={{ icon: TextAlignLeftIcon, title: t('rsa.emptyDecryptTitle'), body: t('rsa.emptyDecryptBody') }}
            stageLabel={stageLabel}
            status={() => <Tag tone="good">{t('aes.doneDecrypt')}</Tag>}
            meta={(data) => `${formatSize(data.bytes.length, formatNumber)}, ${timing(data)}`}
          >
            {(data) => (
              <PlaintextOutput
                text={data.text}
                bytes={data.bytes}
                sourceName={inputFileName(decryptInput)}
                banner={
                  data.keyId && (
                    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 border-b bg-muted/30 px-4 py-2 text-xs text-muted-foreground">
                      {t('rsa.decryptedWith')}
                      <KeyReference id={data.keyId} />
                    </div>
                  )
                }
                switchLabel={t('common.useAsInputEncrypt')}
                onSwitch={() => data.text !== null && sendToEncrypt(data.text)}
                details={<SummaryDetails summary={data.summary} />}
              />
            )}
          </ResultPanel>
        </ToolLayout>
      )}

      <GenerateKeyDialog
        open={dialog === 'generate'}
        onOpenChange={(open) => setDialog(open ? 'generate' : null)}
        onCreated={(key) => updateSelection({ recipients: [...recipients, key.id] })}
      />
      <ImportKeyDialog
        open={dialog === 'import'}
        onOpenChange={(open) => setDialog(open ? 'import' : null)}
        onImported={(result) => {
          if (direction === 'encrypt' && result.added.length) {
            updateSelection({ recipients: [...recipients, ...result.added.map((key) => key.id)] })
          }
        }}
      />
    </PageContainer>
  )
}
