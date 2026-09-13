import { useCallback, useState, type ReactNode } from 'react'
import { PenNibIcon, SealCheckIcon, SealWarningIcon, SignatureIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { motion } from 'motion/react'
import { Callout } from '@/components/common/callout'
import { Tag } from '@/components/common/choice'
import { DataInput } from '@/components/common/data-input'
import { DetailsList } from '@/components/common/output'
import { PageContainer, PageHeader } from '@/components/common/page'
import { Segmented } from '@/components/common/segmented'
import { CiphertextOutput, ResultPanel } from '@/components/crypto/result'
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
import { pssMaxSaltLength } from '@/lib/crypto/rsa-params'
import type { SignResponse, VerifyRequest, VerifyResponse } from '@/lib/crypto/service'
import { InputProblem } from '@/lib/describe-error'
import { EMPTY_INPUT, encryptedFileName, inputFileName, isInputEmpty, type InputValue } from '@/lib/files'
import { formatDuration, formatSize } from '@/lib/format'
import { inputBytes, inputForDetection, textInput } from '@/lib/input-data'
import { useKeyring, type RingKey } from '@/stores/keyring'
import { updateSelection, useSelection } from '@/stores/selection'
import { useSettings } from '@/stores/settings'
import {
  DEFAULT_RAW_VERIFY,
  DEFAULT_SIGN_OPTIONS,
  defaultSaltLength,
  effectiveSignOptions,
  isSignOptions,
  SCHEME_LABEL,
  signatureExtensions,
  type RawVerifyParams,
  type SignOptions,
} from './options'
import { SignSettings, VerifySettings } from './sign-settings'

type Mode = 'sign' | 'verify'

interface VerifyResult extends VerifyResponse {
  ms: number
}

function VerifyOutcome({ data }: { data: VerifyResult }) {
  const { t, formatNumber } = useI18n()
  const { valid } = data
  const Icon = valid ? SealCheckIcon : SealWarningIcon
  const rows = [
    { label: t('sign.verifiedWith'), value: <KeyReference id={data.keyId} /> },
    { label: t('aes.sumAlgorithm'), value: `${SCHEME_LABEL[data.scheme]}, ${data.hash}` },
    ...(data.saltLength !== undefined ? [{ label: t('sign.saltLength'), value: formatNumber(data.saltLength) }] : []),
    { label: t('aes.sumContainer'), value: data.container === 'edt' ? t('aes.formatEdt') : t('aes.formatRaw') },
  ]

  return (
    <div>
      <div
        className={cn(
          'flex items-start gap-4 px-4 py-6 sm:px-5',
          valid ? 'bg-success/[0.06] dark:bg-success/10' : 'bg-destructive/[0.06] dark:bg-destructive/10',
        )}
      >
        <motion.span
          initial={{ scale: 0.6, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: 'spring', stiffness: 420, damping: 24 }}
          className={cn(
            'grid size-12 shrink-0 place-items-center rounded-2xl',
            valid ? 'bg-success/15 text-success' : 'bg-destructive/12 text-destructive',
          )}
        >
          <Icon weight="fill" className="size-7" />
        </motion.span>
        <div className="min-w-0 pt-0.5">
          <p className={cn('text-base font-semibold', valid ? 'text-success' : 'text-destructive')}>
            {valid ? t('sign.valid') : t('sign.invalid')}
          </p>
          <p className="mt-1 max-w-[60ch] text-sm leading-relaxed text-muted-foreground">
            {valid ? t('sign.validBody') : t('sign.invalidBody')}
          </p>
        </div>
      </div>
      {data.keyMismatch && (
        <div className="px-4 pt-4">
          <Callout tone="warn">{t('sign.keyMismatch')}</Callout>
        </div>
      )}
      <div className="border-t px-4 py-4">
        <DetailsList rows={rows} />
      </div>
    </div>
  )
}

export function SignPage() {
  const { t, formatNumber } = useI18n()
  const { level } = useSettings()
  const keys = useKeyring()
  const selection = useSelection()
  const [mode, setMode] = useState<Mode>('sign')
  const [savedOptions, setSavedOptions] = usePersistentState<SignOptions>(
    'edt.sign.options',
    DEFAULT_SIGN_OPTIONS,
    isSignOptions,
  )
  const options = effectiveSignOptions(savedOptions, level)
  const patchOptions = useCallback(
    (patch: Partial<SignOptions>) => setSavedOptions((current) => ({ ...current, ...patch })),
    [setSavedOptions],
  )

  const [signInput, setSignInput] = useState<InputValue>(EMPTY_INPUT)
  const [verifyInput, setVerifyInput] = useState<InputValue>(EMPTY_INPUT)
  const [signatureInput, setSignatureInput] = useState<InputValue>(EMPTY_INPUT)
  const [rawParams, setRawParams] = useState<RawVerifyParams>(DEFAULT_RAW_VERIFY)
  const [dialog, setDialog] = useState<'generate' | 'import' | null>(null)
  const [inspection, resetInspection] = useInspection(signatureInput)
  const signOp = useOperation<SignResponse, 'sign'>()
  const verifyOp = useOperation<VerifyResult, 'verify'>()

  // A radio list always shows a choice, so default to the first usable key instead of none.
  const privateKeys = keys.filter((key) => key.pkcs8)
  const signerId = privateKeys.some((key) => key.id === selection.signer)
    ? selection.signer
    : (privateKeys[0]?.id ?? null)
  const verifierId = keys.some((key) => key.id === selection.verifier)
    ? selection.verifier
    : keys.length === 1
      ? keys[0].id
      : null

  const submitSign = () => {
    if (signOp.state.status === 'running') return
    if (isInputEmpty(signInput)) return signOp.fail(new InputProblem('errors.emptyInput'))
    const signer = privateKeys.find((key) => key.id === signerId)
    if (!signer?.pkcs8) return signOp.fail(new InputProblem('errors.noSigner'))
    const pss = options.scheme === 'RSA-PSS'
    const maxSalt = pssMaxSaltLength(signer.bits, options.hash)
    const saltLength = options.saltLength ?? defaultSaltLength(signer.bits, options.hash)
    if (pss && saltLength > maxSalt) {
      return signOp.fail(new InputProblem('errors.saltTooLong', { max: formatNumber(Math.max(0, maxSalt)) }))
    }
    void signOp.run('sign', () =>
      callCrypto('sign', {
        data: inputBytes(signInput),
        key: { spki: signer.spki, pkcs8: signer.pkcs8 },
        scheme: options.scheme,
        hash: options.hash,
        saltLength: pss ? saltLength : undefined,
        format: options.format,
        encoding: options.encoding,
      }),
    )
  }

  const submitVerify = () => {
    if (verifyOp.state.status === 'running') return
    if (isInputEmpty(verifyInput)) return verifyOp.fail(new InputProblem('errors.emptyInput'))
    if (isInputEmpty(signatureInput)) return verifyOp.fail(new InputProblem('errors.emptySignature'))
    const signature = inputForDetection(signatureInput)
    const data = inputBytes(verifyInput)
    void verifyOp.run('verify', async () => {
      const start = performance.now()
      // Inspect here rather than trusting the debounced badge, which may lag behind a fresh paste.
      const detected = await callCrypto('inspectCiphertext', signature)
      let key: RingKey | undefined
      let raw: VerifyRequest['raw']
      if (detected.container === 'raw') {
        if (level === 'basic') throw new InputProblem('errors.rawNeedsAdvanced')
        key = keys.find((item) => item.id === verifierId)
        if (!key) throw new InputProblem('errors.noVerifier')
        raw = {
          scheme: rawParams.scheme,
          hash: rawParams.hash,
          saltLength: rawParams.scheme === 'RSA-PSS' ? (rawParams.saltLength ?? undefined) : undefined,
        }
      } else {
        const { summary } = detected
        if (summary.kind !== 'signature') throw new InputProblem('errors.notSignature')
        key = keys.find((item) => item.id === summary.keyId)
        if (!key) throw new InputProblem('sign.unknownSigner')
      }
      const response = await callCrypto('verify', { data, signature, keys: [{ spki: key.spki }], raw })
      return { ...response, ms: performance.now() - start }
    })
  }

  const sendToVerify = (result: SignResponse) => {
    const container = result.summary.container === 'edt' ? 'edt' : 'raw'
    const name = inputFileName(signInput)
    setVerifyInput(signInput)
    setSignatureInput(
      textInput(result.text, name && encryptedFileName(name, signatureExtensions(container, options.encoding).text)),
    )
    if (container === 'raw' && result.summary.scheme && result.summary.rsaHash) {
      setRawParams({
        scheme: result.summary.scheme,
        hash: result.summary.rsaHash,
        saltLength: result.summary.saltLength ?? null,
      })
      updateSelection({ verifier: signerId })
    }
    verifyOp.reset()
    setMode('verify')
  }

  let detectionBadge: ReactNode = null
  if (inspection.status === 'invalid') detectionBadge = <Tag tone="warn">{t('aes.detectInvalid')}</Tag>
  else if (inspection.status === 'ok') {
    const { result } = inspection
    detectionBadge = (
      <Tag>{result.container === 'edt' ? 'EDT' : result.container === 'openssl' ? 'OpenSSL' : result.encoding}</Tag>
    )
  }

  const running = (op: { state: { status: string } }) => op.state.status === 'running'

  return (
    <PageContainer>
      <PageHeader
        title={t('sign.title')}
        description={t('sign.description')}
        actions={
          <Segmented<Mode>
            size="lg"
            ariaLabel={t('sign.title')}
            value={mode}
            onValueChange={setMode}
            options={[
              { value: 'sign', label: t('sign.modeSign'), icon: PenNibIcon },
              { value: 'verify', label: t('sign.modeVerify'), icon: SealCheckIcon },
            ]}
          />
        }
      />

      {mode === 'sign' ? (
        <ToolLayout
          aside={
            <SignSettings
              level={level}
              options={options}
              onOptions={patchOptions}
              privateKeys={privateKeys}
              signerId={signerId}
              onSigner={(id) => updateSelection({ signer: id })}
              onGenerate={() => setDialog('generate')}
              onImport={() => setDialog('import')}
            />
          }
        >
          <DataInput
            label={t('sign.inputSign')}
            value={signInput}
            onChange={(value) => {
              setSignInput(value)
              if (signOp.state.status === 'error') signOp.reset()
            }}
            placeholder={t('sign.placeholderSign')}
            action={
              <RunButton icon={PenNibIcon} label={t('sign.runSign')} onClick={submitSign} disabled={running(signOp)} />
            }
            onError={signOp.fail}
            onSubmit={submitSign}
          />
          <ResultPanel
            state={signOp.state}
            view="sign"
            empty={{ icon: SignatureIcon, title: t('sign.emptySignTitle'), body: t('sign.emptySignBody') }}
            stageLabel={() => t('sign.stageSign')}
            status={() => <Tag tone="good">{t('sign.signed')}</Tag>}
            meta={(data) =>
              `${formatSize(data.bytes.length, formatNumber)}, ${formatDuration(data.ms, t, formatNumber)}`
            }
          >
            {(data) => {
              const container = data.summary.container === 'edt' ? 'edt' : 'raw'
              const extensions = signatureExtensions(container, options.encoding)
              return (
                <CiphertextOutput
                  text={data.text}
                  bytes={data.bytes}
                  sourceName={inputFileName(signInput)}
                  textExtension={extensions.text}
                  binaryExtension={extensions.binary}
                  preferBinary={container === 'raw'}
                  switchLabel={t('sign.sendToVerify')}
                  onSwitch={() => sendToVerify(data)}
                  details={<SummaryDetails summary={data.summary} />}
                />
              )
            }}
          </ResultPanel>
        </ToolLayout>
      ) : (
        <ToolLayout
          aside={
            <VerifySettings
              level={level}
              inspection={inspection}
              keys={keys}
              verifierId={verifierId}
              onVerifier={(id) => updateSelection({ verifier: id })}
              raw={rawParams}
              onRaw={(patch) => setRawParams((current) => ({ ...current, ...patch }))}
              onImport={() => setDialog('import')}
            />
          }
        >
          <DataInput
            label={t('sign.inputVerify')}
            value={verifyInput}
            onChange={(value) => {
              setVerifyInput(value)
              if (verifyOp.state.status !== 'running') verifyOp.reset()
            }}
            placeholder={t('sign.placeholderVerify')}
            onError={verifyOp.fail}
            onSubmit={submitVerify}
          />
          <DataInput
            label={t('sign.signature')}
            value={signatureInput}
            onChange={(value) => {
              setSignatureInput(value)
              if (isInputEmpty(value)) resetInspection()
              if (verifyOp.state.status !== 'running') verifyOp.reset()
            }}
            placeholder={t('sign.signaturePlaceholder')}
            monospace
            compact
            badge={detectionBadge}
            action={
              <RunButton
                icon={SealCheckIcon}
                label={t('sign.runVerify')}
                onClick={submitVerify}
                disabled={running(verifyOp)}
              />
            }
            onError={verifyOp.fail}
            onSubmit={submitVerify}
          />
          <ResultPanel
            state={verifyOp.state}
            view="verify"
            empty={{ icon: SealCheckIcon, title: t('sign.emptyVerifyTitle'), body: t('sign.emptyVerifyBody') }}
            stageLabel={() => t('sign.stageVerify')}
            status={(data) =>
              data.valid ? <Tag tone="good">{t('sign.valid')}</Tag> : <Tag tone="bad">{t('sign.invalid')}</Tag>
            }
            meta={(data) => formatDuration(data.ms, t, formatNumber)}
          >
            {(data) => <VerifyOutcome data={data} />}
          </ResultPanel>
        </ToolLayout>
      )}

      <GenerateKeyDialog
        open={dialog === 'generate'}
        onOpenChange={(open) => setDialog(open ? 'generate' : null)}
        onCreated={(key) => updateSelection({ signer: key.id })}
      />
      <ImportKeyDialog
        open={dialog === 'import'}
        onOpenChange={(open) => setDialog(open ? 'import' : null)}
        onImported={(result) => {
          const first = result.added[0] ?? result.upgraded[0]
          if (!first) return
          updateSelection(mode === 'sign' ? { signer: first.id } : { verifier: first.id })
        }}
      />
    </PageContainer>
  )
}
