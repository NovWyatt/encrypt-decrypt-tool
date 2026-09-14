import { Fragment, useMemo, useState, type ReactNode } from 'react'
import { sha256 } from '@noble/hashes/sha2.js'
import type { Icon } from '@phosphor-icons/react'
import {
  ArrowRightIcon,
  HammerIcon,
  KeyIcon,
  LockKeyIcon,
  SealCheckIcon,
  SealWarningIcon,
  ShuffleIcon,
} from '@phosphor-icons/react'
import { cn } from 'cn'
import { navigate } from '@/app/routes'
import { Callout } from '@/components/common/callout'
import { Tag } from '@/components/common/choice'
import { Panel } from '@/components/common/page'
import { SettingsSection } from '@/components/common/settings-section'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldError, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import { useFitsViewport } from '@/hooks/use-fits-viewport'
import { useI18n, type TFunction } from '@/i18n'
import { toHex, utf8Encode } from '@/lib/crypto/encoding'
import { formatDuration } from '@/lib/format'
import { useSettings } from '@/stores/settings'
import { Formula, LessonStep, LessonSteps, LessonTable, MathDetails, Muted, Var } from './lesson-parts'
import {
  bitLength,
  chooseExponent,
  extendedEuclid,
  factorSemiprime,
  gcd,
  isPrime,
  modInverse,
  modPow,
  modPowTrace,
  randomPrime,
  type EuclidRow,
} from './rsa-math'

const MAX_PRIME_BITS = 64
const MAX_FACTOR_BITS = 64
const MAX_TEXT_BYTES = 16

interface TextbookKey {
  p: bigint
  q: bigint
  n: bigint
  phi: bigint
  lambda: bigint
  e: bigint
  d: bigint
  euclid: EuclidRow[]
}

function buildKey(p: bigint, q: bigint, e: bigint): TextbookKey | null {
  const n = p * q
  const phi = (p - 1n) * (q - 1n)
  if (e <= 1n || e >= phi || gcd(e, phi) !== 1n) return null
  const { t: coefficient, rows } = extendedEuclid(phi, e)
  const d = ((coefficient % phi) + phi) % phi
  return { p, q, n, phi, lambda: phi / gcd(p - 1n, q - 1n), e, d, euclid: rows }
}

const CLASSIC_KEY = buildKey(61n, 53n, 17n)!

function parseWhole(text: string): bigint | null {
  return /^\d+$/.test(text) ? BigInt(text) : null
}

function checkPrime(text: string, t: TFunction): { value: bigint | null; error?: string } {
  const value = parseWhole(text)
  if (value === null) return { value, error: t('rsaLesson.invalidNumber') }
  if (value < 3n) return { value: null, error: t('rsaLesson.tooSmall') }
  if (bitLength(value) > MAX_PRIME_BITS) return { value: null, error: t('rsaLesson.tooBig') }
  if (!isPrime(value)) return { value: null, error: t('rsaLesson.notPrime', { value: text }) }
  return { value }
}

const hashNumber = (text: string) => BigInt(`0x${toHex(sha256(utf8Encode(text)))}`)

/** base^exponent written with a superscript, for worked examples. */
function Power({ base, exponent }: { base: ReactNode; exponent: ReactNode }) {
  return (
    <>
      {base}
      <sup className="text-[0.7em]">{exponent}</sup>
    </>
  )
}

function DigitsField({
  id,
  label,
  value,
  onChange,
  error,
  className,
  children,
}: {
  id: string
  label: ReactNode
  value: string
  onChange: (value: string) => void
  error?: string
  className?: string
  children?: ReactNode
}) {
  return (
    <Field className={cn('gap-1.5', className)}>
      <FieldLabel htmlFor={id} className="text-xs font-medium text-muted-foreground">
        {label}
      </FieldLabel>
      <div className="flex gap-2">
        <Input
          id={id}
          value={value}
          inputMode="numeric"
          autoComplete="off"
          spellCheck={false}
          aria-invalid={error ? true : undefined}
          onChange={(event) => onChange(event.target.value.replace(/\D/g, '').slice(0, 40))}
          className="font-mono text-[0.8125rem] tabular-nums"
        />
        {children}
      </div>
      {error && <FieldError className="text-xs">{error}</FieldError>}
    </Field>
  )
}

function KeyBox({ icon: IconComponent, title, rows }: { icon: Icon; title: string; rows: Array<[string, bigint]> }) {
  return (
    <div className="flex min-w-0 flex-col gap-2 rounded-lg border p-3">
      <span className="flex items-center gap-1.5 text-xs font-medium">
        <IconComponent weight="bold" className="size-3.5 text-muted-foreground" />
        {title}
      </span>
      <dl className="grid grid-cols-[1rem_minmax(0,1fr)] gap-x-2 gap-y-1 font-mono text-[0.8125rem]">
        {rows.map(([name, value]) => (
          <Fragment key={name}>
            <dt className="font-sans text-muted-foreground italic">{name}</dt>
            <dd className="[overflow-wrap:anywhere] tabular-nums">{value.toString()}</dd>
          </Fragment>
        ))}
      </dl>
    </div>
  )
}

function Verdict({ valid, children }: { valid: boolean; children: ReactNode }) {
  const IconComponent = valid ? SealCheckIcon : SealWarningIcon
  return (
    <div
      role="status"
      className={cn(
        'flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-[0.8125rem] font-medium',
        valid ? 'bg-success/10 text-success' : 'bg-destructive/[0.08] text-destructive',
      )}
    >
      <IconComponent weight="fill" className="size-5 shrink-0" />
      <span className="text-foreground">{children}</span>
    </div>
  )
}

function EuclidTable({ rows }: { rows: EuclidRow[] }) {
  const { t } = useI18n()
  return (
    <div className="flex flex-col gap-2">
      <LessonTable
        className="max-h-72"
        caption={t('rsaLesson.euclidTable')}
        head={[t('rsaLesson.quotient'), t('rsaLesson.remainder'), t('rsaLesson.coefficient')]}
      >
        {rows.map((row, index) => (
          <tr key={index} className={cn(row.remainder === 1n && 'bg-primary/[0.07] dark:bg-primary/15')}>
            <td className="px-3 py-1.5 font-mono text-xs text-muted-foreground tabular-nums">
              {row.quotient?.toString() ?? '–'}
            </td>
            <td className="px-3 py-1.5 font-mono text-xs tabular-nums">{row.remainder.toString()}</td>
            <td className="px-3 py-1.5 font-mono text-xs tabular-nums">{row.t.toString()}</td>
          </tr>
        ))}
      </LessonTable>
      <p className="text-xs text-muted-foreground">{t('rsaLesson.euclidHint')}</p>
    </div>
  )
}

function EncryptStep({ number, rsaKey, advanced }: { number: number; rsaKey: TextbookKey; advanced: boolean }) {
  const { t } = useI18n()
  const [messageText, setMessageText] = useState('65')
  const { n, e, d } = rsaKey
  const m = parseWhole(messageText)
  const valid = m !== null && m < n
  const c = valid ? modPow(m, e, n) : null
  // At most 128 squarings for the demo sizes, so there is nothing worth memoising.
  const trace = valid ? modPowTrace(m, e, n).steps : []

  return (
    <LessonStep number={number} title={t('rsaLesson.step5')} description={t('rsaLesson.step5Body')}>
      <DigitsField
        id="rsa-lesson-message"
        label={t('rsaLesson.message')}
        value={messageText}
        onChange={setMessageText}
        error={valid ? undefined : t('rsaLesson.messageTooBig', { max: (n - 1n).toString() })}
        className="max-w-72"
      />
      {valid && c !== null && (
        <>
          <Formula>
            <span className="block">
              <Muted>{t('rsaLesson.encryptLine')}: </Muted>
              <Var>c</Var> = <Power base={<Var>m</Var>} exponent={<Var>e</Var>} /> mod <Var>n</Var> ={' '}
              <Power base={m.toString()} exponent={e.toString()} /> mod {n.toString()} ={' '}
              <strong className="font-semibold">{c.toString()}</strong>
            </span>
            <span className="block">
              <Muted>{t('rsaLesson.decryptLine')}: </Muted>
              <Var>m</Var> = <Power base={<Var>c</Var>} exponent={<Var>d</Var>} /> mod <Var>n</Var> ={' '}
              <Power base={c.toString()} exponent={d.toString()} /> mod {n.toString()} ={' '}
              <strong className="font-semibold">{modPow(c, d, n).toString()}</strong>
            </span>
          </Formula>
          <MathDetails defaultOpen={advanced} label={t('rsaLesson.powTrace')}>
            <LessonTable
              className="max-h-72"
              caption={t('rsaLesson.powTrace')}
              head={[t('rsaLesson.bit'), t('rsaLesson.operation'), t('rsaLesson.result')]}
            >
              {trace.map((step, index) => (
                <tr key={index}>
                  <td className="px-3 py-1.5 font-mono text-xs tabular-nums">{step.bit}</td>
                  <td className="px-3 py-1.5 text-xs text-muted-foreground">
                    {step.bit ? t('rsaLesson.squareMultiply', { base: m.toString() }) : t('rsaLesson.square')}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs tabular-nums">{step.result.toString()}</td>
                </tr>
              ))}
            </LessonTable>
          </MathDetails>
        </>
      )}
    </LessonStep>
  )
}

function CharacterStep({ number, rsaKey }: { number: number; rsaKey: TextbookKey }) {
  const { t } = useI18n()
  const [edited, setEdited] = useState<string | null>(null)
  const text = edited ?? t('rsaLesson.textDefault')
  const { n, e } = rsaKey
  const bytes = Array.from(utf8Encode(text))
  const seen = new Set<bigint>()
  const rows = bytes.map((byte) => {
    const c = modPow(BigInt(byte), e, n)
    const repeated = seen.has(c)
    seen.add(c)
    return { byte, c, repeated }
  })

  return (
    <LessonStep number={number} title={t('rsaLesson.textTitle')} description={t('rsaLesson.textBody')}>
      <Field className="max-w-72 gap-1.5">
        <FieldLabel htmlFor="rsa-lesson-text" className="text-xs font-medium text-muted-foreground">
          {t('rsaLesson.textLabel')}
        </FieldLabel>
        <Input
          id="rsa-lesson-text"
          value={text}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => {
            let next = event.target.value
            while (utf8Encode(next).length > MAX_TEXT_BYTES) next = next.slice(0, -1)
            setEdited(next)
          }}
          className="font-mono text-[0.8125rem]"
        />
      </Field>
      {n <= 255n ? (
        <Callout tone="warn">{t('rsaLesson.textNeedsN')}</Callout>
      ) : (
        rows.length > 0 && (
          <LessonTable
            className="max-h-80"
            caption={t('rsaLesson.textTitle')}
            head={[t('rsaLesson.char'), <Var key="m">m</Var>, <Var key="c">c</Var>]}
          >
            {rows.map(({ byte, c, repeated }, index) => (
              <tr key={index} className={cn(repeated && 'bg-destructive/[0.06] dark:bg-destructive/10')}>
                <td className="px-3 py-1.5 font-mono text-xs">
                  {byte >= 0x21 && byte <= 0x7e ? String.fromCharCode(byte) : `0x${byte.toString(16).padStart(2, '0')}`}
                </td>
                <td className="px-3 py-1.5 font-mono text-xs tabular-nums">{byte}</td>
                <td className="px-3 py-1.5">
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="font-mono text-xs [overflow-wrap:anywhere] tabular-nums">{c.toString()}</span>
                    {repeated && <Tag tone="bad">{t('rsaLesson.repeated')}</Tag>}
                  </span>
                </td>
              </tr>
            ))}
          </LessonTable>
        )
      )}
      <Callout tone="info">{t('rsaLesson.oaepNote')}</Callout>
    </LessonStep>
  )
}

function SignatureStep({ number, rsaKey, advanced }: { number: number; rsaKey: TextbookKey; advanced: boolean }) {
  const { t } = useI18n()
  const [signedEdit, setSignedEdit] = useState<string | null>(null)
  const [receivedEdit, setReceivedEdit] = useState<string | null>(null)
  const signed = signedEdit ?? t('rsaLesson.signedDefault')
  const received = receivedEdit ?? signed
  const { n, e, d } = rsaKey

  const h = hashNumber(signed) % n
  const s = modPow(h, d, n)
  const recovered = modPow(s, e, n)
  const receivedHash = hashNumber(received) % n
  const valid = recovered === receivedHash

  return (
    <LessonStep number={number} title={t('rsaLesson.step6')} description={t('rsaLesson.step6Body')}>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="flex min-w-0 flex-col gap-3">
          <Field className="gap-1.5">
            <FieldLabel htmlFor="rsa-lesson-signed" className="text-xs font-medium text-muted-foreground">
              {t('rsaLesson.signedText')}
            </FieldLabel>
            <Input
              id="rsa-lesson-signed"
              value={signed}
              autoComplete="off"
              onChange={(event) => setSignedEdit(event.target.value)}
            />
          </Field>
          <Formula>
            <span className="block">
              <Var>h</Var> = {h.toString()} <Muted>({t('rsaLesson.hashLine')})</Muted>
            </span>
            <span className="block">
              <Var>s</Var> = <Power base={<Var>h</Var>} exponent={<Var>d</Var>} /> mod <Var>n</Var> ={' '}
              <strong className="font-semibold">{s.toString()}</strong>
            </span>
          </Formula>
        </div>
        <div className="flex min-w-0 flex-col gap-3">
          <Field className="gap-1.5">
            <FieldLabel htmlFor="rsa-lesson-received" className="text-xs font-medium text-muted-foreground">
              {t('rsaLesson.receivedText')}
            </FieldLabel>
            <Input
              id="rsa-lesson-received"
              value={received}
              autoComplete="off"
              aria-describedby="rsa-lesson-received-hint"
              onChange={(event) => setReceivedEdit(event.target.value)}
            />
            <FieldDescription id="rsa-lesson-received-hint" className="text-xs">
              {t('rsaLesson.receivedHint')}
            </FieldDescription>
          </Field>
          <Formula>
            <span className="block">
              <Power base={<Var>s</Var>} exponent={<Var>e</Var>} /> mod <Var>n</Var> ={' '}
              <strong className="font-semibold">{recovered.toString()}</strong>
            </span>
            <span className="block">
              <Var>h′</Var> = {receivedHash.toString()} <Muted>({t('rsaLesson.hashLine')})</Muted>
            </span>
          </Formula>
        </div>
      </div>
      <Verdict valid={valid}>{valid ? t('rsaLesson.verifyValid') : t('rsaLesson.verifyInvalid')}</Verdict>
      {advanced && <p className="text-xs leading-relaxed text-muted-foreground">{t('rsaLesson.collisionNote')}</p>}
    </LessonStep>
  )
}

function FactorStep({ number, rsaKey }: { number: number; rsaKey: TextbookKey }) {
  const { t, formatNumber } = useI18n()
  const [attack, setAttack] = useState<{
    n: bigint
    found: ReturnType<typeof factorSemiprime>
    ms: number
  } | null>(null)
  const [running, setRunning] = useState(false)
  const { n, e } = rsaKey
  const allowed = bitLength(n) <= MAX_FACTOR_BITS
  const result = attack?.n === n ? attack : null

  const run = () => {
    setRunning(true)
    // Let the busy state paint before the (short) synchronous search starts.
    setTimeout(() => {
      const started = performance.now()
      const found = factorSemiprime(n)
      setAttack({ n, found, ms: performance.now() - started })
      setRunning(false)
    }, 30)
  }

  const found = result?.found ?? null
  const recoveredD = found ? modInverse(e, (found.p - 1n) * (found.q - 1n)) : null

  return (
    <LessonStep number={number} title={t('rsaLesson.step7')} description={t('rsaLesson.step7Body')}>
      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={run} disabled={!allowed || running}>
          {running ? <Spinner /> : <HammerIcon weight="bold" />}
          {running ? t('rsaLesson.factoring') : t('rsaLesson.factor')}
        </Button>
        {!allowed && <span className="text-xs text-muted-foreground">{t('rsaLesson.factorTooBig')}</span>}
      </div>
      {result && found && recoveredD !== null && (
        <Callout tone="bad" title={t('rsaLesson.recoveredKey', { d: recoveredD.toString() })}>
          {t('rsaLesson.factorFound', {
            p: found.p.toString(),
            q: found.q.toString(),
            steps: formatNumber(found.steps),
            time: formatDuration(result.ms, t, formatNumber),
          })}
        </Callout>
      )}
      <p className="max-w-[72ch] text-xs leading-relaxed text-pretty text-muted-foreground">
        {t('rsaLesson.scaleNote')}
      </p>
    </LessonStep>
  )
}

export function RsaLesson() {
  const { t } = useI18n()
  const { level } = useSettings()
  const advanced = level === 'advanced'
  const [asideRef, asideFits] = useFitsViewport<HTMLDivElement>()

  const [pText, setPText] = useState('61')
  const [qText, setQText] = useState('53')
  // null picks e automatically; the classic example pins the textbook value 17.
  const [eText, setEText] = useState<string | null>('17')

  const pCheck = checkPrime(pText, t)
  const qCheck = checkPrime(qText, t)
  const same = pCheck.value !== null && pCheck.value === qCheck.value
  const primesId = pCheck.value !== null && qCheck.value !== null && !same ? `${pCheck.value}:${qCheck.value}` : null
  const autoE = useMemo(() => {
    if (!primesId) return null
    const [p, q] = primesId.split(':').map(BigInt)
    return chooseExponent((p - 1n) * (q - 1n))
  }, [primesId])
  const eValue = eText === null ? autoE : parseWhole(eText)

  const fresh = useMemo(() => {
    if (!primesId || eValue === null) return null
    const [p, q] = primesId.split(':').map(BigInt)
    return buildKey(p, q, eValue)
  }, [primesId, eValue])
  const eError = primesId !== null && !fresh
  // Keep the last complete key on screen (dimmed) while an input is being edited.
  const [rsaKey, setRsaKey] = useState<TextbookKey>(CLASSIC_KEY)
  if (fresh && fresh !== rsaKey) setRsaKey(fresh)
  const stale = !fresh

  const editPrime = (setter: (value: string) => void) => (value: string) => {
    setter(value)
    // At the basic level e cannot be edited, so a new pair always gets an automatic e.
    if (!advanced) setEText(null)
  }
  const randomize = (bits: number) => {
    const p = randomPrime(bits)
    let q = randomPrime(bits)
    while (q === p) q = randomPrime(bits)
    setPText(p.toString())
    setQText(q.toString())
    setEText(null)
  }

  const { p, q, n, phi, lambda, e, d } = rsaKey

  const aside = (
    <Panel as="aside" className="overflow-hidden">
      <SettingsSection title={t('rsaLesson.setupTitle')}>
        <div className="grid grid-cols-2 gap-3">
          <DigitsField
            id="rsa-lesson-p"
            label={<Var>p</Var>}
            value={pText}
            onChange={editPrime(setPText)}
            error={pCheck.error}
          />
          <DigitsField
            id="rsa-lesson-q"
            label={<Var>q</Var>}
            value={qText}
            onChange={editPrime(setQText)}
            error={qCheck.error ?? (same ? t('rsaLesson.samePrimes') : undefined)}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <div className="flex flex-wrap gap-1.5">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setPText('61')
                setQText('53')
                setEText('17')
              }}
            >
              {t('rsaLesson.presetClassic')}
            </Button>
          </div>
          <span className="mt-1 text-xs text-muted-foreground">{t('rsaLesson.randomLabel')}</span>
          <div className="flex flex-wrap gap-1.5">
            {[8, 16, 32].map((bits) => (
              <Button key={bits} variant="outline" size="sm" onClick={() => randomize(bits)}>
                <ShuffleIcon />
                {t('rsaLesson.presetRandom', { bits })}
              </Button>
            ))}
          </div>
        </div>
        {advanced && (
          <DigitsField
            id="rsa-lesson-e"
            label={t('rsaLesson.e')}
            value={eText ?? autoE?.toString() ?? ''}
            onChange={setEText}
            error={eError ? t('rsaLesson.eInvalid') : undefined}
          >
            <Button variant="outline" onClick={() => setEText(null)} disabled={eText === null} className="h-8">
              {t('rsaLesson.eAuto')}
            </Button>
          </DigitsField>
        )}
      </SettingsSection>
      <SettingsSection title={t('rsaLesson.keysTitle')} className={cn('transition-opacity', stale && 'opacity-50')}>
        <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-1">
          <KeyBox
            icon={LockKeyIcon}
            title={t('rsaLesson.publicKey')}
            rows={[
              ['n', n],
              ['e', e],
            ]}
          />
          <KeyBox
            icon={KeyIcon}
            title={t('rsaLesson.privateKey')}
            rows={[
              ['n', n],
              ['d', d],
            ]}
          />
        </div>
      </SettingsSection>
      <div className="border-t p-4">
        <Callout
          tone="warn"
          action={
            <Button variant="outline" size="sm" onClick={() => navigate('keys')}>
              {t('rsaLesson.openKeys')}
              <ArrowRightIcon data-icon="inline-end" />
            </Button>
          }
        >
          {t('rsaLesson.textbookWarning')}
        </Callout>
      </div>
    </Panel>
  )

  return (
    <div className="grid items-start gap-5 xl:grid-cols-[340px_minmax(0,1fr)]">
      <div ref={asideRef} className={cn(asideFits && 'xl:sticky xl:top-6')}>
        {aside}
      </div>
      <Panel className={cn('p-4 transition-opacity sm:p-6', stale && 'opacity-60')}>
        <LessonSteps>
          <LessonStep
            number={1}
            title={t('rsaLesson.step1')}
            description={t('rsaLesson.step1Body')}
            aside={<Tag>{t('rsaLesson.nBits', { bits: bitLength(n) })}</Tag>}
          >
            <Formula>
              <Var>n</Var> = <Var>p</Var> · <Var>q</Var> = {p.toString()} · {q.toString()} ={' '}
              <strong className="font-semibold">{n.toString()}</strong>
            </Formula>
          </LessonStep>

          <LessonStep number={2} title={t('rsaLesson.step2')} description={t('rsaLesson.step2Body')}>
            <Formula>
              φ(<Var>n</Var>) = (<Var>p</Var> − 1)(<Var>q</Var> − 1) = {(p - 1n).toString()} · {(q - 1n).toString()} ={' '}
              <strong className="font-semibold">{phi.toString()}</strong>
            </Formula>
            {advanced && (
              <p className="text-xs leading-relaxed text-muted-foreground">
                {t('rsaLesson.lambdaNote', { lambda: lambda.toString() })}
              </p>
            )}
          </LessonStep>

          <LessonStep number={3} title={t('rsaLesson.step3')} description={t('rsaLesson.step3Body')}>
            <Formula>
              <span className="block">
                <Var>e</Var> = <strong className="font-semibold">{e.toString()}</strong>
              </span>
              <span className="block">
                gcd(<Var>e</Var>, φ(<Var>n</Var>)) = gcd({e.toString()}, {phi.toString()}) = 1
              </span>
            </Formula>
          </LessonStep>

          <LessonStep number={4} title={t('rsaLesson.step4')} description={t('rsaLesson.step4Body')}>
            <Formula>
              <span className="block">
                <Var>d</Var> = <Power base={<Var>e</Var>} exponent="−1" /> mod φ(<Var>n</Var>) ={' '}
                <strong className="font-semibold">{d.toString()}</strong>
              </span>
              <span className="block">
                <Var>e</Var> · <Var>d</Var> mod φ(<Var>n</Var>) = {e.toString()} · {d.toString()} mod {phi.toString()} =
                1
              </span>
            </Formula>
            <MathDetails defaultOpen={advanced} label={t('rsaLesson.euclidTable')}>
              <EuclidTable rows={rsaKey.euclid} />
            </MathDetails>
          </LessonStep>

          <EncryptStep number={5} rsaKey={rsaKey} advanced={advanced} />
          <CharacterStep number={6} rsaKey={rsaKey} />
          <SignatureStep number={7} rsaKey={rsaKey} advanced={advanced} />
          <FactorStep number={8} rsaKey={rsaKey} />
        </LessonSteps>
      </Panel>
    </div>
  )
}
