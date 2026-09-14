import { useEffect, useState } from 'react'
import {
  CaretRightIcon,
  DotsThreeIcon,
  DownloadSimpleIcon,
  KeyIcon,
  LockKeyIcon,
  PencilSimpleIcon,
  SignatureIcon,
  TrashIcon,
  VaultIcon,
} from '@phosphor-icons/react'
import { cn } from 'cn'
import { navigate } from '@/app/routes'
import { Callout } from '@/components/common/callout'
import { Tag } from '@/components/common/choice'
import { CopyButton } from '@/components/common/copy-button'
import { DetailsList } from '@/components/common/output'
import { PageContainer, PageHeader, Panel } from '@/components/common/page'
import { ScrollRegion } from '@/components/common/scroll-region'
import { KeyIdenticon } from '@/components/crypto/key-identicon'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Input } from '@/components/ui/input'
import { useI18n } from '@/i18n'
import { callCrypto } from '@/lib/crypto/client'
import type { RsaKeyDetails } from '@/lib/crypto/rsa-keys'
import { groupHex } from '@/lib/format'
import { forgetPrivateKey, removeKey, renameKey, useKeyring, type RingKey } from '@/stores/keyring'
import { updateSelection } from '@/stores/selection'
import { useSettings } from '@/stores/settings'
import { GenerateKeyDialog } from './generate-key-dialog'
import { ImportKeyDialog } from './import-key-dialog'
import { KeyExport } from './key-export'

export function KeysPage() {
  const { t, formatNumber } = useI18n()
  const keys = useKeyring()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [dialog, setDialog] = useState<'generate' | 'import' | null>(null)
  const selected = keys.find((key) => key.id === selectedId) ?? keys[0] ?? null
  const unsaved = keys.filter((key) => key.pkcs8 && !key.privateSaved).length

  return (
    <PageContainer>
      <PageHeader
        title={t('keys.title')}
        description={t('keys.description')}
        actions={
          <>
            <Button variant="outline" size="lg" onClick={() => setDialog('import')}>
              <DownloadSimpleIcon />
              {t('keys.import')}
            </Button>
            <Button size="lg" onClick={() => setDialog('generate')}>
              <KeyIcon weight="bold" />
              {t('keys.generate')}
            </Button>
          </>
        }
      />

      {unsaved > 0 && (
        <Callout tone="warn" className="mb-5 text-[0.8125rem]">
          {t('keys.memoryNotice', { count: formatNumber(unsaved) })}
        </Callout>
      )}

      {keys.length === 0 ? (
        <Panel>
          <Empty className="min-h-[360px] gap-4 py-12">
            <EmptyHeader>
              <EmptyMedia variant="icon" className="size-12 rounded-xl">
                <VaultIcon className="size-6 text-muted-foreground" />
              </EmptyMedia>
              <EmptyTitle>{t('keys.emptyTitle')}</EmptyTitle>
              <EmptyDescription className="max-w-[48ch]">{t('keys.emptyBody')}</EmptyDescription>
            </EmptyHeader>
            <EmptyContent className="flex-row justify-center">
              <Button onClick={() => setDialog('generate')}>
                <KeyIcon weight="bold" />
                {t('keys.generate')}
              </Button>
              <Button variant="outline" onClick={() => setDialog('import')}>
                <DownloadSimpleIcon />
                {t('keys.import')}
              </Button>
            </EmptyContent>
          </Empty>
        </Panel>
      ) : (
        <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(420px,500px)]">
          <Panel className="overflow-hidden">
            <div className="flex min-h-12 items-center justify-between gap-3 border-b px-4 py-2">
              <h2 className="text-sm font-semibold">{t('keys.listTitle')}</h2>
              <span className="text-xs text-muted-foreground tabular-nums">
                {t('keys.count', { count: formatNumber(keys.length) })}
              </span>
            </div>
            <ul className="divide-y">
              {keys.map((key) => (
                <li key={key.id}>
                  <KeyRow ringKey={key} selected={key.id === selected?.id} onSelect={() => setSelectedId(key.id)} />
                </li>
              ))}
            </ul>
          </Panel>
          {selected && <KeyDetails key={selected.id} ringKey={selected} />}
        </div>
      )}

      <GenerateKeyDialog
        open={dialog === 'generate'}
        onOpenChange={(open) => setDialog(open ? 'generate' : null)}
        onCreated={(key) => setSelectedId(key.id)}
      />
      <ImportKeyDialog
        open={dialog === 'import'}
        onOpenChange={(open) => setDialog(open ? 'import' : null)}
        onImported={(result) => {
          const first = result.added[0] ?? result.upgraded[0] ?? result.duplicates[0]
          if (first) setSelectedId(first.id)
        }}
      />
    </PageContainer>
  )
}

function KeyRow({ ringKey, selected, onSelect }: { ringKey: RingKey; selected: boolean; onSelect: () => void }) {
  const { t } = useI18n()
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-current={selected || undefined}
      className={cn(
        'group flex w-full items-center gap-3 px-4 py-3 text-left transition-colors outline-none hover:bg-muted/50 focus-visible:bg-muted/60',
        selected &&
          'bg-primary/[0.05] hover:bg-primary/[0.07] dark:bg-primary/10 forced-colors:border-l-4 forced-colors:border-[Highlight] forced-colors:pl-3',
      )}
    >
      <KeyIdenticon id={ringKey.id} className="size-10 rounded-xl" />
      <span className="min-w-0 flex-1">
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-medium">{ringKey.name}</span>
          {ringKey.pkcs8 && !ringKey.privateSaved && <Tag tone="warn">{t('keys.unsaved')}</Tag>}
        </span>
        {/* Two groups without a separator between them, so a wrap never leaves a dangling dot. */}
        <span className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
          <span className="whitespace-nowrap">
            RSA {ringKey.bits} <span aria-hidden>·</span>{' '}
            <span className="font-mono text-[0.6875rem]">{groupHex(ringKey.id, 4)}</span>
          </span>
          <span className={cn('inline-flex items-center gap-1', ringKey.pkcs8 && 'text-foreground')}>
            {ringKey.pkcs8 ? (
              <LockKeyIcon weight="fill" className="size-3 text-primary" />
            ) : (
              <KeyIcon className="size-3" />
            )}
            {ringKey.pkcs8 ? t('keys.private') : t('keys.publicOnly')}
          </span>
        </span>
      </span>
      <CaretRightIcon
        className={cn(
          'size-4 shrink-0 text-muted-foreground/60 transition-transform group-hover:translate-x-0.5',
          selected && 'text-primary',
        )}
      />
    </button>
  )
}

function KeyDetails({ ringKey }: { ringKey: RingKey }) {
  const { t, lang } = useI18n()
  const { level } = useSettings()
  const [renaming, setRenaming] = useState(false)
  const [draft, setDraft] = useState(ringKey.name)
  const [confirm, setConfirm] = useState<'delete' | 'forget' | null>(null)
  const added = new Intl.DateTimeFormat(lang === 'vi' ? 'vi-VN' : 'en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(ringKey.addedAt)

  const commitRename = () => {
    renameKey(ringKey.id, draft)
    setRenaming(false)
  }

  return (
    <Panel as="aside" aria-label={ringKey.name} className="overflow-hidden xl:sticky xl:top-6">
      <div className="flex items-start gap-3 border-b px-4 py-3.5">
        <KeyIdenticon id={ringKey.id} className="size-11 rounded-xl" />
        <div className="min-w-0 flex-1">
          {renaming ? (
            <form
              onSubmit={(event) => {
                event.preventDefault()
                commitRename()
              }}
            >
              <Input
                value={draft}
                autoFocus
                aria-label={t('keys.renameLabel')}
                maxLength={80}
                onChange={(event) => setDraft(event.target.value)}
                onBlur={commitRename}
                onKeyDown={(event) => {
                  if (event.key === 'Escape') {
                    setDraft(ringKey.name)
                    setRenaming(false)
                  }
                }}
                className="h-8"
              />
            </form>
          ) : (
            <h2 className="truncate text-base leading-8 font-semibold">{ringKey.name}</h2>
          )}
          <p className="text-xs text-muted-foreground">
            RSA {ringKey.bits} bit · {ringKey.pkcs8 ? t('keys.private') : t('keys.publicOnly')}
          </p>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label={t('keys.actions')}>
              <DotsThreeIcon weight="bold" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-52">
            <DropdownMenuItem
              onSelect={() => {
                setDraft(ringKey.name)
                setRenaming(true)
              }}
            >
              <PencilSimpleIcon />
              {t('keys.rename')}
            </DropdownMenuItem>
            <DropdownMenuItem
              onSelect={() => {
                updateSelection({ recipients: [ringKey.id] })
                navigate('rsa')
              }}
            >
              <LockKeyIcon />
              {t('keys.useEncrypt')}
            </DropdownMenuItem>
            {ringKey.pkcs8 && (
              <DropdownMenuItem
                onSelect={() => {
                  updateSelection({ signer: ringKey.id })
                  navigate('sign')
                }}
              >
                <SignatureIcon />
                {t('keys.useSign')}
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            {ringKey.pkcs8 && (
              <DropdownMenuItem onSelect={() => setConfirm('forget')}>
                <KeyIcon />
                {t('keys.forgetPrivate')}
              </DropdownMenuItem>
            )}
            <DropdownMenuItem variant="destructive" onSelect={() => setConfirm('delete')}>
              <TrashIcon />
              {t('keys.delete')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div className="flex flex-col gap-3 border-b px-4 py-4">
        <DetailsList
          rows={[
            {
              label: t('keys.keyId'),
              value: (
                <span className="inline-flex items-center gap-1">
                  <span className="font-mono text-xs">{groupHex(ringKey.id, 4)}</span>
                  <CopyButton value={ringKey.id} iconOnly variant="ghost" size="icon-xs" />
                </span>
              ),
            },
            { label: t('keys.fingerprint'), value: ringKey.fingerprint.replace(/^SHA256:/, ''), mono: true },
            // An identifier rather than a quantity: 65537, never "65.537".
            { label: t('keys.exponentShort'), value: String(ringKey.publicExponent) },
            {
              label: t('keys.origin'),
              value:
                ringKey.origin === 'generated'
                  ? t('keys.originGenerated')
                  : ringKey.source
                    ? `${t('keys.originImported')} (${t(`keys.sources.${ringKey.source}`)})`
                    : t('keys.originImported'),
            },
            { label: t('keys.added'), value: added },
          ]}
        />
      </div>

      <div className="flex flex-col gap-3 px-4 py-4">
        <h3 className="text-[0.8125rem] font-semibold">{t('keys.export')}</h3>
        <KeyExport ringKey={ringKey} />
      </div>

      {level === 'advanced' && <KeyComponents ringKey={ringKey} />}

      <AlertDialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirm === 'forget'
                ? t('keys.forgetTitle', { name: ringKey.name })
                : t('keys.deleteTitle', { name: ringKey.name })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirm === 'forget' ? t('keys.forgetBody') : t('keys.deleteBody')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => (confirm === 'forget' ? forgetPrivateKey(ringKey.id) : removeKey(ringKey.id))}
            >
              {confirm === 'forget' ? t('keys.forgetPrivate') : t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Panel>
  )
}

function KeyComponents({ ringKey }: { ringKey: RingKey }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [details, setDetails] = useState<{ id: string; value: RsaKeyDetails } | null>(null)

  useEffect(() => {
    if (!open) return
    let cancelled = false
    callCrypto('keyDetails', { spki: ringKey.spki, pkcs8: ringKey.pkcs8 }).then(
      (value) => !cancelled && setDetails({ id: ringKey.id, value }),
      () => undefined,
    )
    return () => {
      cancelled = true
    }
  }, [open, ringKey])

  const value = details?.id === ringKey.id ? details.value : null
  const rows = value
    ? [
        { label: t('keys.modulus'), value: value.modulusHex, mono: true },
        ...(value.private
          ? [
              { label: t('keys.privateExponent'), value: value.private.d, mono: true },
              { label: t('keys.primeP'), value: value.private.p, mono: true },
              { label: t('keys.primeQ'), value: value.private.q, mono: true },
            ]
          : []),
      ]
    : []

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="border-t">
      <CollapsibleTrigger className="flex w-full items-center justify-between px-4 py-3 text-left text-sm font-medium outline-none hover:bg-muted/40 focus-visible:bg-muted/60">
        {t('keys.advancedDetails')}
        <CaretRightIcon className={cn('size-4 text-muted-foreground transition-transform', open && 'rotate-90')} />
      </CollapsibleTrigger>
      <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down">
        <div className="px-4 pb-4">
          {rows.length > 0 && (
            <dl className="flex flex-col gap-3 text-[0.8125rem]">
              {rows.map((row) => (
                <div key={row.label} className="flex flex-col gap-1">
                  <dt className="text-xs text-muted-foreground">{row.label}</dt>
                  <dd>
                    <ScrollRegion
                      label={row.label}
                      className="max-h-28 rounded-md bg-muted/50 px-2.5 py-2 font-mono text-[0.6875rem] leading-relaxed break-all"
                    >
                      {row.value}
                    </ScrollRegion>
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}
