import { Component, lazy, Suspense, useEffect, useState, type ComponentType, type ReactNode } from 'react'
import { ArrowClockwiseIcon, WarningCircleIcon } from '@phosphor-icons/react'
import { useRoute, type RouteId } from '@/app/routes'
import { AppShell } from '@/components/layout/app-shell'
import { PageContainer, PageHeader, Panel } from '@/components/common/page'
import { Button } from '@/components/ui/button'
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Skeleton } from '@/components/ui/skeleton'
import { useI18n } from '@/i18n'
import { warmUpCrypto } from '@/lib/crypto/client'

type PageModule = Promise<{ default: ComponentType }>

// Each tool is its own chunk; the shell renders first and the rest loads in the background.
const LOADERS: Record<RouteId, () => PageModule> = {
  aes: () => import('@/features/aes/aes-page').then((module) => ({ default: module.AesPage })),
  rsa: () => import('@/features/rsa/rsa-page').then((module) => ({ default: module.RsaPage })),
  sign: () => import('@/features/sign/sign-page').then((module) => ({ default: module.SignPage })),
  keys: () => import('@/features/keys/keys-page').then((module) => ({ default: module.KeysPage })),
  learn: () => import('@/features/learn/learn-page').then((module) => ({ default: module.LearnPage })),
}

const PAGES: Record<RouteId, ComponentType> = {
  aes: lazy(LOADERS.aes),
  rsa: lazy(LOADERS.rsa),
  sign: lazy(LOADERS.sign),
  keys: lazy(LOADERS.keys),
  learn: lazy(LOADERS.learn),
}

/** Same outline as a tool page, so the layout does not jump when the chunk arrives. */
function PageFallback() {
  return (
    <PageContainer>
      <div aria-busy="true" className="mb-6 flex flex-col gap-3 md:mb-8">
        <Skeleton className="h-8 w-56" />
        <Skeleton className="h-4 w-full max-w-[520px]" />
      </div>
      <div className="grid gap-5 lg:grid-cols-[336px_minmax(0,1fr)] xl:grid-cols-[380px_minmax(0,1fr)]">
        <Skeleton className="h-80 rounded-xl" />
        <Skeleton className="h-[480px] rounded-xl" />
      </div>
    </PageContainer>
  )
}

function PageLoadError({ route }: { route: RouteId }) {
  const { t } = useI18n()
  return (
    <PageContainer>
      <PageHeader title={t(`nav.${route}`)} />
      <Panel as="div" role="alert">
        <Empty className="min-h-[320px] gap-5 py-10">
          <EmptyHeader>
            <EmptyMedia variant="icon" className="size-10 rounded-xl bg-destructive/10 text-destructive">
              <WarningCircleIcon weight="fill" className="size-5" />
            </EmptyMedia>
            <EmptyTitle className="text-base">{t('app.pageFailed')}</EmptyTitle>
            <EmptyDescription>{t('app.pageFailedBody')}</EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button size="lg" onClick={() => location.reload()}>
              <ArrowClockwiseIcon />
              {t('app.reload')}
            </Button>
          </EmptyContent>
        </Empty>
      </Panel>
    </PageContainer>
  )
}

/**
 * Stands in for a page that could not load, usually because the network dropped or a deploy replaced its chunk, so
 * the other pages keep working. Reloading is left to the user: private keys and typed text live only in this tab.
 */
class PageBoundary extends Component<{ route: RouteId; children: ReactNode }, { failed: boolean }> {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  render() {
    return this.state.failed ? <PageLoadError route={this.props.route} /> : this.props.children
  }
}

export default function App() {
  const route = useRoute()
  const { t } = useI18n()
  // Pages stay mounted once visited so switching tools never discards typed input.
  const [visited, setVisited] = useState<RouteId[]>([route])
  if (!visited.includes(route)) setVisited([...visited, route])

  useEffect(() => {
    warmUpCrypto()
    // Fetch the other pages once the browser is idle: navigation stays instant, even offline later. A page that fails
    // to load here shows its own error when opened.
    const preload = () => Object.values(LOADERS).forEach((load) => load().catch(() => undefined))
    if ('requestIdleCallback' in window) {
      const handle = requestIdleCallback(preload, { timeout: 3000 })
      return () => cancelIdleCallback(handle)
    }
    const timer = setTimeout(preload, 1500)
    return () => clearTimeout(timer)
  }, [])

  useEffect(() => {
    document.title = `${t(`nav.${route}`)} | ${t('app.name')}`
  }, [route, t])

  return (
    <AppShell>
      {visited.map((id) => {
        const Page = PAGES[id]
        return (
          <div key={id} hidden={id !== route} className="animate-in duration-300 fade-in">
            <PageBoundary route={id}>
              <Suspense fallback={<PageFallback />}>
                <Page />
              </Suspense>
            </PageBoundary>
          </div>
        )
      })}
    </AppShell>
  )
}
