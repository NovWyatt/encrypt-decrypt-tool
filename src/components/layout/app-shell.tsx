import { useRef, useState, type ReactNode } from 'react'
import { ListIcon, LockKeyIcon, ShieldCheckIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { motion } from 'motion/react'
import { navigate, ROUTE_GROUPS, ROUTES, useRoute, type RouteId } from '@/app/routes'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import { useI18n } from '@/i18n'
import { LanguageSwitch, LevelSwitch, ThemeMenu } from './preferences'

function Brand() {
  const { t } = useI18n()
  return (
    <a
      href="#/aes"
      className="flex items-center gap-2.5 rounded-lg outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-primary text-primary-foreground shadow-[inset_0_1px_0_oklch(1_0_0/0.18)]">
        <LockKeyIcon weight="bold" className="size-4.5" />
      </span>
      <span className="text-[0.9375rem] leading-tight font-semibold tracking-tight">{t('app.name')}</span>
    </a>
  )
}

function NavList({ onNavigate, layoutId }: { onNavigate?: () => void; layoutId: string }) {
  const { t } = useI18n()
  const current = useRoute()
  const go = (id: RouteId) => {
    navigate(id)
    onNavigate?.()
  }
  return (
    <nav aria-label={t('nav.navigation')} className="flex flex-col gap-5">
      {ROUTE_GROUPS.map((group) => (
        <div key={group.id} className="flex flex-col gap-0.5">
          <p className="px-2.5 pb-1 text-xs font-medium text-muted-foreground">{t(group.label)}</p>
          {ROUTES.filter((route) => route.group === group.id).map((route) => {
            const active = route.id === current
            return (
              <a
                key={route.id}
                href={`#/${route.id}`}
                aria-current={active ? 'page' : undefined}
                onClick={(event) => {
                  event.preventDefault()
                  go(route.id)
                }}
                className={cn(
                  'relative isolate flex h-9 items-center gap-2.5 rounded-lg px-2.5 text-sm font-medium transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50',
                  active
                    ? 'text-foreground forced-colors:text-[HighlightText] forced-colors:forced-color-adjust-none'
                    : 'text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground',
                )}
              >
                {active && (
                  <motion.span
                    layoutId={layoutId}
                    layoutDependency={current}
                    aria-hidden
                    className="absolute inset-0 -z-10 rounded-lg bg-sidebar-accent forced-colors:bg-[Highlight]"
                    transition={{ type: 'spring', stiffness: 520, damping: 42 }}
                  />
                )}
                <route.icon
                  weight={active ? 'fill' : 'regular'}
                  className={cn('size-4.5', active && 'text-primary forced-colors:text-[HighlightText]')}
                />
                {t(route.label)}
              </a>
            )
          })}
        </div>
      ))}
    </nav>
  )
}

function SidebarFooter() {
  const { t } = useI18n()
  return (
    <div className="flex flex-col gap-4">
      <LevelSwitch />
      <div className="flex items-center justify-between gap-2">
        <ThemeMenu />
        <LanguageSwitch />
      </div>
      <p className="flex gap-2 text-xs leading-relaxed text-muted-foreground">
        <ShieldCheckIcon weight="fill" className="mt-0.5 size-3.5 shrink-0 text-success" />
        {t('app.localOnly')}
      </p>
    </div>
  )
}

export function AppShell({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const [menuOpen, setMenuOpen] = useState(false)
  const navigatedFromMenu = useRef(false)

  return (
    <div className="min-h-[100dvh] bg-background">
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
      >
        {t('app.skipToContent')}
      </a>

      <aside
        aria-label={t('nav.sidebar')}
        className="fixed inset-y-0 left-0 hidden w-64 flex-col border-r border-sidebar-border bg-sidebar lg:flex"
      >
        <div className="flex h-16 items-center px-5">
          <Brand />
        </div>
        <div className="flex-1 scrollbar-thin overflow-y-auto px-3 py-3">
          <NavList layoutId="nav-desktop" />
        </div>
        <div className="border-t border-sidebar-border p-4">
          <SidebarFooter />
        </div>
      </aside>

      <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b bg-background/85 px-4 backdrop-blur-md lg:hidden">
        <Brand />
        <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
          <SheetTrigger asChild>
            <Button variant="ghost" size="icon" aria-label={t('nav.openMenu')}>
              <ListIcon className="size-5" />
            </Button>
          </SheetTrigger>
          <SheetContent
            side="left"
            closeLabel={t('common.close')}
            className="flex w-72 flex-col gap-0 bg-sidebar p-0"
            onOpenAutoFocus={(event) => {
              // Radix skips links when choosing initial focus; the current page link is the natural start.
              event.preventDefault()
              const target = event.currentTarget as HTMLElement
              target.querySelector<HTMLElement>('[aria-current="page"]')?.focus({ preventScroll: true })
            }}
            onCloseAutoFocus={(event) => {
              if (!navigatedFromMenu.current) return
              navigatedFromMenu.current = false
              // After picking a page, continue at its heading instead of back on the menu button.
              event.preventDefault()
              const heading = document.querySelector<HTMLElement>('main > :not([hidden]) h1')
              ;(heading ?? document.getElementById('main'))?.focus({ preventScroll: true })
            }}
          >
            <SheetHeader className="h-14 justify-center px-5">
              <SheetTitle className="sr-only">{t('nav.navigation')}</SheetTitle>
              <SheetDescription className="sr-only">{t('app.localOnly')}</SheetDescription>
              <Brand />
            </SheetHeader>
            <div className="flex-1 overflow-y-auto px-3 py-3">
              <NavList
                layoutId="nav-mobile"
                onNavigate={() => {
                  navigatedFromMenu.current = true
                  setMenuOpen(false)
                }}
              />
            </div>
            <div className="border-t border-sidebar-border p-4">
              <SidebarFooter />
            </div>
          </SheetContent>
        </Sheet>
      </header>

      <main id="main" tabIndex={-1} className="outline-none lg:pl-64">
        {children}
      </main>
    </div>
  )
}
