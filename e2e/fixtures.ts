import { AxeBuilder } from '@axe-core/playwright'
import { expect, test as base, type Locator, type Page } from '@playwright/test'

export { expect }

export interface AppSettings {
  level?: 'basic' | 'advanced'
  lang?: 'vi' | 'en'
  theme?: 'light' | 'dark'
  /** Other localStorage entries, stored as JSON like the app stores them. */
  storage?: Record<string, unknown>
}

/**
 * Every test fails on a console error, an uncaught exception or a Content-Security-Policy violation, so a header
 * that blocks something the app needs cannot slip through.
 */
export const test = base.extend<{ problems: string[] }>({
  problems: [
    async ({ page }, use) => {
      const problems: string[] = []
      page.on('console', (message) => {
        if (message.type() === 'error') problems.push(message.text())
      })
      page.on('pageerror', (error) => problems.push(error.message))
      await page.addInitScript(() =>
        document.addEventListener('securitypolicyviolation', (event) =>
          console.error(`CSP blocked ${event.blockedURI || 'inline code'} (${event.effectiveDirective})`),
        ),
      )
      await use(problems)
      expect(problems, 'console errors, exceptions or CSP violations').toEqual([])
    },
    { auto: true },
  ],
})

/** The page on screen. Pages stay mounted, hidden, once visited, so queries on `main` alone can match old pages. */
export function view(page: Page) {
  return page.locator('main > :not([hidden])')
}

/**
 * Follows a sidebar link and waits for its page to show. The route changes on `hashchange`, a task after the click,
 * so acting straight away would reach the page being left.
 */
export async function goTo(page: Page, name: string) {
  await page.getByRole('navigation').getByRole('link', { name, exact: true }).click()
  await expect(view(page).getByRole('heading', { level: 1, name, exact: true })).toBeVisible()
}

/**
 * Watches `scope` for the update that first shows `badge` in a status, and returns a function that resolves with the
 * result text on screen in that same update. A status and its result come from one state, so any other text there,
 * such as the previous result still fading out, is an old body left under the new status.
 */
export async function watchResult(scope: Locator, badge: string) {
  const watch = await scope.evaluateHandle(
    (root, badge) => ({
      text: new Promise<string | null>((resolve) => {
        const observer = new MutationObserver(() => {
          const statuses = [...root.querySelectorAll('[role="status"]')]
          if (!statuses.some((status) => status.textContent?.includes(badge))) return
          observer.disconnect()
          resolve(root.querySelector('pre')?.textContent ?? null)
        })
        observer.observe(root, { childList: true, characterData: true, subtree: true })
      }),
    }),
    badge,
  )
  return () => watch.evaluate(({ text }) => text)
}

const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice']

/**
 * Runs axe on the current page and returns its violations in a form that reads well in a failed assertion. Waits for
 * running animations first: a result that is still fading in would be measured at part of its contrast.
 */
export async function violations(page: Page, disabledRules: string[] = []) {
  await page.evaluate(async () => {
    const running = () =>
      document
        .getAnimations()
        .filter(
          (animation) =>
            animation.playState === 'running' && animation.effect?.getComputedTiming().endTime !== Infinity,
        )
    // One animation can start another, such as an old result fading out before the new one fades in.
    for (let pending = running(); pending.length > 0; pending = running()) {
      await Promise.all(pending.map((animation) => animation.finished.catch(() => undefined)))
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))
    }
  })
  const results = await new AxeBuilder({ page }).withTags(AXE_TAGS).disableRules(disabledRules).analyze()
  return results.violations.map(({ id, help, nodes }) => ({
    id,
    help,
    targets: nodes.map((node) => node.target.join(' ')),
  }))
}

/** Opens a route with preset settings and waits until the page and its fonts are ready. */
export async function openApp(page: Page, route: string, settings: AppSettings = {}) {
  const { level = 'basic', lang = 'vi', theme = 'light', storage = {} } = settings
  await page.addInitScript(
    ({ level, lang, theme, storage }) => {
      localStorage.setItem('edt.settings', JSON.stringify({ level, lang }))
      localStorage.setItem('edt.theme', JSON.stringify(theme))
      for (const [key, value] of Object.entries(storage)) localStorage.setItem(key, JSON.stringify(value))
    },
    { level, lang, theme, storage },
  )
  const response = await page.goto(`./#/${route}`)
  await expect(view(page).locator('h1')).toBeVisible()
  await page.evaluate(() => document.fonts.ready)
  return response
}
