import { expect, test as base, type Page } from '@playwright/test'

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
