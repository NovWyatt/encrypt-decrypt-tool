import { expect, goTo, openApp, test, view, violations } from './fixtures.ts'
import { LEVELS, PAGES } from './pages.ts'

const VIEWS = [
  { theme: 'light', viewport: { width: 1280, height: 900 }, isMobile: false },
  { theme: 'dark', viewport: { width: 390, height: 844 }, isMobile: true },
] as const

for (const { theme, viewport, isMobile } of VIEWS) {
  test.describe(`${theme} theme at ${viewport.width}px`, () => {
    test.use({ viewport, isMobile, hasTouch: isMobile })

    for (const level of LEVELS) {
      for (const { name, route, ...rest } of PAGES) {
        test(`${name} page (${level}) has no axe violations`, async ({ page }) => {
          await openApp(page, route, { level, theme, storage: 'storage' in rest ? rest.storage : {} })
          expect(await violations(page)).toEqual([])
        })
      }
    }
  })
}

test('results, menus and dialogs have no axe violations', async ({ page }) => {
  await openApp(page, 'aes', { level: 'advanced' })
  const aes = view(page)
  await aes.getByLabel('Văn bản cần mã hóa').fill('Kiểm tra trợ năng.')
  await aes.locator('input[autocomplete="new-password"]').fill('mat-khau-kiem-tra-2026')
  await aes.getByRole('button', { name: 'Mã hóa', exact: true }).click()
  await expect(aes.getByRole('status').getByText('Đã mã hóa', { exact: true })).toBeVisible()
  await aes.getByRole('button', { name: 'Thông số' }).click()
  expect(await violations(page)).toEqual([])

  // Menus are portaled to the end of the body, outside the landmarks, and hold focus while open; axe's
  // best-practice region rule does not exempt them the way it exempts dialogs.
  await aes.getByRole('button', { name: 'Thêm tùy chọn' }).click()
  await expect(page.getByRole('menu')).toBeVisible()
  expect(await violations(page, ['region'])).toEqual([])
  await page.keyboard.press('Escape')
  await expect(page.getByRole('menu')).toBeHidden()

  await goTo(page, 'Kho khóa RSA')
  for (const name of ['Tạo cặp khóa', 'Nhập khóa']) {
    await view(page).getByRole('button', { name }).first().click()
    await expect(page.getByRole('dialog')).toBeVisible()
    expect(await violations(page)).toEqual([])
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toBeHidden()
  }
})

test('popups keep an edge and a system highlight in Windows contrast themes', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active' })
  await openApp(page, 'keys')
  const system = await page.evaluate(() => {
    const probe = document.createElement('div')
    probe.style.cssText = 'forced-color-adjust: none; background-color: Highlight; color: HighlightText'
    document.body.append(probe)
    const { backgroundColor, color } = getComputedStyle(probe)
    probe.remove()
    return { backgroundColor, color }
  })

  await view(page).getByRole('button', { name: 'Tạo cặp khóa' }).first().click()
  await expect(page.getByRole('dialog')).toHaveCSS('outline-style', 'solid')
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toBeHidden()

  await page.getByRole('button', { name: 'Giao diện' }).click()
  const menu = page.getByRole('menu')
  await expect(menu).toHaveCSS('outline-style', 'solid')
  await page.keyboard.press('ArrowDown')
  const item = menu.locator('[data-highlighted]')
  await expect(item).toHaveCSS('background-color', system.backgroundColor)
  await expect(item).toHaveCSS('color', system.color)
  await expect(item).toHaveCSS('outline-style', 'none')
})
