import { expect, openApp, test } from './fixtures.ts'
import { layoutFaults } from './layout.ts'
import { LEVELS, PAGES } from './pages.ts'

// The narrowest phone, a tablet, the smallest width with the sidebar, and a laptop.
const WIDTHS = [320, 768, 1024, 1280]

for (const width of WIDTHS) {
  test.describe(`${width}px`, () => {
    test.use({ viewport: { width, height: width < 768 ? 800 : 900 }, isMobile: width < 768, hasTouch: width < 768 })

    for (const level of LEVELS) {
      for (const { name, route, ...rest } of PAGES) {
        test(`${name} page (${level}) lays out without faults`, async ({ page }) => {
          await openApp(page, route, { level, storage: 'storage' in rest ? rest.storage : {} })
          const { overflow, faults } = await layoutFaults(page)
          expect(overflow, 'horizontal page overflow in px').toBe(0)
          expect(faults).toEqual([])
        })
      }
    }
  })
}

test.describe('short screens', () => {
  // A desktop browser zoomed to 400%, the size WCAG reflow asks content to work at.
  test.use({ viewport: { width: 320, height: 256 } })

  test('dialogs fit and scroll inside themselves', async ({ page }) => {
    await openApp(page, 'keys', { level: 'advanced' })
    for (const name of ['Tạo cặp khóa', 'Nhập khóa']) {
      await page.getByRole('main').getByRole('button', { name }).first().click()
      const dialog = page.getByRole('dialog')
      const box = await dialog.boundingBox()
      expect(box && box.y >= 0 && box.y + box.height <= 256, `${name} dialog inside the viewport`).toBe(true)
      // The last control is reachable by scrolling the dialog, and the footer stays flush with its bottom edge.
      const footer = dialog.locator('[data-slot="dialog-footer"]')
      await footer.getByRole('button').last().scrollIntoViewIfNeeded()
      await expect(footer.getByRole('button').last()).toBeInViewport()
      const [footerBox, dialogBox] = [await footer.boundingBox(), await dialog.boundingBox()]
      expect(Math.abs(footerBox!.y + footerBox!.height - (dialogBox!.y + dialogBox!.height))).toBeLessThan(1)
      await page.keyboard.press('Escape')
      await expect(dialog).toBeHidden()
    }
  })
})
