import { expect, goTo, openApp, test, view, violations } from './fixtures.ts'
import { layoutFaults } from './layout.ts'

test('a path that is not in the build gets a 404 that is never cached', async ({ page, problems }) => {
  // A script name the build does not have, like a chunk that a deploy replaced while a tab was open.
  const response = await page.goto('./assets/page-khong-co.js')
  expect(response?.status()).toBe(404)
  expect(response?.headers()['cache-control']).toBe('no-store')
  await expect(page.getByRole('heading', { level: 1, name: 'Không tìm thấy trang' })).toBeVisible()
  expect(await violations(page)).toEqual([])

  await page.setViewportSize({ width: 320, height: 640 })
  const { overflow, faults } = await layoutFaults(page)
  expect(overflow, 'horizontal page overflow in px').toBe(0)
  expect(faults).toEqual([])

  await page.getByRole('link', { name: 'Mở Encrypt/Decrypt Tool' }).click()
  await expect(view(page).locator('h1')).toBeVisible()

  // The 404 itself is logged as a console error; nothing else may be.
  expect(problems.splice(0).filter((problem) => !problem.includes('status of 404'))).toEqual([])
})

test('a page whose code cannot load offers a reload, and the other pages keep working', async ({ page, problems }) => {
  // Stands in for a chunk that a deploy replaced while this tab was open.
  const chunk = '**/assets/keys-page-*.js'
  await page.route(chunk, (route) => route.fulfill({ status: 404, contentType: 'text/html', body: 'Not found' }))
  await openApp(page, 'aes')
  const text = 'Vẫn còn nguyên sau lỗi.'
  await view(page).getByLabel('Văn bản cần mã hóa').fill(text)

  await goTo(page, 'Kho khóa RSA')
  const alert = view(page).getByRole('alert')
  await expect(alert).toContainText('Không tải được trang này')
  expect(await violations(page)).toEqual([])

  await goTo(page, 'Mã hóa AES')
  await expect(view(page).getByLabel('Văn bản cần mã hóa')).toHaveValue(text)

  await page.unroute(chunk)
  await goTo(page, 'Kho khóa RSA')
  await alert.getByRole('button', { name: 'Tải lại trang' }).click()
  await expect(view(page).getByRole('button', { name: 'Tạo cặp khóa' }).first()).toBeVisible()

  // The blocked chunk is logged as a failed request and as the error React caught; nothing else may be.
  const expected = /status of 404|dynamically imported module/
  expect(problems.splice(0).filter((problem) => !expected.test(problem))).toEqual([])
})
