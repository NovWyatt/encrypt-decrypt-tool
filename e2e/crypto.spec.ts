import { expect, goTo, openApp, test, view } from './fixtures.ts'

const PASSWORD = 'mat-khau-kiem-tra-2026'

test('serves the production headers and runs the inline theme script under them', async ({ page }) => {
  const response = await openApp(page, 'aes', { theme: 'dark' })
  const policy = response?.headers()['content-security-policy'] ?? ''
  expect(policy).toContain("script-src 'self' 'wasm-unsafe-eval' 'sha256-")
  expect(policy).toContain("frame-ancestors 'none'")
  await expect(page.locator('html')).toHaveClass(/\bdark\b/)
})

test('AES encrypts with a password and decrypts back, and rejects a wrong password', async ({ page }) => {
  const text = 'Xin chào — kiểm tra AES-256-GCM với Argon2id.'
  await openApp(page, 'aes')
  const aes = view(page)
  await aes.getByLabel('Văn bản cần mã hóa').fill(text)
  await aes.locator('input[autocomplete="new-password"]').fill(PASSWORD)
  await aes.getByRole('button', { name: 'Mã hóa', exact: true }).click()
  await expect(aes.getByRole('status').getByText('Đã mã hóa', { exact: true })).toBeVisible()

  await aes.getByRole('button', { name: 'Chuyển sang giải mã' }).click()
  const password = aes.locator('input[type="password"]')
  await password.fill('sai-mat-khau')
  await aes.getByRole('button', { name: 'Giải mã', exact: true }).click()
  await expect(aes.getByRole('alert')).toBeVisible()

  await password.fill(PASSWORD)
  await aes.getByRole('button', { name: 'Giải mã', exact: true }).click()
  await expect(aes.getByRole('status').getByText('Đã giải mã', { exact: true })).toBeVisible()
  await expect(aes.locator('pre')).toHaveText(text)
})

test('RSA and signatures work with a key pair generated in the browser', async ({ page }) => {
  await openApp(page, 'keys')
  await view(page).getByRole('button', { name: 'Tạo cặp khóa' }).first().click()
  const dialog = page.getByRole('dialog')
  await dialog.locator('#generate-key-name').fill('Khóa kiểm thử')
  await dialog.getByRole('radio', { name: /2048 bit/ }).click()
  await dialog.getByRole('button', { name: 'Tạo cặp khóa' }).click()
  await expect(dialog).toBeHidden({ timeout: 60_000 })

  // Navigate inside the app: the private key lives only in this page's memory.
  const message = 'Tin nhắn RSA cho bài kiểm thử.'
  await goTo(page, 'Mã hóa RSA')
  const rsa = view(page)
  const recipient = rsa.getByRole('checkbox', { name: /Khóa kiểm thử/ })
  if (!(await recipient.isChecked())) await recipient.check()
  await rsa.getByLabel('Văn bản cần mã hóa').fill(message)
  await rsa.getByRole('button', { name: 'Mã hóa', exact: true }).click()
  await expect(rsa.getByRole('status').getByText('Đã mã hóa', { exact: true })).toBeVisible()
  await rsa.getByRole('button', { name: 'Chuyển sang giải mã' }).click()
  await rsa.getByRole('button', { name: 'Giải mã', exact: true }).click()
  await expect(rsa.getByRole('status').getByText('Đã giải mã', { exact: true })).toBeVisible()
  await expect(rsa.locator('pre')).toHaveText(message)

  await goTo(page, 'Chữ ký số')
  const sign = view(page)
  await sign.getByLabel('Nội dung cần ký').fill('Văn bản cần ký.')
  await sign.getByRole('button', { name: 'Ký', exact: true }).click()
  await expect(sign.getByRole('status').getByText('Đã ký', { exact: true })).toBeVisible()
  await sign.getByRole('button', { name: 'Chuyển sang xác minh' }).click()
  await sign.getByRole('button', { name: 'Xác minh', exact: true }).click()
  await expect(sign.getByRole('status').getByText('Chữ ký hợp lệ', { exact: true })).toBeVisible()
})
