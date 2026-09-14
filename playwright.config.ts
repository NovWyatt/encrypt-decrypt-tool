import { defineConfig, devices } from '@playwright/test'

const CI = Boolean(process.env.CI)

// End-to-end tests run against the production build, served with the headers from dist/_headers. `npm run test:e2e`
// builds first. Set E2E_CHANNEL to test in an installed browser instead of Playwright's Chromium, for example msedge.
export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: CI,
  retries: CI ? 1 : 0,
  reporter: CI ? [['github'], ['html', { open: 'never' }]] : [['list'], ['html', { open: 'never' }]],
  expect: { timeout: 15_000 },
  use: {
    baseURL: 'http://localhost:4173/',
    contextOptions: { reducedMotion: 'reduce' },
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], channel: process.env.E2E_CHANNEL },
    },
  ],
  webServer: {
    command: 'node e2e/serve.ts',
    url: 'http://localhost:4173/',
    reuseExistingServer: !CI,
  },
})
