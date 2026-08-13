import { defineConfig, devices } from '@playwright/test'

// Side-effect import: evaluates the quarantine ratchet (AAASM-5192). It lives
// here rather than only in `playwright.ci.config.ts` because the local
// `pnpm test:e2e` path never loads that file — so the earlier claim that the
// ratchet ran "on every config load, local and CI" was only half true. This
// makes it true. Nothing from the module is used here on purpose.
import './playwright.quarantine'

export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  // AAASM-5192: the HTML report is the human entry point; the JUnit XML and the
  // `list` lines are what a CI log and a check-annotation can read without
  // unpacking an artifact. `open: 'never'` stops the reporter blocking a
  // headless runner on a browser it cannot launch.
  reporter: process.env.CI
    ? [
        ['list'],
        ['html', { open: 'never' }],
        ['junit', { outputFile: 'test-results/junit.xml' }],
      ]
    : 'html',
  use: {
    baseURL: 'http://localhost:4173',
    trace: 'on-first-retry',
    // AAASM-5192: a failure has to be diagnosable from the uploaded artifact
    // alone — a CI-only failure that needs a local reproduction to read is the
    // thing this gate exists to prevent.
    screenshot: 'only-on-failure',
    video: process.env.CI ? 'retain-on-failure' : 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm preview',
    port: 4173,
    reuseExistingServer: !process.env.CI,
  },
})
