import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5077 Wave-2 shared-foundation evidence capture.
// Runs Storybook on 4560 (isolated harness for the shared primitives, which are
// not yet mounted on any route) so sibling servers on other ports are untouched.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5077.spec.ts',
  reporter: 'list',
  timeout: 120_000,
  use: {
    baseURL: 'http://localhost:4560',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec storybook dev -p 4560 --ci --no-open',
    port: 4560,
    reuseExistingServer: true,
    timeout: 180_000,
  },
})
