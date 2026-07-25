import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5075 Trace FE-parity evidence capture. Runs
// Storybook on 4563 (its own port so sibling parity servers — e.g. the 5077
// foundation on 4560 — are untouched) since the ApprovalDetailDrawer shell and
// the square VerdictChip callers are proven in isolation from the Storybook
// harness rather than a product route.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5075.spec.ts',
  reporter: 'list',
  timeout: 120_000,
  use: {
    baseURL: 'http://localhost:4563',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec storybook dev -p 4563 --ci --no-open',
    port: 4563,
    reuseExistingServer: true,
    timeout: 180_000,
  },
})
