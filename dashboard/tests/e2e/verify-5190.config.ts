import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5190 approval-drawer head capture. Serves
// Storybook (not `vite preview`) because the drawer has no product route yet —
// its approval-review flow is backend-blocked on AAASM-5095 — and pins its own
// port so a run here never steals another lane's server.
const PORT = 4617

export default defineConfig({
  testDir: '.',
  testMatch: 'verify-aaasm-5190.spec.ts',
  fullyParallel: false,
  timeout: 120_000,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `pnpm exec storybook dev -p ${PORT} --ci --no-open`,
    port: PORT,
    reuseExistingServer: true,
    timeout: 180_000,
  },
})
