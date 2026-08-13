import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5073 agent-detail FE-parity evidence capture.
// Runs a preview server on 4561 (reusing one already listening) so sibling
// servers on other ports are left untouched.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5073.spec.ts',
  reporter: 'list',
  timeout: 120_000,
  use: {
    baseURL: 'http://localhost:4561',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4561 --strictPort',
    port: 4561,
    reuseExistingServer: true,
    timeout: 180_000,
  },
})
