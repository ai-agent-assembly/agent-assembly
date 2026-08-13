import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5074 Live-Ops FE-parity evidence capture: runs a
// preview server on 4562 (via --strictPort) so sibling servers on other ports
// are left untouched.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5074.spec.ts',
  reporter: 'list',
  timeout: 120_000,
  use: {
    baseURL: 'http://localhost:4562',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4562 --strictPort',
    port: 4562,
    reuseExistingServer: true,
  },
})
