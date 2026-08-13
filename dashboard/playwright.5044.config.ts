import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5044 evidence capture: runs against a preview
// server on 4510 (a non-default port so sibling servers on 4173/other ports are
// left untouched). The webServer is reused if one is already listening.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5044.spec.ts',
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4510',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4510 --strictPort',
    port: 4510,
    reuseExistingServer: true,
  },
})
