import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5045 evidence capture: runs against a preview
// server on 4512 (a non-default port so sibling servers on 4173/4510/other
// ports are left untouched). The webServer is reused if one is already
// listening.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5045.spec.ts',
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4512',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4512 --strictPort',
    port: 4512,
    reuseExistingServer: true,
  },
})
