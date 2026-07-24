import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5041 evidence capture: runs against a preview
// server already listening on 4507 (started out-of-band so sibling servers on
// the default 4173 port are left untouched).
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5041.spec.ts',
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4507',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4507 --strictPort',
    port: 4507,
    reuseExistingServer: true,
  },
})
