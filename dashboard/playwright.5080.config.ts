import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5080 orphan-section evidence capture: runs against
// a preview server on 4553 (a non-default port so sibling servers on other ports
// are left untouched). The webServer is reused if one is already listening.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5080.spec.ts',
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4553',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4553 --strictPort',
    port: 4553,
    reuseExistingServer: true,
  },
})
