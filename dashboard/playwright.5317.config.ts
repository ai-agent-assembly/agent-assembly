import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5317 trust-wiring evidence capture: runs against a
// preview server on 4557 (a non-default port so sibling servers on other ports
// are left untouched). The webServer is reused if one is already listening.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5317.spec.ts',
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4557',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4557 --strictPort',
    port: 4557,
    reuseExistingServer: true,
  },
})
