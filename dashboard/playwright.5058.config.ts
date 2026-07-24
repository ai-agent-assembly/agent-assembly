import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5058 evidence capture: runs a preview server on
// 4514 (via --strictPort) so sibling servers on other ports are left untouched.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5058.spec.ts',
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4514',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4514 --strictPort',
    port: 4514,
    reuseExistingServer: true,
  },
})
