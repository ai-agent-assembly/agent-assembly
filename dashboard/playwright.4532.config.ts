import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5063/5064/5065 design-QA evidence capture: runs
// against a preview server on 4532 (a non-default port so sibling servers on
// 4173/other ports are left untouched). The webServer is reused if one is
// already listening.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5063.spec.ts',
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4532',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4532 --strictPort',
    port: 4532,
    reuseExistingServer: true,
  },
})
