import { defineConfig, devices } from '@playwright/test'

// Scoped config for the AAASM-5059/5060 evidence capture. Builds + serves the
// dashboard on 4531 (strictPort so it never collides with sibling servers) and
// runs only the verify spec.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5059.spec.ts',
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4531',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4531 --strictPort',
    port: 4531,
    reuseExistingServer: true,
  },
})
