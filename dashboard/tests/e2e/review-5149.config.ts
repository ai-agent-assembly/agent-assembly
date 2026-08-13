import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5149 / 5134 shell-truthfulness review pass.
// Pinned to its own port so a run here never steals another lane's preview server.
const PORT = 4605

export default defineConfig({
  testDir: '.',
  testMatch: 'review-aaasm-5149.spec.ts',
  fullyParallel: false,
  timeout: 120_000,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `pnpm exec vite preview --port ${PORT} --strictPort`,
    port: PORT,
    reuseExistingServer: true,
  },
})
