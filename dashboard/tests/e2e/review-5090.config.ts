import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5090 *review* pass. Pinned to port 4591 — one
// above the capture config's 4590 — so a review run and a capture run can be in
// flight at the same time without either stealing the other's preview server.
const PORT = 4591

export default defineConfig({
  testDir: '.',
  testMatch: 'review-aaasm-5090.spec.ts',
  fullyParallel: false,
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
