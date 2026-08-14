import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5126 / 5127 Costs truthfulness review pass.
// Pinned to its own port so a run here never steals the preview server of
// another ticket's capture/review config.
const PORT = 4592

export default defineConfig({
  testDir: '.',
  testMatch: 'review-aaasm-5126.spec.ts',
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
