import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5184 unclaimed-team review pass. Pinned to
// its own port so a run here never steals another ticket's preview server.
const PORT = 4612

export default defineConfig({
  testDir: '.',
  testMatch: 'review-aaasm-5184.spec.ts',
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
