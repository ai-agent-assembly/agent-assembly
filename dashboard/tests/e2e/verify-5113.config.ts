import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5113 Overview-truthfulness capture. Pinned to
// its own port so a run here never steals the preview server of another
// ticket's capture/review config (4580/4581, 4590/4591, 4593, 4596, 4599).
const PORT = 4585

export default defineConfig({
  testDir: '.',
  testMatch: 'verify-aaasm-5113.spec.ts',
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
