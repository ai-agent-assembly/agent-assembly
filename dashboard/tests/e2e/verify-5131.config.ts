import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5131 agent-detail posture capture. Pinned to
// its own port so a run here never steals the preview server of another
// ticket's capture/review config (4580-4586, 4590/4591, 4593, 4594, 4596, 4599).
const PORT = 4587

export default defineConfig({
  testDir: '.',
  testMatch: 'verify-aaasm-5131.spec.ts',
  fullyParallel: false,
  reporter: 'list',
  timeout: 120_000,
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `pnpm exec vite preview --port ${PORT} --strictPort`,
    port: PORT,
    reuseExistingServer: true,
    timeout: 180_000,
  },
})
