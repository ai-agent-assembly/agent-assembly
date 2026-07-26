import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5135 / 5136 / 5138 / 5140 Topology
// truthfulness capture. Pinned to its own port so a run here never steals the
// preview server of another ticket's capture/review config (4580/4581, 4585,
// 4593, 4596, 4599).
const PORT = 4590

export default defineConfig({
  testDir: '.',
  testMatch: 'verify-aaasm-5135.spec.ts',
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
