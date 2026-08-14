import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5161 verification capture. Pinned to port
// 4561 (not the shared 4173) so the run never collides with a sibling
// worktree's preview server.
const PORT = 4561

export default defineConfig({
  testDir: '.',
  testMatch: 'verify-aaasm-5161.spec.ts',
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
