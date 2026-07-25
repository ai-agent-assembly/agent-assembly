import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5084 review capture. Pinned to port 4581 (the
// verification capture uses 4580; the shared preview uses 4173) so a review run
// never collides with a sibling worktree's preview server.
const PORT = 4581

export default defineConfig({
  testDir: '.',
  testMatch: 'review-aaasm-5084.spec.ts',
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
