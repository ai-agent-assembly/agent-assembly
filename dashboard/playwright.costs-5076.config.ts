import { defineConfig, devices } from '@playwright/test'

// Isolated Playwright config for the AAASM-5076 Costs FE-parity verification.
// Pinned to port 4551 (a dedicated preview server) so it never contends with
// sibling worktrees' default 4173 preview. Reuses an already-running 4551
// preview when present.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5076.spec.ts',
  fullyParallel: false,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4551',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4551 --strictPort',
    port: 4551,
    reuseExistingServer: true,
  },
})
