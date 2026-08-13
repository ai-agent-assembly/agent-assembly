import { defineConfig, devices } from '@playwright/test'

// Standalone config for the AAASM-5109 / AAASM-5165 Trace review pass.
//
// The run asserts on test ids this branch introduces (`trace-unavailable`,
// `redaction-preview-absent`, `trace-event-verdict-absent`), so a preview
// server left over from an older build fails the run loudly rather than
// producing green evidence for code that is not under test.
const PORT = 4591

export default defineConfig({
  testDir: '.',
  testMatch: 'review-aaasm-5109.spec.ts',
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
