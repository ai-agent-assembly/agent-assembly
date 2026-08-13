import { defineConfig, devices } from '@playwright/test'

// Post-fix review capture for AAASM-5074 (SonarCloud + Codecov remediation):
// re-runs the parity evidence spec into `verify/parity-liveops/review/` on a
// dedicated port 4572 (via --strictPort) so sibling preview servers on other
// ports are left untouched. Output dir is redirected via AAASM5074_OUT.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'verify-aaasm-5074.spec.ts',
  reporter: 'list',
  timeout: 120_000,
  use: {
    baseURL: 'http://localhost:4572',
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite preview --port 4572 --strictPort',
    port: 4572,
    reuseExistingServer: true,
  },
})
