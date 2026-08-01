import { defineConfig } from '@playwright/test'

import base from './playwright.config'

/**
 * The AAASM-5369 verification spec, on a port of its own.
 *
 * The base config serves on 4173 with `reuseExistingServer: !process.env.CI`,
 * so a *local* run reuses whatever already holds that port. On this programme
 * several worktrees are checked out at once, which means a green local run can
 * be a green run against a sibling branch's bundle — the failure mode is silent
 * and the result looks identical to a real pass. A private port with
 * `reuseExistingServer: false` makes that impossible rather than unlikely.
 *
 * Committed (like `playwright.5041.config.ts` and the other per-ticket configs
 * here) so the claim "this ran against this branch's build" is checkable from
 * the diff rather than taken on trust — the AAASM-5369 review could not verify
 * it while this file was local-only.
 *
 * CI does not use this file: there, `playwright.ci.config.ts` runs everything
 * with `CI=true`, where `reuseExistingServer` is already false.
 */
const PORT = 4373

export default defineConfig({
  ...base,
  testMatch: /verify-aaasm-5369\.spec\.ts/,
  use: { ...base.use, baseURL: `http://localhost:${PORT}` },
  webServer: {
    command: `pnpm exec vite preview --port ${PORT} --strictPort`,
    port: PORT,
    reuseExistingServer: false,
  },
})
