import { defineConfig } from '@playwright/test'

import base from './playwright.config'
import QUARANTINE from './playwright.quarantine'

/**
 * The config the CI e2e gate runs (AAASM-5192).
 *
 * It is the base config plus one thing: the quarantine list, which — together
 * with the ratchet that stops it growing — lives in `playwright.quarantine.ts`
 * so that the local `pnpm test:e2e` path loads the same guard.
 */
/**
 * The specs that belong to `dashboard-e2e-real-backend`, not here (AAASM-5694).
 *
 * They are **not** quarantined. Quarantine means "known red, working it down",
 * and `playwright.quarantine.ts`'s ratchet exists to stop that list growing
 * quietly — putting these there would spend a deliberate exemption on a routing
 * fact and misreport two healthy specs as rotten.
 *
 * They are excluded because this job provisions no backend. `real-backend-contract`
 * asserts a live server is up and correctly fails without one; it went red here
 * before this exclusion existed. `verify-aaasm-5360` skips instead, which is
 * worse in its own way — a skip in a lane that cannot satisfy it reads as a pass.
 * Both now run for real in the lane that boots `aa-api-server`.
 */
const REAL_BACKEND_SPECS = [
  'real-backend-contract.spec.ts',
  'verify-aaasm-5360.spec.ts',
]

export default defineConfig({
  ...base,
  testIgnore: [...QUARANTINE, ...REAL_BACKEND_SPECS],
})
