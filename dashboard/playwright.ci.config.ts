import { defineConfig } from '@playwright/test'

import base from './playwright.config'
import QUARANTINE from './playwright.quarantine'
/**
 * Excluded here because this job provisions no backend. These specs are **not**
 * quarantined — quarantine means "known red, working it down", and spending a
 * deliberate exemption on a routing fact would misreport healthy specs as
 * rotten. `real-backend-contract` asserts a live server is up and correctly
 * fails without one; `verify-aaasm-5360` skips instead, which is worse in its
 * own way — a skip in a lane that cannot satisfy it reads as a pass.
 *
 * The list is imported rather than restated so this exclusion and the
 * real-backend lane's selection cannot drift apart; see that file for why
 * (AAASM-5694).
 */
import REAL_BACKEND_SPECS from './playwright.realbackend.specs'

/**
 * The config the CI e2e gate runs (AAASM-5192).
 *
 * It is the base config plus one thing: the quarantine list, which — together
 * with the ratchet that stops it growing — lives in `playwright.quarantine.ts`
 * so that the local `pnpm test:e2e` path loads the same guard.
 */
export default defineConfig({
  ...base,
  testIgnore: [...QUARANTINE, ...REAL_BACKEND_SPECS],
})
