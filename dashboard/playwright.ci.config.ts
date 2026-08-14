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
export default defineConfig({
  ...base,
  testIgnore: QUARANTINE,
})
