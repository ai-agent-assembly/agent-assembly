/**
 * The specs that run in `dashboard-e2e-real-backend`, as one list (AAASM-5694).
 *
 * Both configs read this: `playwright.ci.config.ts` subtracts it, and
 * `playwright.realbackend.config.ts` selects it. That coupling is the point.
 * Held as two hardcoded lists, adding a name to the mocked lane's exclusion
 * would remove a spec from that gate without adding it to this one — the spec
 * would then run in neither, silently, with no error and no change to the
 * `assert-e2e-actually-ran` floor. `playwright.quarantine.ts` has a ratchet
 * against exactly that shape; a second exclusion channel without one reopens
 * it one file over.
 *
 * Read as a single source instead, the two states cannot disagree: anything
 * excluded from the mocked gate is by construction executed against a live
 * `aa-api-server`, where a spec that cannot pass goes red rather than missing.
 *
 * `hitl-approval.spec.ts` is also in `playwright.quarantine.ts`, so the mocked
 * lane already skipped it before this list existed; naming it here changes
 * nothing there and keeps this list equal to what the lane actually runs.
 */
const REAL_BACKEND_SPECS = [
  // Asserts the paginated envelope against the live server — the AAASM-4892
  // drift class the mocked gate structurally cannot see.
  'real-backend-contract.spec.ts',
  // AAASM-5360's acceptance evidence: proxies /api/v1/** to the live server.
  'verify-aaasm-5360.spec.ts',
  // The one pre-existing spec that asserts a genuine round trip.
  'hitl-approval.spec.ts',
]

export default REAL_BACKEND_SPECS
