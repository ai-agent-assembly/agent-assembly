/**
 * Deterministic fixtures for the three `/api/v1/scrub/*` routes (AAASM-5347).
 *
 * ## Why this exists
 *
 * Until AAASM-5347 the Scrub page rendered its detector catalogue from a static
 * table compiled into the bundle, so an e2e spec could open `/scrub` without
 * telling the network anything and still get a fully-populated page. Both scrub
 * specs were written against that world: `scrub-design-fidelity` mocks nothing
 * at all, and `review-aaasm-5112` fulfils every `/api/**` call with a bare `{}`.
 *
 * The catalogue is now fetched, and `scrubCatalogueFromQuery` treats a failed or
 * empty response as an absence — so on an unseeded harness the page short-circuits
 * to its loading/error state and every assertion about the body, the stat strip
 * and the payload diff has nothing to bind to. Seeding these three routes is what
 * puts the page back in the state each spec was written to inspect.
 *
 * ## Faithfulness
 *
 * Every field is what the real handler serves. Kinds, categories and severities
 * are transcribed from `CredentialKind::{ALL, category, severity, as_str}` in
 * `aa-security/src/scanner.rs`; the response envelopes are
 * `ScrubCatalogueResponse` / `PatternCountsResponse` / `PostureResponse` in
 * `openapi/v1.yaml`. The catalogue is a **subset** — one kind per category, in
 * `CredentialKind::ALL` declaration order — because these specs assert the shape
 * of the surface, not the size of the scanner. It deliberately contains none of
 * the four phantom detectors AAASM-5156 removed, so a spec asserting their
 * absence still discriminates: the fixture cannot be the thing that supplies them.
 *
 * `leak_rate` stays `null` with `rate_computed: false` because that is the only
 * thing the handler can honestly say — the alert store persists detections but
 * not the total-payloads-scanned denominator. A fixture that invented a rate
 * would let the page render one and no test would notice.
 */
import type { Page } from '@playwright/test'

export interface ScrubPatternFixture {
  readonly kind: string
  readonly redaction_label: string
  readonly category: string
  readonly severity: string
  readonly builtin: boolean
}

function pattern(kind: string, category: string, severity: string): ScrubPatternFixture {
  // The label is derived, never spelled out per row: `CredentialFinding::new`
  // builds it as `format!("[REDACTED:{}]", kind.as_str())`, so a fixture that
  // let the two disagree could teach a label the gateway never emits — the
  // AAASM-5156 defect, reintroduced through the test harness.
  return {
    kind,
    redaction_label: `[REDACTED:${kind}]`,
    category,
    severity,
    builtin: true,
  }
}

/** One kind per `CredentialKind::category()` family, in declaration order. */
export const SCRUB_PATTERNS: readonly ScrubPatternFixture[] = [
  pattern('AnthropicKey', 'api_key', 'critical'),
  pattern('AwsAccessKey', 'cloud_credential', 'critical'),
  pattern('SlackBotToken', 'auth_token', 'critical'),
  pattern('PostgresUrl', 'database_url', 'high'),
  pattern('RsaPrivateKey', 'private_key', 'critical'),
  pattern('EmailAddress', 'pii', 'medium'),
  pattern('GenericHighEntropy', 'generic', 'low'),
]

export const SCRUB_CATALOGUE_RESPONSE = {
  patterns: SCRUB_PATTERNS,
  total: SCRUB_PATTERNS.length,
}

/**
 * A populated 24h alert tally.
 *
 * Only kinds that fired appear — that is the handler's contract, and it is what
 * makes a `0` in the catalogue's alerts column a measurement rather than a
 * default. `AwsAccessKey` carries a value no local table anywhere in the
 * dashboard holds, so a cell rendering it can only have come from this response.
 */
export const SCRUB_PATTERN_COUNTS = {
  counts: [
    { kind: 'AwsAccessKey', hits: 7 },
    { kind: 'SlackBotToken', hits: 2 },
  ],
  total_hits: 9,
  window_seconds: 86_400,
}

/** A populated 30d posture. `leak_rate` is absent because it is not derivable. */
export const SCRUB_POSTURE = {
  leaks_intercepted: 11,
  distinct_kinds: 2,
  leak_rate: null,
  rate_computed: false,
  window_seconds: 2_592_000,
}

/**
 * Fulfil the three scrub routes.
 *
 * Register **after** any permissive `**/api/**` catch-all: Playwright matches the
 * most recently added route first, so an earlier catch-all would otherwise answer
 * these paths with whatever it serves.
 */
export async function routeScrubApi(page: Page): Promise<void> {
  await page.route('**/api/v1/scrub/patterns**', (route) =>
    route.fulfill({ json: SCRUB_CATALOGUE_RESPONSE }),
  )
  await page.route('**/api/v1/scrub/pattern-counts**', (route) =>
    route.fulfill({ json: SCRUB_PATTERN_COUNTS }),
  )
  await page.route('**/api/v1/scrub/posture**', (route) =>
    route.fulfill({ json: SCRUB_POSTURE }),
  )
}
