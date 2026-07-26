/**
 * What the Scrub stat strip is entitled to say (AAASM-5112).
 *
 * Three of its five segments were string literals rendered inside an
 * `aria-live` region, so a screen-reader user was told a *measured* 30-day DLP
 * posture that had never been measured:
 *
 *   posture: ● 0 leaks (30d)
 *   covers:  http egress · gmail · slack
 *   policy:  P-100 · default-allow with scrub
 *
 * A fabricated all-clear on a security surface is the most damaging untruth the
 * programme can ship, so each is now an explicit absence carrying the reason.
 * They are `not-supported` rather than `unknown` because waiting will not help:
 * there is no DLP endpoint in `aa-api` at all — no `scrub`, `dlp`, `redact`,
 * `pattern` or `leak` path exists in `openapi/v1.yaml`. That gap is owned by
 * AAASM-5174; until it lands, the honest answer is "the backend cannot tell
 * you", not a green dot.
 *
 * They are module constants rather than inline JSX so a regression test can
 * assert on them directly, and so `grep AAASM-5174` finds every place the page
 * declines to answer.
 */
import { absent, type Certain } from '../../lib/truthfulness'

/**
 * Leak posture over a window.
 *
 * Note this is *not* derivable from `GET /api/v1/analytics/agent-enforcement`:
 * that endpoint's `scrubbed` counts redactions the gateway *performed*, which
 * says nothing about secrets that reached a destination unredacted. Nothing
 * measures the latter, so no window length can produce this figure.
 */
export const LEAK_POSTURE: Certain<string> = absent(
  'not-supported',
  'No endpoint computes a leak-posture figure over any window (AAASM-5174).',
)

/** Which egress channels the scrubber is in front of. */
export const SCRUB_COVERAGE: Certain<string> = absent(
  'not-supported',
  'No endpoint reports which egress channels the scrubber covers (AAASM-5174).',
)

/**
 * The policy governing scrubbing.
 *
 * `GET /api/v1/policies` lists policy documents, but nothing binds one to this
 * surface: redaction behaviour comes from a `DataPolicy`'s `credential_action`
 * and `sensitive_patterns`, and no API exposes which document is in force for
 * the scrubber. The previous literal named a policy id — `P-100` — that exists
 * nowhere in the product.
 */
export const SCRUB_POLICY: Certain<string> = absent(
  'not-supported',
  'No endpoint reports which policy document governs scrubbing (AAASM-5174).',
)

/**
 * Whether scrubbing is switched on at runtime.
 *
 * `ScannerConfig.disabled` is a real, global kill switch, and it is not readable
 * over HTTP — so the page can say what the gateway *ships* with, but not whether
 * it is currently running.
 */
export const SCRUBBING_RUNTIME_STATE: Certain<string> = absent(
  'not-supported',
  'The scanner’s global on/off state is not exposed over the API (AAASM-5174).',
)

/**
 * Per-detector hit counts over 24h — no endpoint aggregates by kind.
 *
 * `not-supported` rather than `unknown` even though related raw material is on
 * the wire: `AlertResponse.detected_pattern_type` (`openapi/v1.yaml:4045-4051`,
 * served by `GET /api/v1/alerts`) names the credential kind behind a
 * `secret_detected` alert. It is not a hit count and cannot be summed into one —
 * alerts are rule-triggered and deduped, so one alert can stand for many
 * detections and a detection inside an open dedup window produces no alert at
 * all. Turning that into a per-detector counter needs the aggregation described
 * in AAASM-5174 item 2, not a different fetch here.
 */
export const DETECTOR_HITS_24H: Certain<number> = absent(
  'not-supported',
  'No endpoint reports per-detector hit counts (AAASM-5174).',
)
