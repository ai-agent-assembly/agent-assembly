/**
 * What the Scrub stat strip is *still* not entitled to say (AAASM-5112 →
 * AAASM-5347).
 *
 * ## Where this started
 *
 * Three of the strip's five segments were string literals rendered inside an
 * `aria-live` region, so a screen-reader user was told a *measured* 30-day DLP
 * posture that had never been measured:
 *
 *   posture: ● 0 leaks (30d)
 *   covers:  http egress · gmail · slack
 *   policy:  P-100 · default-allow with scrub
 *
 * A fabricated all-clear on a security surface is the most damaging untruth the
 * programme can ship, so each became an explicit absence carrying its reason.
 *
 * ## What changed
 *
 * Those absences were justified with "there is no DLP endpoint in `aa-api` at
 * all — no `scrub`, `dlp`, `redact`, `pattern` or `leak` path exists in
 * `openapi/v1.yaml`". **That is no longer true.** AAASM-5174 shipped
 * `/scrub/patterns`, `/scrub/pattern-counts` and `/scrub/posture`, and
 * AAASM-5347 wires the page to all three — see `api.ts`. A page that keeps
 * declining to answer questions the backend can now answer, and justifies the
 * refusal with a premise that has expired, is the mirror image of the original
 * defect and just as misleading.
 *
 * So the two absences that had a source are gone from this module: the effective
 * pattern catalogue and per-detector counts are fetched now. What remains here is
 * only what those three routes genuinely do not carry.
 *
 * They stay module constants rather than inline JSX so a regression test can
 * assert on them directly, and so one grep finds every place the page still
 * declines to answer.
 */
import { absent, type Certain } from '../../lib/truthfulness'

/**
 * Whether any secret *escaped* — reached a destination unredacted.
 *
 * Still `not-supported`, and the reason is now sharper rather than weaker.
 * `GET /api/v1/scrub/posture` does report a windowed figure, but it counts
 * `secret_detected` alerts — payloads the scanner **caught and redacted**. That
 * is a leaks-*intercepted* figure, which the page renders (see `api.ts`
 * `scrubPostureFromQuery`), and it is the opposite question: interceptions are
 * evidence the scrubber worked, not evidence nothing got past it.
 *
 * Nothing in the product measures what got past it — a payload the scanner did
 * not match produces no alert and no audit event distinguishable from ordinary
 * traffic — so no window length and no endpoint can produce this figure. The
 * green dot the design mock showed here can never be earned by counting alerts.
 */
export const LEAK_POSTURE: Certain<string> = absent(
  'not-supported',
  'Nothing measures secrets that reached a destination unredacted; /scrub/posture counts leaks intercepted, which is the opposite question.',
)

/**
 * Which egress channels the scrubber is in front of.
 *
 * None of the three scrub routes carries a channel or transport dimension:
 * `ScrubPattern` is the detector set, and both aggregations are keyed only by
 * credential kind. The interception layer that handled a payload is not recorded
 * on the alert at all.
 */
export const SCRUB_COVERAGE: Certain<string> = absent(
  'not-supported',
  'No endpoint reports which egress channels the scrubber covers; the scrub routes carry no channel dimension.',
)

/**
 * The policy governing scrubbing.
 *
 * `GET /api/v1/policies` lists policy documents, but nothing binds one to this
 * surface: redaction behaviour comes from a `DataPolicy`'s `credential_action`
 * and `sensitive_patterns`, and no API exposes which document is in force for
 * the scrubber. `/scrub/patterns` deliberately serves only the built-in set —
 * `builtin` is always `true` — so it cannot name a policy either. The previous
 * literal named a policy id, `P-100`, that exists nowhere in the product.
 */
export const SCRUB_POLICY: Certain<string> = absent(
  'not-supported',
  'No endpoint reports which policy document governs scrubbing; /scrub/patterns serves only the built-in set.',
)

/**
 * Whether scrubbing is switched on at runtime.
 *
 * `ScannerConfig.disabled` is a real, global kill switch, and it is not readable
 * over HTTP. `/scrub/patterns` reports the detectors the gateway *ships*, not
 * whether the scanner is running — it would serve the same catalogue with the
 * kill switch thrown — so the page can still say what ships and not whether it
 * is enforcing.
 */
export const SCRUBBING_RUNTIME_STATE: Certain<string> = absent(
  'not-supported',
  'The scanner’s global on/off state is not exposed over the API; the catalogue is served identically either way.',
)
