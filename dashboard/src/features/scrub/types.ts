/**
 * Types for the Secret Scrubbing surface (AAASM-5156).
 *
 * These describe the **shipped scanner's detector catalogue**, not an authored
 * pattern list. The distinction is the point of the ticket: the previous shape
 * carried `enabled`, `hits24h` and `severity`, and the page rendered all three
 * as fact. None of them exists behind the product —
 *
 *  - `enabled` — `ScannerConfig` (`aa-security/src/scanner.rs`) has exactly two
 *    knobs: `disabled`, a *global* kill switch, and `custom_patterns`, an
 *    *additive* list. There is no per-detector switch to reflect, so a boolean
 *    here could only ever be a claim the product cannot honour. Whether that
 *    capability should exist is ADR 0026 Decision 3, still `Proposed`; this type
 *    does not prejudge it, it just stops asserting it.
 *  - `hits24h` — no endpoint reports per-detector-kind counts (AAASM-5174
 *    item 2), so the column folds to an absence rather than to a number.
 *  - `severity` — no severity is modelled anywhere in `aa-security`, the alert
 *    store, or the policy document. `category` replaces it: it is read straight
 *    off the scanner source's own section grouping, so it is checkable against a
 *    file rather than invented here.
 */

/**
 * The scanner's own grouping of `CredentialKind`, transcribed from the section
 * comments in `aa-security/src/scanner.rs` (API keys / cloud credentials / auth
 * tokens / database URLs / private keys / PII / generic), plus the one kind the
 * policy layer contributes.
 */
export type ScrubDetectorCategory =
  | 'api-key'
  | 'cloud-credential'
  | 'auth-token'
  | 'database-url'
  | 'private-key'
  | 'pii'
  | 'generic'
  | 'policy-defined'

/** Where a detector comes from: the compiled-in set, or a policy document. */
export type ScrubDetectorOrigin = 'built-in' | 'policy-defined'

export interface ScrubDetector {
  /**
   * `CredentialKind::as_str()` — the exact identity the gateway emits in its
   * `[REDACTED:<kind>]` label and in an alert's `detected_pattern_type`.
   */
  readonly id: string
  /** Human-readable name for the list. Presentation only. */
  readonly name: string
  readonly category: ScrubDetectorCategory
  readonly origin: ScrubDetectorOrigin
  /**
   * How `aa-security` actually detects this kind, in prose — the literal prefix
   * for an Aho-Corasick entry, the heuristic for the rest. Prose rather than a
   * regex because the scanner is not regex-based: presenting a regex as *the*
   * detector would be the same class of untruth this lane is removing.
   */
  readonly detection: string
  /**
   * Exactly `[REDACTED:<id>]`, built by {@link redactionLabel} so it cannot
   * drift from `CredentialFinding::new`'s `format!("[REDACTED:{}]", …)`.
   */
  readonly replace: string
  /**
   * Client-side approximation of the detector, used **only** by the in-page
   * payload preview.
   *
   * `undefined` where a browser regex cannot stand in for the real detector
   * (Shannon-entropy scoring; policy-authored literals the dashboard cannot
   * read). Those detectors still appear in the catalogue — they are part of the
   * shipped set — they simply do not participate in the local preview, and the
   * preview says so rather than implying they found nothing.
   */
  readonly previewRegex?: string
  /** Illustrative literal for the preview. Never a real credential. */
  readonly example?: string
}

/** The redaction label `aa-security` writes for a kind. */
export function redactionLabel(kind: string): string {
  return `[REDACTED:${kind}]`
}

export interface ScrubPlainToken {
  kind: 'plain'
  text: string
}

export interface ScrubMatchToken {
  kind: 'match'
  text: string
  detector: ScrubDetector
}

export type ScrubToken = ScrubPlainToken | ScrubMatchToken
