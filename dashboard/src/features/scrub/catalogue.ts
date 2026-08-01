/**
 * Joining the served catalogue to the dashboard's local preview metadata
 * (AAASM-5347).
 *
 * `GET /api/v1/scrub/patterns` serves four facts per detector — kind, category,
 * severity, redaction label — and is the authority for *which* detectors the
 * gateway scanner enforces. It does not serve, and cannot serve, the two things
 * the page also shows: prose describing how a kind is detected, and the regex
 * the browser uses to approximate it in the local payload preview. Those live in
 * `detectors.ts`, transcribed from `aa-security/src/scanner.rs`.
 *
 * The join is therefore deliberately one-directional:
 *
 *  - **The API decides membership.** A kind the API omits does not appear, even
 *    if `detectors.ts` still carries a row for it — that is how `Custom`, which
 *    is policy-defined rather than built in, correctly drops out of the table.
 *  - **A kind with no local row still renders.** Its identity, category,
 *    severity and label come from the API; its prose and preview render as
 *    explicit absences. Dropping it would hide a shipped detector from an
 *    operator because the *dashboard* is out of date, which is the same class of
 *    untruth as inventing one.
 *  - **Local rows never contribute a value the API also serves.** In particular
 *    the redaction label is taken from the response, not re-derived, so the page
 *    cannot teach a label the gateway does not emit (the AAASM-5156 defect).
 */
import { BUILT_IN_DETECTORS } from './detectors'
import type { ScrubPatternRow } from './api'
import type { ScrubCatalogueEntry, ScrubDetector } from './types'

/** Local preview metadata indexed by `CredentialKind`, built once. */
const LOCAL_BY_KIND: ReadonlyMap<string, ScrubDetector> = new Map(
  BUILT_IN_DETECTORS.map((d) => [d.id, d]),
)

export function toCatalogueEntry(row: ScrubPatternRow): ScrubCatalogueEntry {
  return {
    kind: row.kind,
    category: row.category,
    severity: row.severity,
    redactionLabel: row.redaction_label,
    builtin: row.builtin,
    local: LOCAL_BY_KIND.get(row.kind),
  }
}

/** Join a served catalogue, preserving the scanner's declaration order. */
export function toCatalogue(rows: readonly ScrubPatternRow[]): readonly ScrubCatalogueEntry[] {
  return rows.map(toCatalogueEntry)
}

/**
 * Display name for a row.
 *
 * Falls back to the kind itself rather than to a prettified guess: the kind is
 * the identity the gateway emits in `[REDACTED:<kind>]` and in an alert's
 * `detected_pattern_type`, so showing it verbatim is always correct, whereas
 * inventing "Aws Access Key" from `AwsAccessKey` would be the dashboard
 * asserting a name nothing gave it.
 */
export function entryName(entry: ScrubCatalogueEntry): string {
  return entry.local?.name ?? entry.kind
}

/**
 * CSS-safe slug for a served category or severity.
 *
 * The API spells categories `api_key`; the surface's stylesheets have keyed off
 * the hyphenated form since AAASM-5156. This normalises for the class name only
 * — the value shown to the operator stays exactly what the API sent.
 */
export function classSlug(value: string): string {
  return value.replaceAll('_', '-')
}
