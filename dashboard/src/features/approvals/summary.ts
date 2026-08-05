import { getUrgency } from './urgency'

/**
 * The one field this module reads off an approval — its creation time.
 *
 * Structural, not `Approval`, so the summary is computable from any row that
 * proves `created_at`: the full `Approval` the fetch path carries, and the
 * narrower `ApprovalRow` the Overview card folds through `decodeApprovalList`
 * (AAASM-5380 slice S8), which validates `created_at` and nothing this function
 * does not read. Widening the parameter here rather than the decoded row keeps
 * the absence no wider than the evidence — the row schema still requires only
 * what a surface actually reads.
 */
interface HasCreatedAt {
  readonly created_at: string
}

/**
 * Derived headline for the pending-approvals queue, computed client-side from
 * the already-loaded approval list. Backs the Overview approvals card's
 * "{n} urgent · oldest {age}" sub-line (AAASM-5169).
 *
 * The design mock (`design/v1/hi-fi/overview.jsx:150`) also shows a category
 * tag — "2 urgent (PII)". No field on `ApprovalResponse` classifies an approval
 * as PII (or any category), so that tag is intentionally not derived here:
 * inventing it would assert a classification the data does not support.
 */
export interface ApprovalsSummary {
  /** Approvals in the most-urgent age tier (`getUrgency` === 'high'). */
  urgentCount: number
  /** Age in ms of the oldest approval, or null when the list is empty. */
  oldestAgeMs: number | null
}

export function deriveApprovalsSummary(
  approvals: readonly HasCreatedAt[],
  now: number = Date.now(),
): ApprovalsSummary {
  let urgentCount = 0
  let oldestCreatedMs: number | null = null

  for (const approval of approvals) {
    if (getUrgency(approval.created_at, now) === 'high') urgentCount += 1

    const createdMs = new Date(approval.created_at).getTime()
    if (Number.isNaN(createdMs)) continue
    if (oldestCreatedMs === null || createdMs < oldestCreatedMs) {
      oldestCreatedMs = createdMs
    }
  }

  return {
    urgentCount,
    oldestAgeMs: oldestCreatedMs === null ? null : Math.max(0, now - oldestCreatedMs),
  }
}

const ONE_MINUTE_MS = 60 * 1000
const ONE_HOUR_MS = 60 * ONE_MINUTE_MS
const ONE_DAY_MS = 24 * ONE_HOUR_MS

/**
 * Compact age label — "6m", "2h", "3d" — matching the mock's "oldest 6m" copy.
 * Under a minute reads as "0m" rather than seconds, since the queue age is a
 * coarse triage signal, not a countdown.
 */
export function formatAge(ageMs: number): string {
  if (ageMs >= ONE_DAY_MS) return `${Math.floor(ageMs / ONE_DAY_MS)}d`
  if (ageMs >= ONE_HOUR_MS) return `${Math.floor(ageMs / ONE_HOUR_MS)}h`
  return `${Math.floor(ageMs / ONE_MINUTE_MS)}m`
}

/**
 * The full sub-line for the approvals card given a known, non-empty queue:
 * "{n} urgent · oldest {age}". Callers handle the empty / unknown cases.
 */
export function formatApprovalsSummary(summary: ApprovalsSummary): string | null {
  if (summary.oldestAgeMs === null) return null
  return `${summary.urgentCount} urgent · oldest ${formatAge(summary.oldestAgeMs)}`
}
