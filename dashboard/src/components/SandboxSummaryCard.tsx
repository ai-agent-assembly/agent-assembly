import type { MouseEvent } from 'react'
import './SandboxSummaryCard.css'

/**
 * Aggregate counts for the policy's sandbox (observe-mode) window.
 *
 * Each count is the number of shadow audit events the gateway recorded
 * with `dry_run: true` (see AAASM-1564) over the configured window —
 * what *would* have happened under live enforcement.
 */
export interface SandboxSummaryCounts {
  wouldBeDenies: number
  wouldBeRedactions: number
  wouldBePendingApprovals: number
}

/**
 * Most-frequent matched rule across the shadow events in the window,
 * surfaced so operators can see at a glance which rule is generating
 * the bulk of would-be violations.
 */
export interface SandboxSummaryTopRule {
  /** Rule identifier as recorded in `shadow_decision.matched_rule_id`. */
  id: string
  /** Number of shadow events that matched this rule in the window. */
  count: number
}

export interface SandboxSummaryCardProps {
  /** Policy name surfaced in the card title. */
  readonly policyName: string
  /** Window label, e.g. `'last 24h'`. Free-form so callers can swap units. */
  readonly windowLabel?: string
  /** Counts to render in the breakdown. */
  readonly counts: SandboxSummaryCounts
  /** Optional top-rule line. Omits when `undefined`. */
  readonly topRule?: SandboxSummaryTopRule
  /** Fires when the operator clicks "View all events". */
  readonly onViewAllEvents?: () => void
  /** Fires when the operator clicks "Export CSV". */
  readonly onExportCsv?: () => void
  /**
   * Fires when the operator clicks "Enable live enforcement →".
   * Callers should open a confirmation modal before issuing the
   * `enforcement_mode: enforce` policy update.
   */
  readonly onEnableLiveEnforcement?: () => void
}

/**
 * Read-only summary card for the per-policy sandbox / observe-mode window.
 *
 * Renders the three would-be-decision counts (denies / redactions /
 * pending approvals), an optional top-matched-rule line, and three
 * action buttons. The component is purely presentational — all counts,
 * the top rule, and the click handlers come from the caller so the
 * card can be reused on any page that has access to an aggregated
 * `dry_run: true` count.
 *
 * AAASM-1563. The data-source plumbing (`aa-api` aggregation endpoint
 * + dashboard fetcher) lands in a follow-up subtask; this PR ships
 * the primitive only.
 */
export function SandboxSummaryCard({
  policyName,
  windowLabel = 'last 24h',
  counts,
  topRule,
  onViewAllEvents,
  onExportCsv,
  onEnableLiveEnforcement,
}: SandboxSummaryCardProps) {
  function handleClick(handler: (() => void) | undefined) {
    return (event: MouseEvent<HTMLButtonElement>) => {
      event.preventDefault()
      handler?.()
    }
  }

  return (
    <section
      className="sandbox-summary-card"
      data-testid="sandbox-summary-card"
      aria-labelledby="sandbox-summary-card-title"
    >
      <header className="sandbox-summary-card__head">
        <h2 id="sandbox-summary-card-title" className="sandbox-summary-card__title">
          Sandbox Summary
        </h2>
        <p className="sandbox-summary-card__subtitle">
          <span className="sandbox-summary-card__policy">{policyName}</span>
          <span className="sandbox-summary-card__window"> ({windowLabel})</span>
        </p>
      </header>

      <dl className="sandbox-summary-card__counts">
        <div className="sandbox-summary-card__row" data-testid="would-be-denies">
          <dt className="sandbox-summary-card__count">{counts.wouldBeDenies}</dt>
          <dd className="sandbox-summary-card__label">Would-be denies</dd>
        </div>
        <div className="sandbox-summary-card__row" data-testid="would-be-redactions">
          <dt className="sandbox-summary-card__count">{counts.wouldBeRedactions}</dt>
          <dd className="sandbox-summary-card__label">Would-be redactions</dd>
        </div>
        <div className="sandbox-summary-card__row" data-testid="would-be-pending-approvals">
          <dt className="sandbox-summary-card__count">{counts.wouldBePendingApprovals}</dt>
          <dd className="sandbox-summary-card__label">Would-be pending approvals</dd>
        </div>
      </dl>

      {topRule && (
        <p className="sandbox-summary-card__top-rule" data-testid="top-rule">
          Top matched rule: <code>{topRule.id}</code> ({topRule.count}×)
        </p>
      )}

      <div className="sandbox-summary-card__actions">
        <button
          type="button"
          className="sandbox-summary-card__btn"
          onClick={handleClick(onViewAllEvents)}
          disabled={!onViewAllEvents}
        >
          View all events
        </button>
        <button
          type="button"
          className="sandbox-summary-card__btn"
          onClick={handleClick(onExportCsv)}
          disabled={!onExportCsv}
        >
          Export CSV
        </button>
        <button
          type="button"
          className="sandbox-summary-card__btn sandbox-summary-card__btn--enforce"
          onClick={handleClick(onEnableLiveEnforcement)}
          disabled={!onEnableLiveEnforcement}
        >
          Enable live enforcement →
        </button>
      </div>
    </section>
  )
}
