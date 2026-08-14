// Which of the five mutually-exclusive feed surfaces the Alerts tab shows.
//
// Extracted from AlertsPage so the precedence between them lives in one named
// place. The order is the whole point and is load-bearing:
//
//   1. the alerts request FAILED (and is no longer in flight) → say so, and
//      assert nothing at all about alerts;
//   2. no rules are configured → onboarding, not an absence;
//   3. the page matched nothing → an empty answer, scoped to the page;
//   4/5. rows, in the chosen view.
//
// Putting 1 first is the AAASM-5150 fix: an outage evaluated after the
// empty-state check renders as "No alerts in this window" while alerts fire.
// A still-pending request deliberately does NOT take branch 1 — a slow request
// is not a broken one, and rendering a fault tone while data is in flight
// trains operators to ignore fault tones.

import { AlertCardFeed } from './AlertCardFeed'
import { AlertList } from './AlertList'
import { EmptyStateNoAlerts } from './EmptyStateNoAlerts'
import { EmptyStateNoRules } from './EmptyStateNoRules'
import { StatusState } from '../../components/truthfulness'
import { isKnown, type Certain } from '../../lib/truthfulness'
import type { Alert, AlertRule } from './types'

export interface AlertsFeedBodyProps {
  /** The loaded page, or the absence that stands in for it. */
  alerts: Certain<readonly Alert[]>
  /** Whether the alerts request is still in flight (not yet an absence). */
  pending: boolean
  /** Rules loaded successfully and came back empty. */
  noRulesConfigured: boolean
  /** Whether the loaded page provably covers every alert the server has. */
  pageIsWholeFleet: boolean
  /** Rows to render, after every filter. */
  rows: readonly Alert[]
  rulesById: ReadonlyMap<string, AlertRule>
  viewMode: 'table' | 'cards'
  onSelect: (id: string) => void
  onCreateRule: () => void
}

export function AlertsFeedBody({
  alerts,
  pending,
  noRulesConfigured,
  pageIsWholeFleet,
  rows,
  rulesById,
  viewMode,
  onSelect,
  onCreateRule,
}: Readonly<AlertsFeedBodyProps>) {
  if (!isKnown(alerts) && !pending) {
    return (
      <StatusState
        state={alerts.state}
        title="Alerts unavailable"
        description="The alerts list could not be loaded, so this page cannot say whether any alerts are firing."
        detail={alerts.detail}
        testId="alerts-unavailable"
      />
    )
  }
  if (noRulesConfigured) {
    return <EmptyStateNoRules onCreateRule={onCreateRule} />
  }
  if (isKnown(alerts) && rows.length === 0) {
    return <EmptyStateNoAlerts pageScoped={!pageIsWholeFleet} />
  }
  if (viewMode === 'cards') {
    return <AlertCardFeed rows={rows} rulesById={rulesById} onSelect={onSelect} />
  }
  return <AlertList rows={rows} onSelect={onSelect} loading={pending && rows.length === 0} />
}
