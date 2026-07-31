import { useState } from 'react'
import { Link } from 'react-router'
import { ACCESS_LOG_AVAILABILITY, type AccessLogFilter } from './accessLog'
import { AccessLogFilterBar } from './AccessLogFilterBar'
import { StatusState } from '../../components/truthfulness'
import './AccessLogPanel.css'

/**
 * The Access Log tab.
 *
 * Renders no rows, because no endpoint reports identity-attributed access
 * events — see `accessLog.ts` for why `GET /api/v1/logs` cannot stand in.
 * The tab itself stays: the 4-tab Identity model is a ratified design decision
 * (ADR-0017 item 19), so the honest render is the tab present and explicitly
 * unanswerable, not the tab quietly removed.
 *
 * The filter bar stays too, but **disabled**. Filtering is an action with no
 * successful production path — there is nothing to narrow — and a live control
 * over an empty surface reads as "no events matched your filter", which is a
 * different and much more reassuring claim than "there is no audit source".
 * Disabled keeps the tab's shape legible without letting it lie.
 */
export function AccessLogPanel() {
  // Held so the bar renders its real (empty) selection rather than a fabricated
  // one; nothing can change it while the bar is disabled.
  const [filter, setFilter] = useState<AccessLogFilter>({})

  return (
    <section className="iam-access-log-panel" data-testid="iam-panel-access-log">
      <h2>Access Log</h2>
      <p className="iam-access-log-panel__intro">
        Identity-scoped audit events — who signed in, from where, and what they
        changed.
      </p>

      <AccessLogFilterBar identities={[]} value={filter} onChange={setFilter} disabled />

      <StatusState
        state={ACCESS_LOG_AVAILABILITY.state}
        testId="access-log-unsupported"
        title="Identity-attributed access events are not available"
        description={
          <>
            The gateway&apos;s audit log records governance decisions per agent
            session. It carries no signing-in identity, no source address, and no
            success or failure outcome, so this tab has no source to draw on.
            Issuing real agent identities is tracked as{' '}
            <span className="iam-access-log-panel__ticket">AAASM-5176</span>, and
            the token-lifecycle events this tab would show are tracked as{' '}
            <span className="iam-access-log-panel__ticket">AAASM-5177</span>.
          </>
        }
        detail={ACCESS_LOG_AVAILABILITY.detail}
        action={
          <Link
            to="/audit"
            className="iam-access-log-panel__audit-link"
            data-testid="access-log-audit-link"
          >
            View the governance audit log →
          </Link>
        }
      />
    </section>
  )
}
