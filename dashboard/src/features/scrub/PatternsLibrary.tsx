/**
 * The effective detector catalogue, rendered read-only from the API
 * (AAASM-5156 / AAASM-5174 / AAASM-5347).
 *
 * ## What this table no longer invents
 *
 *  - **the per-row enable/disable checkbox.** It flipped a boolean in local
 *    React state; nothing was persisted or transmitted, so the page *confirmed*
 *    a change it had not made. It also toggled a concept the product does not
 *    model — `ScannerConfig` offers a global kill switch and additive custom
 *    patterns, not a per-detector switch. Whether it should is ADR 0026
 *    Decision 3 (`Proposed`); this component neither builds nor forecloses that.
 *  - **the fixture hit count.** It used to be a constant per row, then an
 *    explicit absence once AAASM-5156 established no endpoint aggregated by
 *    kind. `GET /api/v1/scrub/pattern-counts` now does, so the column is fetched.
 *
 * ## Why the count column says "alerts" and not "hits" or "findings"
 *
 * This is the correctness constraint of the whole lane. The gateway records one
 * alert per intercepted action and files it under the **first** credential kind
 * it found (`SecretAlert::primary_kind()` → `kinds.first()`), and the handler
 * tallies those alerts by that single kind. An action carrying one AWS key and
 * three e-mail addresses therefore adds one to `AwsAccessKey` and nothing to
 * `EmailAddress`. Calling that column "findings" — or even the design mock's
 * bare "24h" beside a detector name, which reads as "times this detector fired"
 * — would overstate what was measured for the primary kind and understate it to
 * zero for every co-occurring kind. The header, the note and the per-cell
 * tooltip all say "alerts", and the note states the first-kind rule outright.
 *
 * ## Severity is sourced again
 *
 * AAASM-5156 removed the severity column because nothing in the product modelled
 * it and the values shown were the design mock's. `CredentialKind::severity()`
 * models it now and `/scrub/patterns` serves it, so the column is back — with
 * the API's value, not a local table's.
 *
 * The in-sample chip stays: it counts matches in the payload the operator typed
 * into this page, which is a local fact about local input, not a claim about
 * production traffic.
 */
import { useMemo, useState } from 'react'
import { TruthfulValue } from '../../components/truthfulness'
import { certainText, mapCertain, type Certain } from '../../lib/truthfulness'
import { alertsForKind, type PatternAlertTally } from './api'
import { classSlug, entryName } from './catalogue'
import type { ScrubCatalogueEntry } from './types'
import './PatternsLibrary.css'

export interface PatternsLibraryProps {
  /** Rows as `GET /api/v1/scrub/patterns` served them, in scanner order. */
  entries: readonly ScrubCatalogueEntry[]
  /** The windowed alert tally, or its explicit absence. */
  alerts: Certain<PatternAlertTally>
  /** The window the server aggregated over, e.g. `24h`. */
  alertWindow: Certain<string>
  selectedKind: string
  onSelect: (kind: string) => void
  matchCounts: Record<string, number>
}

export function PatternsLibrary({
  entries,
  alerts,
  alertWindow,
  selectedKind,
  onSelect,
  matchCounts,
}: Readonly<PatternsLibraryProps>) {
  const [search, setSearch] = useState('')
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return entries
    return entries.filter(
      (e) => entryName(e).toLowerCase().includes(q) || e.kind.toLowerCase().includes(q),
    )
  }, [entries, search])

  return (
    <section
      className="scrub-patterns"
      aria-label="detector catalogue"
      data-testid="scrub-patterns"
    >
      <header className="scrub-patterns-head">
        <h3 className="scrub-patterns-title">▤ detector catalogue</h3>
        <input
          type="search"
          className="scrub-patterns-search"
          placeholder="search…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="search detectors"
          data-testid="scrub-patterns-search"
        />
      </header>
      <p className="scrub-patterns-note" data-testid="scrub-patterns-note">
        Read-only, served by <code>GET /api/v1/scrub/patterns</code>. The API
        exposes no way to switch a detector on or off, and serves only the
        built-in set — policy-defined patterns are authored in a policy
        document&rsquo;s <code>data.sensitive_patterns</code>.
      </p>
      <p className="scrub-patterns-note" data-testid="scrub-patterns-alerts-note">
        The <b>alerts</b> column counts <em>alerts over the last{' '}
        <TruthfulValue value={alertWindow} testId="scrub-patterns-window" /></em>, not
        findings. One intercepted action raises one alert, filed under the first
        credential kind found in it — so an action carrying an AWS key and three
        e-mail addresses adds one to <code>AwsAccessKey</code> and nothing to{' '}
        <code>EmailAddress</code>.
      </p>
      {/*
        The column's total, placed directly above the column rather than below
        it. Below, it sat at the far end of a 27-row table that scrolls with the
        page — a summary an operator only reaches after passing everything it
        summarises. It is also deliberately not in the stat strip: `total_hits`
        and the strip's `leaks_intercepted` are very nearly the same measurement
        (both count `secret_detected` alerts), so side by side over two different
        windows they read as a discrepancy worth investigating, when the only
        difference is the window.
      */}
      <p className="scrub-patterns-total" data-testid="scrub-patterns-total">
        <TruthfulValue
          value={mapCertain(alerts, (t) => t.totalAlerts)}
          testId="scrub-patterns-total-value"
        />{' '}
        alerts across{' '}
        <TruthfulValue
          value={mapCertain(alerts, (t) => t.byKind.size)}
          testId="scrub-patterns-total-kinds"
        />{' '}
        kinds in the last <TruthfulValue value={alertWindow} testId="scrub-patterns-total-window" />
      </p>
      <div className="scrub-patterns-table-wrap">
        <table className="scrub-patterns-table">
          <thead>
            <tr>
              <th scope="col">detector</th>
              <th scope="col">category</th>
              <th scope="col" className="scrub-patterns-col-sev">
                sev
              </th>
              <th
                scope="col"
                className="scrub-patterns-col-hits"
                title="Alerts raised in the window, counted by each alert's first detected kind — not per-detector findings."
              >
                alerts
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td
                  colSpan={4}
                  className="scrub-patterns-empty"
                  data-testid="scrub-patterns-empty"
                >
                  no detectors match &ldquo;{search}&rdquo;
                </td>
              </tr>
            ) : (
              filtered.map((e) => {
                const active = e.kind === selectedKind
                const matchN = matchCounts[e.kind] ?? 0
                return (
                  <tr
                    key={e.kind}
                    className={`scrub-patterns-row${active ? ' is-active' : ''}`}
                    onClick={() => onSelect(e.kind)}
                    data-testid={`scrub-patterns-row-${e.kind}`}
                  >
                    <td>
                      <div className="scrub-patterns-name">
                        {entryName(e)}
                        {matchN > 0 && (
                          <span
                            className="scrub-patterns-chip"
                            data-testid={`scrub-patterns-matchchip-${e.kind}`}
                          >
                            {matchN} in sample
                          </span>
                        )}
                      </div>
                      <div className="scrub-patterns-id">{e.kind}</div>
                    </td>
                    <td>
                      <span
                        className={`scrub-patterns-cat scrub-patterns-cat--${classSlug(e.category)}`}
                        data-testid={`scrub-patterns-cat-${e.kind}`}
                      >
                        {e.category}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`scrub-patterns-sev scrub-patterns-sev--${classSlug(e.severity)}`}
                        data-testid={`scrub-patterns-sev-${e.kind}`}
                      >
                        ● {e.severity}
                      </span>
                    </td>
                    <td
                      className="scrub-patterns-hits"
                      title={`Alerts in the last ${certainText(alertWindow)} whose first detected kind was ${e.kind}.`}
                    >
                      <TruthfulValue
                        value={alertsForKind(alerts, e.kind)}
                        testId={`scrub-patterns-hits-${e.kind}`}
                      />
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}
