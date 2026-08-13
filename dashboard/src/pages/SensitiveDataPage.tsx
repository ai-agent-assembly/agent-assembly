/**
 * Sensitive Data — who attempted what, where it was going, which categories were
 * involved, what Agent Assembly decided, and whether execution actually occurred
 * (AAASM-5360, over the AAASM-5359 routes).
 *
 * ## The three things this page exists to get right
 *
 * **1. Actions and findings are different counts.** One action carrying three
 * findings, two rewritten before it was refused, is `1` action and `3` findings
 * and `2` redaction operations, all true. No figure on this page is rendered
 * without the unit it is counted in — see `CountFigure`, which has no prop that
 * suppresses the noun.
 *
 * **2. `prevention_rate` is structurally zero, and that is not a measurement.**
 * Nothing in this build writes `TransmissionEvidence::NotForwarded`, so ADR 0032
 * §8's four prevention conditions can never all hold (AAASM-5685). The rate is
 * therefore always `0` over a non-empty window, and rendering "0% prevented"
 * alone would say the opposite of what is true. `PreventionPanel` renders it
 * only alongside the unmeasured share, a one-word state badge, a qualifier
 * naming what the number is evidence of, and the cause.
 *
 * **3. A lossy window does not render as a complete one.**
 * `inspection_incomplete_event_count` is surfaced as its own notice, and `total`
 * versus the page length is surfaced as a sentence. Those are the two
 * completeness signals that reach these endpoints; **no response field reports
 * that the window itself was rotated, truncated or partially lost**, so no such
 * claim is made in either direction — the copy says "every recorded action",
 * never "every action".
 *
 * ## Access before figures
 *
 * A `403`, a `503`, a `400` and a `401` are four different facts about the
 * caller or the deployment, and each has a different next step. The page
 * switches on `readAccess` before it renders any panel, so a refusal renders as
 * a refusal — never as an empty chart, which would be a claim about a tenant's
 * data rather than a statement that it was not shown.
 *
 * A consequence worth stating, because it looks like a bug: **changing a filter
 * blanks the page to its loading state** until the summary answers again. Every
 * query gets a new key, the summary becomes pending, and `readAccess` reports
 * `pending`. Keeping the previous figures on screen under the new filter labels
 * would be the alternative, and it would mean showing counts that were measured
 * over a *different* query while the controls claim otherwise. Blanking is the
 * honest option; it is not an oversight.
 *
 * ## Design fidelity
 *
 * `design/v2/hi-fi` has **no** mock for this surface — `data.jsx` there is sample
 * data for the capability matrix, not a page. So the visual vocabulary is taken
 * from the two nearest shipped surfaces (Scrub and Analytics) and every value in
 * `sensitiveData.css` resolves to a token from `src/styles.css`. Stated here as
 * a deliberate deviation rather than left to be discovered.
 */
import { useState } from 'react'
import { StatusState } from '../components/truthfulness'
import { ignorePromise } from '../lib/ignorePromise'
import {
  accessDescription,
  accessIsRetryable,
  accessTitle,
  breakdownFromQuery,
  eventDetailFromQuery,
  eventsFromQuery,
  readAccess,
  summaryFromQuery,
  timeseriesFromQuery,
  topOffendersFromQuery,
  useSensitiveDataBreakdownQuery,
  useSensitiveDataEventQuery,
  useSensitiveDataEventsQuery,
  useSensitiveDataSummaryQuery,
  useSensitiveDataTimeseriesQuery,
  useSensitiveDataTopOffendersQuery,
  type OffenderDimension,
  type TimeseriesBucket,
} from '../features/sensitiveData/api'
import { BreakdownPanel } from '../features/sensitiveData/BreakdownPanel'
import { CountersPanel } from '../features/sensitiveData/CountersPanel'
import { EventDetailPanel } from '../features/sensitiveData/EventDetailPanel'
import { EventsPanel } from '../features/sensitiveData/EventsPanel'
import { ExportPanel } from '../features/sensitiveData/ExportPanel'
import { PreventionPanel } from '../features/sensitiveData/PreventionPanel'
import { SensitiveDataFilterBar } from '../features/sensitiveData/SensitiveDataFilterBar'
import { TopOffendersPanel } from '../features/sensitiveData/TopOffendersPanel'
import { TrendPanel } from '../features/sensitiveData/TrendPanel'
import {
  DEFAULT_FILTERS,
  activeFilterCount,
  clearFilters,
  withFilter,
  type FilterKey,
  type SensitiveDataFilters,
  type SensitiveDataRange,
} from '../features/sensitiveData/filters'
import { formatWindow } from '../features/sensitiveData/format'
import type { MetricDimension } from '../features/sensitiveData/schema'
import { isKnown } from '../lib/truthfulness'
import '../features/sensitiveData/sensitiveData.css'

/**
 * The bucket width paired with each window preset.
 *
 * Chosen so a series is legible rather than so it is fine-grained: `/timeseries`
 * refuses a request needing more than 750 buckets, and a 90-day window at one
 * hour would need 2 160. Refusing here would be a worse experience than the
 * coarser bucket, and the panel states the width it drew.
 */
const BUCKET_FOR_RANGE = new Map<SensitiveDataRange, TimeseriesBucket>([
  ['24h', '1h'],
  ['7d', '6h'],
  ['30d', '1d'],
  ['90d', '1d'],
])

export function SensitiveDataPage() {
  const [filters, setFilters] = useState<SensitiveDataFilters>(DEFAULT_FILTERS)
  const [groupBy, setGroupBy] = useState<MetricDimension>('category')
  const [offenderDimension, setOffenderDimension] = useState<OffenderDimension>('agent')
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null)

  const bucket = BUCKET_FOR_RANGE.get(filters.range) ?? '1d'

  const summaryQuery = useSensitiveDataSummaryQuery(filters)
  const timeseriesQuery = useSensitiveDataTimeseriesQuery(filters, bucket)
  const breakdownQuery = useSensitiveDataBreakdownQuery(filters, groupBy)
  const eventsQuery = useSensitiveDataEventsQuery(filters)
  const offendersQuery = useSensitiveDataTopOffendersQuery(filters, offenderDimension)
  const detailQuery = useSensitiveDataEventQuery(filters, selectedEventId)

  // The summary is the page's access probe: it is the cheapest read, it is
  // subject to exactly the same tenant, scope and projection checks as the
  // others, and its answer is the one that decides whether any figure may be
  // shown at all.
  const access = readAccess(summaryQuery)
  const summary = summaryFromQuery(summaryQuery)
  const activeFilters = activeFilterCount(filters)

  const changeFilters = (next: SensitiveDataFilters) => {
    setFilters(next)
    // A row selected under the previous filters may not be in the new window at
    // all, and its detail request would 404. Closing it is honest; leaving it
    // open would show a detail that the list beneath no longer contains.
    setSelectedEventId(null)
  }

  const header = (
    <header className="sd-page-head">
      <h1>
        Sensitive Data <span className="sd-figure__unit">· detection, decision and evidence</span>
      </h1>
      <p>
        What agents attempted to send, which categories were involved, what was decided, and — where
        anything recorded it — whether transmission was actually prevented. Actions and findings are
        counted separately throughout: one action can carry many findings, and the two are never the
        same number.
        {isKnown(summary) &&
          ` Reading ${formatWindow(summary.value.scope.from_ns, summary.value.scope.to_ns)} for organisation ${summary.value.scope.org_id}.`}
      </p>
    </header>
  )

  if (access.kind !== 'ok') {
    return (
      <main className="sd-page" data-testid="sensitive-data-page" data-access={access.kind}>
        {header}
        <section className="sd-panel">
          <StatusState
            state={access.kind === 'pending' ? 'unknown' : accessTruthState(access.kind)}
            title={accessTitle(access)}
            description={accessDescription(access)}
            testId="sd-access-state"
            action={
              accessIsRetryable(access) ? (
                <button
                  type="button"
                  className="sd-button"
                  data-testid="sd-access-retry"
                  onClick={() => ignorePromise(summaryQuery.refetch())}
                >
                  Retry
                </button>
              ) : undefined
            }
          />
        </section>
      </main>
    )
  }

  return (
    <main className="sd-page" data-testid="sensitive-data-page" data-access="ok">
      {header}

      <SensitiveDataFilterBar
        filters={filters}
        onRangeChange={(range) => changeFilters({ ...filters, range })}
        onFilterChange={(key: FilterKey, value: string) =>
          changeFilters(withFilter(filters, key, value))
        }
        onClear={() => changeFilters(clearFilters(filters))}
      />

      <PreventionPanel summary={summary} />
      <CountersPanel summary={summary} />
      <TrendPanel timeseries={timeseriesFromQuery(timeseriesQuery)} activeFilterCount={activeFilters} />
      <BreakdownPanel
        breakdown={breakdownFromQuery(breakdownQuery)}
        groupBy={groupBy}
        onGroupByChange={setGroupBy}
        activeFilterCount={activeFilters}
      />
      <TopOffendersPanel
        offenders={topOffendersFromQuery(offendersQuery)}
        dimension={offenderDimension}
        onDimensionChange={setOffenderDimension}
        activeFilterCount={activeFilters}
      />
      <EventsPanel
        events={eventsFromQuery(eventsQuery)}
        activeFilterCount={activeFilters}
        selectedEventId={selectedEventId}
        onSelectEvent={setSelectedEventId}
      />
      {selectedEventId !== null && (
        <EventDetailPanel
          detail={eventDetailFromQuery(detailQuery)}
          onClose={() => setSelectedEventId(null)}
        />
      )}
      <ExportPanel filters={filters} />
    </main>
  )
}

/**
 * The truthfulness tone a blocking access state renders in.
 *
 * `not-supported` for a refusal and for an unscoped session — "waiting will not
 * help" is exactly right for both, and neither is a fault in the deployment.
 * `unconfigured` for a projection that is not enabled, which is a real setup
 * gap. `unavailable` only for a request that actually failed.
 */
function accessTruthState(
  kind: 'unauthenticated' | 'forbidden' | 'unscoped' | 'projection-off' | 'failed',
): 'not-supported' | 'unconfigured' | 'unavailable' {
  switch (kind) {
    case 'forbidden':
    case 'unscoped':
    case 'unauthenticated':
      return 'not-supported'
    case 'projection-off':
      return 'unconfigured'
    case 'failed':
      return 'unavailable'
  }
}
