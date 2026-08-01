/**
 * Secret Scrubbing — the product's data-loss-prevention surface.
 *
 * ## What was wrong (AAASM-5112, release-blocking)
 *
 * The stat strip was opened as `role="status" aria-live="polite"` — semantics
 * the design mock never had, added during the port — and three of its five
 * segments were string literals:
 *
 *     posture: ● 0 leaks (30d)
 *     covers:  http egress · gmail · slack
 *     policy:  P-100 · default-allow with scrub
 *
 * A screen-reader user was therefore told, as live status, a measured 30-day DLP
 * posture that had never been measured, a coverage claim with no source, and a
 * policy id (`P-100`) that exists nowhere in the product. A fabricated
 * *all-clear* on a security surface is the most damaging untruth this programme
 * can ship. The fourth segment, "N stripped / 24h", summed twelve fixture
 * constants and rendered `192` on an install with no traffic at all.
 *
 * ## What was then wrong the other way (AAASM-5347)
 *
 * The fix left the page saying, in present tense, that "no `scrub`, `dlp`,
 * `redact`, `pattern` or `leak` path exists in `openapi/v1.yaml`". AAASM-5174
 * shipped three of them — `/scrub/patterns`, `/scrub/pattern-counts` and
 * `/scrub/posture` — and nothing here was ever wired to them. A page that
 * declines to answer what the backend can answer, and justifies the refusal with
 * an expired premise, is the mirror image of the original defect.
 *
 * ## What renders now
 *
 * Sourced (see `features/scrub/api.ts`):
 *
 *  - the **detector catalogue**, from `GET /api/v1/scrub/patterns` — including
 *    each kind's severity and the exact `[REDACTED:<kind>]` label it emits;
 *  - **per-kind alert counts**, from `GET /api/v1/scrub/pattern-counts`;
 *  - **leaks intercepted** over a window, from `GET /api/v1/scrub/posture`;
 *  - the fleet 24h **redaction count**, from
 *    `GET /api/v1/analytics/agent-enforcement` (AAASM-5084).
 *
 * Still absent, and still saying so: whether any secret *escaped* unredacted (an
 * interception count is the opposite measurement), the leak *rate* (the server
 * reports `rate_computed: false` — no denominator is persisted), egress
 * coverage, the governing policy document, and whether the scanner is switched
 * on at runtime. See `features/scrub/posture.ts` for each reason.
 *
 * ## What an unreadable answer costs (AAASM-5366)
 *
 * A `200` whose body does not match its schema used to be read as if it did, so
 * the first field access threw and the page unmounted — a white screen on the
 * DLP surface, which tells an operator strictly less than an error state does.
 * Each response is now decoded before anything reads it (`features/scrub/
 * schema.ts`), and an unreadable body degrades to the same explicit absence an
 * empty one gets, carrying the field that was wrong.
 *
 * It also degrades *locally*. An unreadable catalogue costs the catalogue, the
 * detail panel and the payload diff — the three things it feeds — and nothing
 * else: the header and the stat strip keep reporting what the other three routes
 * measured. One route answering badly must not take the measurements of the
 * other three off the screen with it.
 *
 * ## Two rules this page must not break
 *
 *  - **Alerts are not findings.** `pattern-counts` tallies one alert per
 *    intercepted action under that alert's *first* detected kind, so the column
 *    is labelled "alerts" and the rule is stated inline. See `PatternsLibrary`.
 *  - **`aria-live` announces measurements only.** Exactly one region is live and
 *    it contains only fetched figures, so assistive tech hears either a measured
 *    number or the reason there is not one — never an all-clear that was not
 *    measured. The unsourced segments sit outside it: announcing static
 *    statements as status updates is how the fabricated all-clear reached
 *    assistive tech in the first place.
 *
 * The page's structure, which the design QA called the most faithful port
 * audited, is otherwise unchanged: same header, same stat strip, same
 * catalogue / detail / diff layout.
 */
import { useContext, useMemo, useState, type ReactNode } from 'react'
import { ErrorState } from '../components/ErrorState'
import { LoadingState } from '../components/LoadingState'
import { ToastContext } from '../components/ToastContext'
import { AbsenceMarker, TruthfulValue } from '../components/truthfulness'
import { ignorePromise } from '../lib/ignorePromise'
import { isKnown, mapCertain } from '../lib/truthfulness'
import {
  alertsForKind,
  formatWindow,
  leakRateFromQuery,
  patternAlertsFromQuery,
  scrubCatalogueFromQuery,
  scrubPostureFromQuery,
  scrubWindowFromQuery,
  scrubbed24hFromQuery,
  useScrubPatternCountsQuery,
  useScrubPatternsQuery,
  useScrubPostureQuery,
  useScrubbed24hQuery,
  type ScrubRange,
} from '../features/scrub/api'
import { toCatalogue } from '../features/scrub/catalogue'
import { SAMPLE_PAYLOAD } from '../features/scrub/fixtures'
import { PatternsLibrary } from '../features/scrub/PatternsLibrary'
import { PatternDetail } from '../features/scrub/PatternDetail'
import { PayloadDiff } from '../features/scrub/PayloadDiff'
import { BUILT_IN_DETECTORS } from '../features/scrub/detectors'
import {
  LEAK_POSTURE,
  SCRUBBING_RUNTIME_STATE,
  SCRUB_COVERAGE,
  SCRUB_POLICY,
} from '../features/scrub/posture'
import { countMatchesByDetector, tokenize } from '../features/scrub/tokenize'
import './ScrubPage.css'

/**
 * The per-kind alert window.
 *
 * `24h` keeps the column comparable with the fleet redaction figure beside it,
 * which `agent-enforcement` only serves for 24h.
 */
const ALERT_RANGE: ScrubRange = '24h'

/** The posture window, matching the 30 days the design mock's strip showed. */
const POSTURE_RANGE: ScrubRange = '30d'

export function ScrubPage() {
  const [selectedKind, setSelectedKind] = useState<string | null>(null)
  const [payload, setPayload] = useState<string>(SAMPLE_PAYLOAD)
  const [detailCollapsed, setDetailCollapsed] = useState<boolean>(false)

  // The in-page preview is a local fact about local input, so it runs off the
  // transcribed detector table rather than the served catalogue: it stays usable
  // while the API is unreachable, and it must not imply the gateway scanned the
  // operator's scratch payload.
  const tokens = useMemo(() => tokenize(payload), [payload])
  const matchCounts = useMemo(() => countMatchesByDetector(tokens), [tokens])

  const patternsQuery = useScrubPatternsQuery()
  const countsQuery = useScrubPatternCountsQuery(ALERT_RANGE)
  const postureQuery = useScrubPostureQuery(POSTURE_RANGE)
  const scrubbedQuery = useScrubbed24hQuery()

  const catalogue = scrubCatalogueFromQuery(patternsQuery)
  const alerts = patternAlertsFromQuery(countsQuery)
  const alertWindow = mapCertain(scrubWindowFromQuery(countsQuery), formatWindow)
  const posture = scrubPostureFromQuery(postureQuery)
  const postureWindow = mapCertain(scrubWindowFromQuery(postureQuery), formatWindow)
  const leakRate = leakRateFromQuery(postureQuery)
  const scrubbed24h = scrubbed24hFromQuery(scrubbedQuery)

  // Nullable so the page still renders (and these controls no-op) outside a
  // ToastProvider — e.g. in isolated component tests.
  const toast = useContext(ToastContext)?.toast

  if (patternsQuery.isPending) {
    return (
      <main className="scrub-page" data-testid="scrub-page">
        <LoadingState page="scrub" />
      </main>
    )
  }

  // How many detectors the gateway reports, stated in two places. Derived from
  // the catalogue rather than counted at the render site so an absent catalogue
  // reaches both of them as an absence instead of as a `0` (AAASM-5366): a page
  // that cannot list the detectors does not thereby know there are none.
  const detectorCount = mapCertain(catalogue, (rows) => rows.length)

  // The catalogue drives the library, the detail panel and the payload diff, so
  // an absent one replaces all three — but only those three. Everything above
  // comes from the other routes and still renders, because losing the whole page
  // to one unreadable response is what AAASM-5366 was filed about: a blank page
  // tells an operator less than a strip of measured figures beside a stated
  // reason does.
  let body: ReactNode
  if (isKnown(catalogue)) {
    const entries = toCatalogue(catalogue.value)
    const selected = entries.find((e) => e.kind === selectedKind) ?? entries[0]
    body = (
      <div className="scrub-body">
        <PatternsLibrary
          entries={entries}
          alerts={alerts}
          alertWindow={alertWindow}
          selectedKind={selected.kind}
          onSelect={setSelectedKind}
          matchCounts={matchCounts}
        />

        <div className="scrub-right">
          <PatternDetail
            entry={selected}
            alerts={alertsForKind(alerts, selected.kind)}
            alertWindow={alertWindow}
            collapsed={detailCollapsed}
            onToggleCollapsed={() => setDetailCollapsed((c) => !c)}
            onEditPatterns={() =>
              toast?.(
                'Add patterns through a policy document’s data.sensitive_patterns; the built-in set is read-only',
                'info',
              )
            }
          />
          <PayloadDiff
            payload={payload}
            onPayloadChange={setPayload}
            tokens={tokens}
            detectors={BUILT_IN_DETECTORS}
            matchCounts={matchCounts}
          />
        </div>
      </div>
    )
  } else if (catalogue.state === 'unavailable') {
    // A failed request gets the retry affordance; a 200 we could not read, and a
    // 200 that carried no detectors, get the absence marker and its reason —
    // "we could not fetch the catalogue", "the catalogue we fetched was
    // impossible" and "the catalogue we fetched was unreadable" are different
    // problems, and only the first is worth retrying.
    body = <ErrorState kind="generic" onRetry={() => ignorePromise(patternsQuery.refetch())} />
  } else {
    body = (
      <div className="scrub-catalogue-absent" data-testid="scrub-catalogue-absent">
        <AbsenceMarker
          state={catalogue.state}
          detail={catalogue.detail}
          showLabel
          testId="scrub-catalogue-absent-marker"
        />
      </div>
    )
  }

  return (
    <main className="scrub-page" data-testid="scrub-page">
      <header className="scrub-page-head">
        <div>
          <h1 className="scrub-page-title">
            Secret Scrubbing{' '}
            <span className="scrub-page-subtitle">· L3 · network-layer sanitization</span>
          </h1>
          <p className="scrub-page-sub" data-testid="scrub-page-sub">
            Patterns redact secrets and PII from agent traffic <em>before</em> it
            reaches external endpoints. The gateway reports{' '}
            <TruthfulValue value={detectorCount} testId="scrub-page-sub-detectors" />{' '}
            built-in detectors; it does not report which of them are running.
          </p>
        </div>
        <div className="scrub-head-actions">
          <button
            type="button"
            className="scrub-head-btn"
            data-testid="scrub-add-pattern"
            onClick={() =>
              toast?.(
                'Custom patterns are authored in a policy document’s data.sensitive_patterns, not here',
                'info',
              )
            }
          >
            + add pattern
          </button>
          <button
            type="button"
            className="scrub-head-btn"
            data-testid="scrub-export-config"
            disabled
            title="/scrub/patterns serves the built-in catalogue, not the effective scrubber configuration, so there is nothing complete to export."
          >
            ⏏ export config
          </button>
        </div>
      </header>

      {/*
        `role="group"` is load-bearing, not decoration: name-from-author is not
        supported on a generic container, so most assistive tech drops the
        `aria-label` on a bare `<div>` and the strip is announced as an unnamed
        run of text. The role is what makes "scrubbing posture" audible.
      */}
      <div className="scrub-stats" role="group" aria-label="scrubbing posture">
        {/*
          The page's only live region, and it holds only fetched figures. The
          segments after it are statements about what the API cannot answer;
          announcing those as status updates is how the fabricated all-clear
          reached assistive tech under AAASM-5112.
        */}
        <span
          className="scrub-stats-measured"
          data-testid="scrub-stats-measured"
          role="status"
          aria-live="polite"
        >
          <span data-testid="scrub-stats-intercepted">
            leaks intercepted (
            <TruthfulValue value={postureWindow} testId="scrub-stats-posture-window" />
            ):{' '}
            <TruthfulValue
              value={mapCertain(posture, (p) => p.leaksIntercepted)}
              showLabel
              testId="scrub-stats-intercepted-value"
            />{' '}
            across{' '}
            <TruthfulValue
              value={mapCertain(posture, (p) => p.distinctKinds)}
              testId="scrub-stats-kinds-value"
            />{' '}
            kinds
          </span>
          <span className="scrub-stats-divider" />
          <span className="scrub-stats-scrubbed" data-testid="scrub-stats-stripped">
            redactions / 24h:{' '}
            <TruthfulValue value={scrubbed24h} showLabel testId="scrub-stats-stripped-value" />
          </span>
        </span>
        <span className="scrub-stats-divider" />
        <span data-testid="scrub-stats-posture">
          escaped-leak posture:{' '}
          <TruthfulValue value={LEAK_POSTURE} showLabel testId="scrub-stats-posture-value" />
        </span>
        <span className="scrub-stats-divider" />
        <span data-testid="scrub-stats-rate">
          leak rate:{' '}
          <TruthfulValue value={leakRate} showLabel testId="scrub-stats-rate-value" />
        </span>
        <span className="scrub-stats-divider" />
        <span data-testid="scrub-stats-detectors">
          <TruthfulValue value={detectorCount} testId="scrub-stats-detectors-value" />{' '}
          detectors served · running:{' '}
          <TruthfulValue
            value={SCRUBBING_RUNTIME_STATE}
            showLabel
            testId="scrub-stats-running-value"
          />
        </span>
        <span className="scrub-stats-divider" />
        <span data-testid="scrub-stats-covers">
          covers:{' '}
          <TruthfulValue value={SCRUB_COVERAGE} showLabel testId="scrub-stats-covers-value" />
        </span>
        <span className="scrub-stats-policy" data-testid="scrub-stats-policy">
          policy:{' '}
          <TruthfulValue value={SCRUB_POLICY} showLabel testId="scrub-stats-policy-value" />
        </span>
      </div>

      {body}
    </main>
  )
}
