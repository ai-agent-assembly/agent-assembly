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
 * ## What renders now
 *
 * One figure has a production source and one only: the fleet 24h redaction count
 * from `GET /api/v1/analytics/agent-enforcement` (`openapi/v1.yaml:1102`, shipped
 * under AAASM-5084) — see `features/scrub/api.ts`. It is the sole occupant of the
 * page's only `aria-live` region, so that region announces either a measured
 * number or the reason there is not one, and never an all-clear.
 *
 * Everything else the strip wants to say — leak posture, egress coverage, the
 * governing policy, whether scrubbing is on at runtime — has no route in
 * `aa-api` at all (no `scrub`, `dlp`, `redact`, `pattern` or `leak` path exists
 * in `openapi/v1.yaml`) and renders as an explicit absence carrying its reason.
 * That backend gap is AAASM-5174; the detector catalogue's own defects are
 * AAASM-5156.
 *
 * The page's structure, which the design QA called the most faithful port
 * audited, is unchanged: same header, same five-segment strip, same
 * catalogue / detail / diff layout.
 */
import { useContext, useMemo, useState } from 'react'
import { ToastContext } from '../components/ToastContext'
import { TruthfulValue } from '../components/truthfulness'
import { scrubbed24hFromQuery, useScrubbed24hQuery } from '../features/scrub/api'
import { BUILT_IN_DETECTORS, COMPILED_IN_DETECTORS } from '../features/scrub/detectors'
import { SAMPLE_PAYLOAD } from '../features/scrub/fixtures'
import { PatternsLibrary } from '../features/scrub/PatternsLibrary'
import { PatternDetail } from '../features/scrub/PatternDetail'
import { PayloadDiff } from '../features/scrub/PayloadDiff'
import {
  LEAK_POSTURE,
  SCRUBBING_RUNTIME_STATE,
  SCRUB_COVERAGE,
  SCRUB_POLICY,
} from '../features/scrub/posture'
import { countMatchesByDetector, tokenize } from '../features/scrub/tokenize'
import './ScrubPage.css'

/** First row of the catalogue, so the detail panel always has a subject. */
const DEFAULT_DETECTOR_ID = BUILT_IN_DETECTORS[0].id

export function ScrubPage() {
  const [selectedId, setSelectedId] = useState<string>(DEFAULT_DETECTOR_ID)
  const [payload, setPayload] = useState<string>(SAMPLE_PAYLOAD)
  const [detailCollapsed, setDetailCollapsed] = useState<boolean>(false)

  const tokens = useMemo(() => tokenize(payload), [payload])
  const matchCounts = useMemo(() => countMatchesByDetector(tokens), [tokens])

  const scrubbedQuery = useScrubbed24hQuery()
  const scrubbed24h = scrubbed24hFromQuery(scrubbedQuery)

  const selected = BUILT_IN_DETECTORS.find((d) => d.id === selectedId) ?? BUILT_IN_DETECTORS[0]

  // Nullable so the page still renders (and these controls no-op) outside a
  // ToastProvider — e.g. in isolated component tests.
  const toast = useContext(ToastContext)?.toast

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
            reaches external endpoints. {COMPILED_IN_DETECTORS.length} detectors
            ship with the gateway scanner; the API reports neither which of them
            are running nor how often each fires.
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
            title="No endpoint serves the effective scrubber configuration, so there is nothing to export (AAASM-5174)."
          >
            ⏏ export config
          </button>
        </div>
      </header>

      {/*
        Deliberately NOT a live region. Four of these five segments are static
        statements about what the API cannot answer; announcing them as status
        updates is how the fabricated all-clear reached assistive tech in the
        first place. Only the fetched figure below is live.
      */}
      <div className="scrub-stats" aria-label="scrubbing posture">
        <span className="scrub-stats-item" data-testid="scrub-stats-posture">
          leak posture (30d):{' '}
          <TruthfulValue value={LEAK_POSTURE} showLabel testId="scrub-stats-posture-value" />
        </span>
        <span className="scrub-stats-divider" />
        <span
          className="scrub-stats-scrubbed"
          data-testid="scrub-stats-stripped"
          role="status"
          aria-live="polite"
        >
          redactions / 24h:{' '}
          <TruthfulValue value={scrubbed24h} showLabel testId="scrub-stats-stripped-value" />
        </span>
        <span className="scrub-stats-divider" />
        <span data-testid="scrub-stats-detectors">
          {COMPILED_IN_DETECTORS.length} detectors shipped · running:{' '}
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

      <div className="scrub-body">
        <PatternsLibrary
          detectors={BUILT_IN_DETECTORS}
          selectedId={selected.id}
          onSelect={setSelectedId}
          matchCounts={matchCounts}
        />

        <div className="scrub-right">
          <PatternDetail
            detector={selected}
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
    </main>
  )
}
