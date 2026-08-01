/**
 * Detail panel for one detector (AAASM-5156 / AAASM-5174 / AAASM-5347).
 *
 * ## What the panel sources, and from where
 *
 * The subject is now a `ScrubCatalogueEntry` — a row of
 * `GET /api/v1/scrub/patterns` joined to whatever local preview metadata the
 * dashboard has for that kind. Identity, category, severity and the redaction
 * label come off the response; only the two things the API does not serve —
 * prose describing how the kind is detected, and the browser-side approximation
 * used by the in-page preview — come from `detectors.ts`, and each renders as an
 * explicit absence when the dashboard has no transcription for a served kind.
 *
 * ## What stays removed
 *
 *  - **`regex` is still not presented as *the* detector.** The scanner is
 *    Aho-Corasick over literal prefixes plus entropy scoring, not a regex engine.
 *    The panel states how the kind is really detected and shows the browser
 *    approximation separately, labelled as an approximation.
 *  - **`replaced with` is the label the gateway actually emits.** It is read from
 *    the response's `redaction_label` rather than rebuilt locally, so the panel
 *    cannot drift back to teaching labels such as `[REDACTED:PEM]` that
 *    `aa-security` never writes, against ADR 0015's contract.
 *  - **"test on traffic" and "disable" stay disabled.** The first toasted
 *    "Tested {id} against the last 24h of traffic" when nothing was tested — the
 *    page reporting a result for an action it never performed. The second claimed
 *    a per-detector switch that does not exist. Neither has a production path,
 *    and none of the three routes AAASM-5174 shipped provides one, so both stay
 *    visible, disabled, and say why rather than vanishing without explanation.
 */
import { TruthfulValue } from '../../components/truthfulness'
import { absent, known, type Certain } from '../../lib/truthfulness'
import { classSlug, entryName } from './catalogue'
import type { ScrubCatalogueEntry } from './types'
import './PatternDetail.css'

export interface PatternDetailProps {
  entry: ScrubCatalogueEntry
  /** Alerts in the window whose first detected kind was this one. */
  alerts: Certain<number>
  /** The window the alert figure covers, e.g. `24h`. */
  alertWindow: Certain<string>
  collapsed: boolean
  onToggleCollapsed: () => void
  /** Optional so the component renders standalone; the action row no-ops when absent. */
  onEditPatterns?: () => void
}

/** Why the browser has no stand-in for a detector, phrased for an operator. */
const NO_PREVIEW = absent<string>(
  'not-supported',
  'This detector cannot be approximated in the browser, so the local preview does not stand in for it.',
)

/**
 * Why the panel cannot say how a served kind is detected.
 *
 * Reachable only when the scanner ships a `CredentialKind` the dashboard has not
 * transcribed. `unknown` rather than `not-supported`: the answer exists in
 * `aa-security`, this build simply does not carry it, so a later dashboard will.
 */
const NO_DETECTION_PROSE = absent<string>(
  'unknown',
  'This dashboard build has no transcription of how the gateway detects this kind.',
)

export function PatternDetail({
  entry,
  alerts,
  alertWindow,
  collapsed,
  onToggleCollapsed,
  onEditPatterns,
}: Readonly<PatternDetailProps>) {
  return (
    <section
      className="scrub-detail"
      aria-label="selected detector detail"
      data-testid="scrub-detail"
      data-collapsed={collapsed}
    >
      <header className="scrub-detail-head">
        <div className="scrub-detail-headings">
          <div className="scrub-detail-eyebrow">selected detector · {entry.kind}</div>
          <h3 className="scrub-detail-title">
            {entryName(entry)}
            <span
              className={`scrub-detail-cat scrub-detail-cat--${classSlug(entry.category)}`}
              data-testid="scrub-detail-cat"
            >
              {entry.category}
            </span>
            <span
              className={`scrub-detail-sev scrub-detail-sev--${classSlug(entry.severity)}`}
              data-testid="scrub-detail-sev"
            >
              ● {entry.severity}
            </span>
          </h3>
        </div>
        <button
          type="button"
          className="scrub-detail-collapse-btn"
          onClick={onToggleCollapsed}
          aria-expanded={!collapsed}
          data-testid="scrub-detail-collapse"
        >
          {collapsed ? '+ expand' : '− collapse'}
        </button>
      </header>

      {!collapsed && (
        <div className="scrub-detail-grid" data-testid="scrub-detail-body">
          <div className="scrub-detail-cell">
            <div className="scrub-detail-label">detected by</div>
            <div className="scrub-detail-prose" data-testid="scrub-detail-detection">
              <TruthfulValue
                value={
                  entry.local === undefined ? NO_DETECTION_PROSE : known(entry.local.detection)
                }
                showLabel
                testId="scrub-detail-detection-value"
              />
            </div>
          </div>
          <div className="scrub-detail-cell">
            <div className="scrub-detail-label">preview approximation</div>
            <div className="scrub-detail-code scrub-detail-code--regex">
              <TruthfulValue
                value={
                  entry.local?.previewRegex === undefined
                    ? NO_PREVIEW
                    : known(entry.local.previewRegex)
                }
                showLabel
                testId="scrub-detail-preview-regex"
              />
            </div>
          </div>
          <div className="scrub-detail-cell">
            <div className="scrub-detail-label">replaced with</div>
            <code
              className="scrub-detail-code scrub-detail-code--replace"
              data-testid="scrub-detail-replace"
            >
              {entry.redactionLabel}
            </code>
          </div>
          <div className="scrub-detail-cell">
            <div className="scrub-detail-label">
              alerts / <TruthfulValue value={alertWindow} testId="scrub-detail-window" />
            </div>
            <div className="scrub-detail-prose" data-testid="scrub-detail-alerts">
              <TruthfulValue value={alerts} showLabel testId="scrub-detail-alerts-value" />
            </div>
            <p className="scrub-detail-hint" data-testid="scrub-detail-alerts-hint">
              Alerts, not findings — one per intercepted action, filed under the
              first credential kind found in it.
            </p>
          </div>
        </div>
      )}

      {!collapsed && (
        <div className="scrub-detail-actions" data-testid="scrub-detail-actions">
          <div className="scrub-detail-actions-row">
            <button
              type="button"
              className="scrub-detail-btn"
              data-testid="scrub-detail-edit"
              onClick={onEditPatterns}
            >
              add a policy pattern
            </button>
            <button
              type="button"
              className="scrub-detail-btn"
              data-testid="scrub-detail-test"
              disabled
              title="No endpoint tests a detector against recorded traffic."
            >
              test on traffic
            </button>
            <button
              type="button"
              className="scrub-detail-btn scrub-detail-btn--danger"
              data-testid="scrub-detail-disable"
              disabled
              title="The gateway has no per-detector switch: the built-in set is a floor you add to, not a menu you subtract from."
            >
              disable
            </button>
          </div>
          <p className="scrub-detail-actions-note" data-testid="scrub-detail-actions-note">
            Testing a detector, and disabling one individually, have no API behind
            them — both are unavailable.
          </p>
        </div>
      )}
    </section>
  )
}
