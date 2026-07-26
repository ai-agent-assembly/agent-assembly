/**
 * Detail panel for one detector (AAASM-5156 / AAASM-5174).
 *
 * Three changes of substance:
 *
 *  - **`regex` became `detected by`.** The scanner is Aho-Corasick over literal
 *    prefixes plus entropy scoring, not a regex engine. Showing a regex as *the*
 *    detector taught an implementation the gateway does not have; the panel now
 *    states how the kind is really detected and shows the browser-side
 *    approximation separately, labelled as an approximation — or an explicit
 *    absence where the browser has none.
 *  - **`replaced with` shows the label the gateway actually emits** —
 *    `[REDACTED:<CredentialKind>]`, derived from the id so the two cannot
 *    disagree. The previous panel taught labels such as `[REDACTED:PEM]` that
 *    `aa-security` never writes, against ADR 0015's contract.
 *  - **"test on traffic" and "disable" are disabled.** The first toasted
 *    "Tested {id} against the last 24h of traffic" when nothing was tested — the
 *    page reporting a result for an action it never performed. The second
 *    claimed a per-detector switch that does not exist. Neither has a production
 *    path, so neither is offered as if it does; both stay visible, disabled, and
 *    say why rather than vanishing without explanation.
 */
import { TruthfulValue } from '../../components/truthfulness'
import { absent, known } from '../../lib/truthfulness'
import type { ScrubDetector } from './types'
import './PatternDetail.css'

export interface PatternDetailProps {
  detector: ScrubDetector
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

export function PatternDetail({
  detector,
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
          <div className="scrub-detail-eyebrow">selected detector · {detector.id}</div>
          <h3 className="scrub-detail-title">
            {detector.name}
            <span
              className={`scrub-detail-cat scrub-detail-cat--${detector.category}`}
              data-testid="scrub-detail-cat"
            >
              {detector.category}
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
              {detector.detection}
            </div>
          </div>
          <div className="scrub-detail-cell">
            <div className="scrub-detail-label">preview approximation</div>
            <div className="scrub-detail-code scrub-detail-code--regex">
              <TruthfulValue
                value={
                  detector.previewRegex === undefined ? NO_PREVIEW : known(detector.previewRegex)
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
              {detector.replace}
            </code>
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
              title="No endpoint tests a detector against recorded traffic (AAASM-5174)."
            >
              test on traffic
            </button>
            <button
              type="button"
              className="scrub-detail-btn scrub-detail-btn--danger"
              data-testid="scrub-detail-disable"
              disabled
              title="The gateway has no per-detector switch: the built-in set is a floor you add to, not a menu you subtract from (AAASM-5174)."
            >
              disable
            </button>
          </div>
          <p className="scrub-detail-actions-note" data-testid="scrub-detail-actions-note">
            Testing a detector, and disabling one individually, have no API behind
            them — both are unavailable (AAASM-5174).
          </p>
        </div>
      )}
    </section>
  )
}
