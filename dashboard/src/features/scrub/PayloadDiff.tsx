/**
 * Raw-versus-scrubbed preview of a payload the operator types (AAASM-5156).
 *
 * The panel's promise used to be "what reached destination", stamped with an
 * unconditional **"safe to forward"** chip. Nothing here scans anything: the
 * matching is a browser-regex approximation (`tokenize`) of a scanner that is
 * Aho-Corasick plus entropy scoring, running over text that never left the
 * page. Declaring that text safe is exactly the move the truthfulness rule
 * forbids — an unmeasured input rendered as a legitimate, reassuring outcome.
 *
 * So the framing is now what it actually is: a local approximation of the
 * gateway's redaction, over sample input, with the detectors it cannot
 * approximate named rather than silently absent. The redaction labels are the
 * ones `aa-security` really emits, so the panel still teaches the correct
 * contract — which was the reason the panel existed.
 */
import { UNPREVIEWABLE_DETECTORS } from './detectors'
import type { ScrubDetector, ScrubToken } from './types'
import './PayloadDiff.css'

export interface PayloadDiffProps {
  payload: string
  onPayloadChange: (next: string) => void
  tokens: readonly ScrubToken[]
  detectors: readonly ScrubDetector[]
  matchCounts: Record<string, number>
}

function categoryClass(c: ScrubDetector['category']): string {
  return `scrub-diff-cat scrub-diff-cat--${c}`
}

export function PayloadDiff({
  payload,
  onPayloadChange,
  tokens,
  detectors,
  matchCounts,
}: Readonly<PayloadDiffProps>) {
  const matchCount = tokens.reduce((n, t) => (t.kind === 'match' ? n + 1 : n), 0)

  // Stable per-token keys derived from the running character offset within the
  // payload, so React reconciliation does not rely on the array index. Built
  // with reduce so no variable is reassigned during render.
  const tokenKeys = tokens.reduce<{ keys: string[]; offset: number }>(
    (acc, t) => {
      acc.keys.push(`${acc.offset}-${t.kind}`)
      return { keys: acc.keys, offset: acc.offset + t.text.length }
    },
    { keys: [], offset: 0 },
  ).keys

  return (
    <section className="scrub-diff" aria-label="payload preview" data-testid="scrub-diff">
      <header className="scrub-diff-headrow">
        <div className="scrub-diff-paneheader scrub-diff-paneheader--raw">
          <span className="scrub-diff-panetitle">▶ sample payload</span>
          <span className="scrub-diff-panesub">(editable — never leaves this page)</span>
          <span
            className="scrub-diff-chip scrub-diff-chip--danger"
            data-testid="scrub-diff-detected-count"
          >
            {matchCount} matched in sample
          </span>
        </div>
        <div className="scrub-diff-paneheader scrub-diff-paneheader--scrubbed">
          <span className="scrub-diff-panetitle">◀ approximated output</span>
          <span className="scrub-diff-panesub">(local preview, not a gateway scan)</span>
          <span className="scrub-diff-chip scrub-diff-chip--neutral" data-testid="scrub-diff-scope">
            approximation
          </span>
        </div>
      </header>

      <p className="scrub-diff-caveat" data-testid="scrub-diff-caveat">
        This preview approximates the gateway&apos;s redaction in the browser; it
        does not call the scanner, and no payload here is sent anywhere. It cannot
        stand in for {UNPREVIEWABLE_DETECTORS.map((d) => d.id).join(' or ')}, so a
        clean preview is not a verdict that a payload is safe to forward.
      </p>

      <div className="scrub-diff-body">
        <div className="scrub-diff-pane scrub-diff-pane--raw">
          <textarea
            className="scrub-diff-textarea"
            value={payload}
            onChange={(e) => onPayloadChange(e.target.value)}
            spellCheck={false}
            aria-label="sample payload (editable)"
            data-testid="scrub-diff-textarea"
          />
          <div className="scrub-diff-preview">
            <div className="scrub-diff-label">highlighted preview</div>
            <pre className="scrub-diff-pre" data-testid="scrub-diff-preview-raw">
              {tokens.map((t, i) =>
                t.kind === 'plain' ? (
                  <span key={tokenKeys[i]}>{t.text}</span>
                ) : (
                  <span
                    key={tokenKeys[i]}
                    className="scrub-diff-match"
                    title={`${t.detector.name} · ${t.detector.id}`}
                    data-testid={`scrub-diff-match-${i}`}
                  >
                    {t.text}
                  </span>
                ),
              )}
            </pre>
          </div>
        </div>

        <div className="scrub-diff-pane scrub-diff-pane--scrubbed">
          <pre className="scrub-diff-pre" data-testid="scrub-diff-preview-scrubbed">
            {tokens.map((t, i) =>
              t.kind === 'plain' ? (
                <span key={tokenKeys[i]}>{t.text}</span>
              ) : (
                <span
                  key={tokenKeys[i]}
                  className="scrub-diff-redacted"
                  title={`replaced by ${t.detector.id}`}
                  data-testid={`scrub-diff-redacted-${i}`}
                >
                  {t.detector.replace}
                </span>
              ),
            )}
          </pre>
          <div className="scrub-diff-summary">
            <div className="scrub-diff-label">match summary</div>
            {matchCount === 0 ? (
              <div className="scrub-diff-summary-empty" data-testid="scrub-diff-summary-empty">
                no detector this preview can approximate matched this sample
              </div>
            ) : (
              <ul className="scrub-diff-summary-list">
                {Object.entries(matchCounts).map(([id, n]) => {
                  const det = detectors.find((d) => d.id === id)
                  if (!det) return null
                  return (
                    <li
                      key={id}
                      className="scrub-diff-summary-row"
                      data-testid={`scrub-diff-summary-${id}`}
                    >
                      <span>
                        <span className={categoryClass(det.category)}>●</span> {det.name}{' '}
                        <span className="scrub-diff-summary-id">{id}</span>
                      </span>
                      <span className="scrub-diff-summary-count">×{n}</span>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        </div>
      </div>
    </section>
  )
}
