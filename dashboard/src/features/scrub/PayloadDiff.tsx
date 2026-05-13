import type { ScrubPattern, ScrubToken } from './types'
import './PayloadDiff.css'

export interface PayloadDiffProps {
  payload: string
  onPayloadChange: (next: string) => void
  tokens: ScrubToken[]
  patterns: ScrubPattern[]
  matchCounts: Record<string, number>
}

function severityClass(s: ScrubPattern['severity']): string {
  return `scrub-diff-sev scrub-diff-sev--${s}`
}

export function PayloadDiff({
  payload,
  onPayloadChange,
  tokens,
  patterns,
  matchCounts,
}: PayloadDiffProps) {
  const matchCount = tokens.reduce(
    (n, t) => (t.kind === 'match' ? n + 1 : n),
    0,
  )

  return (
    <div
      className="scrub-diff"
      role="region"
      aria-label="payload diff"
      data-testid="scrub-diff"
    >
      <header className="scrub-diff-headrow">
        <div className="scrub-diff-paneheader scrub-diff-paneheader--raw">
          <span className="scrub-diff-panetitle">▶ raw payload</span>
          <span className="scrub-diff-panesub">(what agent tried to send)</span>
          <span
            className="scrub-diff-chip scrub-diff-chip--danger"
            data-testid="scrub-diff-detected-count"
          >
            {matchCount} secrets detected
          </span>
        </div>
        <div className="scrub-diff-paneheader scrub-diff-paneheader--scrubbed">
          <span className="scrub-diff-panetitle">◀ scrubbed output</span>
          <span className="scrub-diff-panesub">(what reached destination)</span>
          <span className="scrub-diff-chip scrub-diff-chip--ok">safe to forward</span>
        </div>
      </header>

      <div className="scrub-diff-body">
        <div className="scrub-diff-pane scrub-diff-pane--raw">
          <textarea
            className="scrub-diff-textarea"
            value={payload}
            onChange={(e) => onPayloadChange(e.target.value)}
            spellCheck={false}
            aria-label="raw payload (editable)"
            data-testid="scrub-diff-textarea"
          />
          <div className="scrub-diff-preview">
            <div className="scrub-diff-label">highlighted preview</div>
            <pre className="scrub-diff-pre" data-testid="scrub-diff-preview-raw">
              {tokens.map((t, i) =>
                t.kind === 'plain' ? (
                  <span key={i}>{t.text}</span>
                ) : (
                  <span
                    key={i}
                    className="scrub-diff-match"
                    title={`${t.pattern.name} · ${t.pattern.id}`}
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
                <span key={i}>{t.text}</span>
              ) : (
                <span
                  key={i}
                  className="scrub-diff-redacted"
                  title={`replaced by ${t.pattern.id}`}
                  data-testid={`scrub-diff-redacted-${i}`}
                >
                  {t.pattern.replace}
                </span>
              ),
            )}
          </pre>
          <div className="scrub-diff-summary">
            <div className="scrub-diff-label">match summary</div>
            {matchCount === 0 ? (
              <div
                className="scrub-diff-summary-empty"
                data-testid="scrub-diff-summary-empty"
              >
                no secrets matched in this payload
              </div>
            ) : (
              <ul className="scrub-diff-summary-list">
                {Object.entries(matchCounts).map(([id, n]) => {
                  const pat = patterns.find((p) => p.id === id)
                  if (!pat) return null
                  return (
                    <li
                      key={id}
                      className="scrub-diff-summary-row"
                      data-testid={`scrub-diff-summary-${id}`}
                    >
                      <span>
                        <span className={severityClass(pat.severity)}>●</span>{' '}
                        {pat.name}{' '}
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
    </div>
  )
}
