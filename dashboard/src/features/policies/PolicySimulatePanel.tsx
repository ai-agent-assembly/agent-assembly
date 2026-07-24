import { useEffect, useRef, useState, type FormEvent } from 'react'
import { createPortal } from 'react-dom'
import { useSimulatePolicy, type SimulatePolicyResponse } from './api'
import './PolicySimulatePanel.css'

interface PolicySimulatePanelProps {
  readonly open: boolean
  readonly onClose: () => void
}

/** Verdict → design-token modifier, matching the hi-fi policy simulator. */
const VERDICT_CLASS: Record<string, string> = {
  allow: 'policy-simulate__verdict--allow',
  narrow: 'policy-simulate__verdict--narrow',
  approval: 'policy-simulate__verdict--approval',
  deny: 'policy-simulate__verdict--deny',
}

function VerdictResult({ result }: Readonly<{ result: SimulatePolicyResponse }>) {
  const verdictClass = VERDICT_CLASS[result.verdict] ?? 'policy-simulate__verdict--na'
  return (
    <div className="policy-simulate__result" data-testid="simulate-result" aria-live="polite">
      <div className="policy-simulate__verdict-row">
        <span
          className={`policy-simulate__verdict ${verdictClass}`}
          data-testid="simulate-verdict"
          data-verdict={result.verdict}
        >
          <span className="policy-simulate__dot" aria-hidden="true" />
          {result.verdict}
        </span>
        {result.redacted ? (
          <span className="policy-simulate__redacted" data-testid="simulate-redacted">
            payload scrubbed
          </span>
        ) : null}
      </div>
      <dl className="policy-simulate__detail">
        <dt>matched rule</dt>
        <dd data-testid="simulate-matched-rule">
          {result.matched_rule ?? <span className="policy-simulate__muted">— none —</span>}
        </dd>
        <dt>reason</dt>
        <dd data-testid="simulate-reason">{result.reason}</dd>
      </dl>
    </div>
  )
}

/**
 * The Policy Simulate panel (AAASM-5037): a self-contained portal modal that
 * submits a hypothetical `(agent, tool, target)` request to the read-only
 * `POST /api/v1/policies/simulate` dry-run and renders the resulting verdict
 * (allow / narrow / approval / deny) plus the matched rule and reason.
 *
 * Token-driven so it themes light/dark automatically. Esc and backdrop click
 * dismiss it; the agent + tool fields are required before a run.
 */
export function PolicySimulatePanel({ open, onClose }: PolicySimulatePanelProps) {
  const firstFieldRef = useRef<HTMLInputElement>(null)
  const [agentId, setAgentId] = useState('research-bot-04')
  const [tool, setTool] = useState('')
  const [target, setTarget] = useState('')
  const { mutate, data, error, isPending, reset } = useSimulatePolicy()

  useEffect(() => {
    if (!open) return
    firstFieldRef.current?.focus()
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onClose()
      }
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [open, onClose])

  // Clear any prior verdict each time the panel is reopened so a stale result
  // never flashes against a fresh request.
  useEffect(() => {
    if (!open) reset()
  }, [open, reset])

  if (!open || typeof document === 'undefined') return null

  const canRun = agentId.trim() !== '' && tool.trim() !== '' && !isPending

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!canRun) return
    mutate({
      agent_id: agentId.trim(),
      tool: tool.trim(),
      target: target.trim() === '' ? undefined : target.trim(),
    })
  }

  return createPortal(
    <div
      className="policy-simulate__backdrop"
      data-testid="policy-simulate-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return
        if (e.key !== 'Enter' && e.key !== ' ') return
        e.preventDefault()
        onClose()
      }}
      role="button"
      tabIndex={-1}
      aria-label="Close simulator"
    >
      <div
        className="policy-simulate"
        role="dialog"
        aria-modal="true"
        aria-label="Policy simulator"
        data-testid="policy-simulate"
      >
        <header className="policy-simulate__head">
          <div>
            <div className="policy-simulate__eyebrow">policy simulator</div>
            <h2 className="policy-simulate__title">Dry-run a request</h2>
          </div>
          <button
            type="button"
            className="policy-simulate__close"
            data-testid="policy-simulate-close"
            onClick={onClose}
            aria-label="Close"
          >
            ✕
          </button>
        </header>

        <p className="policy-simulate__lede">
          Evaluate a hypothetical request against the active policy. Read-only —
          nothing is enforced, recorded, or charged.
        </p>

        <form className="policy-simulate__form" onSubmit={handleSubmit}>
          <label className="policy-simulate__field">
            <span>agent</span>
            <input
              ref={firstFieldRef}
              type="text"
              className="policy-simulate__input"
              data-testid="simulate-agent-input"
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              placeholder="agent id or name"
            />
          </label>
          <label className="policy-simulate__field">
            <span>tool</span>
            <input
              type="text"
              className="policy-simulate__input"
              data-testid="simulate-tool-input"
              value={tool}
              onChange={(e) => setTool(e.target.value)}
              placeholder="e.g. gmail_send, shell"
            />
          </label>
          <label className="policy-simulate__field">
            <span>target</span>
            <input
              type="text"
              className="policy-simulate__input"
              data-testid="simulate-target-input"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="optional — recipient, host, or path"
            />
          </label>
          <button
            type="submit"
            className="policy-simulate__run"
            data-testid="simulate-run-btn"
            disabled={!canRun}
          >
            {isPending ? 'Simulating…' : '▸ Run simulation'}
          </button>
        </form>

        {error ? (
          <div className="policy-simulate__error" data-testid="simulate-error" role="alert">
            Simulation failed. Please try again.
          </div>
        ) : null}
        {data ? <VerdictResult result={data} /> : null}
      </div>
    </div>,
    document.body,
  )
}
