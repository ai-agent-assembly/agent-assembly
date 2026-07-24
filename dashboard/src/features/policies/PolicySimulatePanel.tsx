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
  const dialogRef = useRef<HTMLDialogElement>(null)
  const firstFieldRef = useRef<HTMLInputElement>(null)
  const [agentId, setAgentId] = useState('research-bot-04')
  const [tool, setTool] = useState('')
  const [target, setTarget] = useState('')
  const { mutate, data, error, isPending, reset } = useSimulatePolicy()

  // Drive the native <dialog> as a true modal: showModal() puts it in the top
  // layer and gives us the ::backdrop, focus-trap, and Esc-to-close for free.
  // The methods are optional-chained because jsdom (the test env) does not
  // implement showModal/close — there the element still mounts, which is all
  // the unit tests assert on; real modal behavior is exercised in Playwright.
  useEffect(() => {
    if (!open) return
    const dialog = dialogRef.current
    dialog?.showModal?.()
    firstFieldRef.current?.focus()
    return () => dialog?.close?.()
  }, [open])

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
    <dialog
      ref={dialogRef}
      className="policy-simulate"
      aria-label="Policy simulator"
      data-testid="policy-simulate"
      onCancel={(e) => {
        // Esc triggers the dialog's native `cancel`; route it through the
        // parent's dismiss handler (which unmounts us) instead of letting the
        // browser close the element out from under React, so the parent stays
        // the single owner of open/closed state.
        e.preventDefault()
        onClose()
      }}
      onClick={(e) => {
        // A modal <dialog> centres its own box; the surrounding ::backdrop
        // still reports clicks on the dialog element. Treat a click that lands
        // outside the box's bounds as a backdrop dismiss, mirroring the prior
        // click-outside behaviour without a non-semantic wrapper.
        const box = e.currentTarget.getBoundingClientRect()
        const outside =
          e.clientX < box.left ||
          e.clientX > box.right ||
          e.clientY < box.top ||
          e.clientY > box.bottom
        if (outside) onClose()
      }}
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
    </dialog>,
    document.body,
  )
}
