import { useState } from 'react'
import { isOverridableDecision } from './override'
import { OVERRIDABLE_DECISIONS } from './types'
import type { OverridableDecision, Resource, Verb } from './types'
import './BulkActionBar.css'

export interface BulkActionBarProps {
  count: number
  resources: Resource[]
  verb: Verb
  onApply: (args: { resourceId: string; decision: OverridableDecision }) => void
  onClear: () => void
}

/**
 * Why the primary control starts disabled rather than pre-selected (AAASM-5124).
 *
 * An earlier revision pre-selected a decision so that an untouched bar would at
 * least submit something the gateway accepts. Review found that trade backwards:
 * it converted an unconsidered click from a harmless guaranteed-400 into a
 * *successful* bulk write across every selected agent, with no undo in the UI —
 * the FE client exposes no DELETE, though the endpoint has one. There is no
 * default that is safe to apply on a click nobody thought about, so there is no
 * default. The reason is surfaced on the control, matching the disabled-with-a-
 * reason pattern in `components/topology/NodeDetailPanel.tsx`.
 */
export const NO_DECISION_TITLE = 'Select a decision before recording an override'

/**
 * What a capability override actually does, stated where the operator acts.
 *
 * `aa-api/src/routes/capability.rs:32-38`: overrides "have never fed enforcement
 * — the store is read by these four handlers and nothing else — so an override
 * annotates the view without changing what the gateway actually permits."
 * AAASM-5178 is that gap: the control and its success toast both read as though a
 * gateway decision changed. Wiring real enforcement is a separate, larger piece
 * of work (and its own ADR); until then the honest fix is to say plainly what the
 * write does, at the point of action rather than in a footnote.
 */
export const DISPLAY_ONLY_NOTE =
  'Recorded as a dashboard annotation — this does not change what the gateway enforces.'

/** The select's "nothing chosen yet" value; not a member of `Decision`. */
const NO_DECISION = ''

type DecisionChoice = OverridableDecision | typeof NO_DECISION

export function BulkActionBar({ count, resources, verb, onApply, onClear }: Readonly<BulkActionBarProps>) {
  const [resourceId, setResourceId] = useState<string>(resources[0]?.id ?? '')
  const [decision, setDecision] = useState<DecisionChoice>(NO_DECISION)
  const [confirming, setConfirming] = useState(false)

  if (count === 0 || resources.length === 0) return null

  const agentsLabel = `${count} agent${count === 1 ? '' : 's'}`
  const resourceName = resources.find((r) => r.id === resourceId)?.name ?? resourceId

  // Any change to what would be written retracts a pending confirmation, so the
  // confirmation an operator accepts is always the one they were shown.
  const chooseDecision = (raw: string) => {
    setConfirming(false)
    // Parsed, not asserted: an unrecognised value falls back to no-selection,
    // which re-disables the button rather than leaving a stale decision armed.
    setDecision(isOverridableDecision(raw) ? raw : NO_DECISION)
  }

  const chooseResource = (raw: string) => {
    setConfirming(false)
    setResourceId(raw)
  }

  return (
    <section className="cap-bulk" aria-label="bulk override">
      <div className="cap-bulk-row">
        <span className="cap-bulk-count">{agentsLabel} selected</span>
        <span className="cap-bulk-sep">·</span>
        <span className="cap-bulk-label">apply</span>
        <select
          className="cap-bulk-select"
          value={decision}
          onChange={(e) => chooseDecision(e.target.value)}
          aria-label="decision"
        >
          <option value={NO_DECISION}>select a decision</option>
          {OVERRIDABLE_DECISIONS.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
        <span className="cap-bulk-label">for</span>
        <span className="cap-bulk-verb">{verb}</span>
        <span className="cap-bulk-label">on</span>
        <select
          className="cap-bulk-select"
          value={resourceId}
          onChange={(e) => chooseResource(e.target.value)}
          aria-label="resource"
        >
          {resources.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="cap-bulk-btn cap-bulk-btn--primary"
          disabled={decision === NO_DECISION}
          title={decision === NO_DECISION ? NO_DECISION_TITLE : undefined}
          onClick={() => setConfirming(true)}
        >
          Record display-only override
        </button>
        <button type="button" className="cap-bulk-btn" onClick={onClear}>
          Clear
        </button>
      </div>

      {/* `<fieldset>` rather than a div: it carries an implicit `group` role, so
          the label is actually exposed — an aria-label on a role-less div is
          ignored by assistive tech, which would leave the enforcement disclosure
          invisible to exactly the operator it protects. Deliberately not
          `alertdialog`, which would promise modal focus management this does not
          implement. */}
      {confirming && decision !== NO_DECISION && (
        <fieldset className="cap-bulk-confirm" aria-label="confirm override">
          <p className="cap-bulk-confirm-q">
            Record <strong>{decision}</strong> for <strong>{verb}</strong> on{' '}
            <strong>{resourceName}</strong> across <strong>{agentsLabel}</strong>?
          </p>
          <p className="cap-bulk-confirm-note">{DISPLAY_ONLY_NOTE}</p>
          <div className="cap-bulk-confirm-actions">
            <button
              type="button"
              className="cap-bulk-btn cap-bulk-btn--primary"
              onClick={() => {
                setConfirming(false)
                onApply({ resourceId, decision })
              }}
            >
              Confirm
            </button>
            <button type="button" className="cap-bulk-btn" onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
        </fieldset>
      )}
    </section>
  )
}
