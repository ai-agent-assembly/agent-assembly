import { useState, type FormEvent } from 'react'
import {
  APPROVER_QUORUM_OPTS,
  APPROVER_SLA_OPTS,
  APPROVER_WHO_OPTS,
  SCRUB_PRESETS,
} from './constants'
import type {
  ActionKind,
  ApproverConfig,
  ApproverQuorum,
  ApproverSla,
  ApproverWho,
  ResourceOption,
  RuleDraft,
} from './types'

interface SubClausesProps {
  ruleIndex: number
  rule: RuleDraft
  onChange: (patch: Partial<RuleDraft>) => void
}

const DEFAULT_APPROVER: ApproverConfig = {
  who: 'security-oncall',
  nOfM: '1-of-1',
  sla: '30m',
}

function ChipList({
  values,
  onChange,
  placeholder,
  testid,
}: {
  values: string[]
  onChange: (next: string[]) => void
  placeholder: string
  testid: string
}) {
  const [draft, setDraft] = useState('')

  const handleAdd = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const trimmed = draft.trim()
    if (trimmed.length === 0) return
    if (values.includes(trimmed)) {
      setDraft('')
      return
    }
    onChange([...values, trimmed])
    setDraft('')
  }

  const handleRemove = (target: string) => {
    onChange(values.filter((v) => v !== target))
  }

  return (
    <div className="editor__chip-list" data-testid={testid}>
      {values.map((v, idx) => (
        <span key={v} className="editor__chip-editable">
          <span>{v}</span>
          <button
            type="button"
            className="editor__chip-remove"
            aria-label={`remove ${v}`}
            data-testid={`${testid}-remove-${idx}`}
            onClick={() => handleRemove(v)}
          >
            ✕
          </button>
        </span>
      ))}
      <form className="editor__chip-add-form" onSubmit={handleAdd}>
        <input
          type="text"
          className="editor__chip-add-input"
          placeholder={placeholder}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          data-testid={`${testid}-input`}
        />
        <button type="submit" className="editor__chip-add-btn" data-testid={`${testid}-add`}>
          add
        </button>
      </form>
    </div>
  )
}

function NarrowSubClause({
  resource,
  values,
  onChange,
}: {
  resource: ResourceOption
  values: string[]
  onChange: (next: string[]) => void
}) {
  return (
    <div className="editor__sub-clause" data-testid="editor-narrow">
      <div className="editor__sub-clause-row">
        <span className="editor__clause-label">narrow to</span>
        <ChipList
          values={values}
          onChange={onChange}
          placeholder={`add path for ${resource}…`}
          testid="editor-narrow-paths"
        />
      </div>
      <span className="editor__help-text">
        Calls outside these patterns will be denied. Glob patterns OK (e.g. <code>{'*'}</code>).
      </span>
    </div>
  )
}

function ApprovalSubClause({
  value,
  onChange,
}: {
  value: ApproverConfig
  onChange: (next: ApproverConfig) => void
}) {
  return (
    <div className="editor__sub-clause" data-testid="editor-approver">
      <div className="editor__sub-clause-row">
        <span className="editor__clause-label">approver</span>
        <select
          className="editor__select"
          aria-label="approver who"
          value={value.who}
          onChange={(e) => onChange({ ...value, who: e.target.value as ApproverWho })}
          data-testid="editor-approver-who"
        >
          {APPROVER_WHO_OPTS.map((opt) => (
            <option key={opt} value={opt}>
              who: {opt}
            </option>
          ))}
        </select>
        <select
          className="editor__select"
          aria-label="approver quorum"
          value={value.nOfM}
          onChange={(e) => onChange({ ...value, nOfM: e.target.value as ApproverQuorum })}
          data-testid="editor-approver-quorum"
        >
          {APPROVER_QUORUM_OPTS.map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
        <select
          className="editor__select"
          aria-label="approver SLA"
          value={value.sla}
          onChange={(e) => onChange({ ...value, sla: e.target.value as ApproverSla })}
          data-testid="editor-approver-sla"
        >
          {APPROVER_SLA_OPTS.map((opt) => (
            <option key={opt} value={opt}>
              SLA: {opt}
            </option>
          ))}
        </select>
      </div>
      <span className="editor__help-text">timeout → fall through to <strong>deny</strong></span>
    </div>
  )
}

function ScrubSubClause({
  value,
  onChange,
}: {
  value: string[]
  onChange: (next: string[]) => void
}) {
  const toggle = (preset: string) => {
    if (value.includes(preset)) {
      onChange(value.filter((v) => v !== preset))
    } else {
      onChange([...value, preset])
    }
  }
  return (
    <div className="editor__sub-clause" data-testid="editor-scrub">
      <div className="editor__sub-clause-row">
        <span className="editor__clause-label">scrub</span>
        <div className="editor__chip-list">
          {SCRUB_PRESETS.map((preset) => {
            const active = value.includes(preset)
            return (
              <button
                key={preset}
                type="button"
                aria-pressed={active}
                className={
                  active
                    ? 'editor__tag-toggle editor__tag-toggle--active'
                    : 'editor__tag-toggle'
                }
                data-testid={`editor-scrub-${preset.replace(/\s+/g, '-')}`}
                onClick={() => toggle(preset)}
              >
                {active ? '✓ ' : '+ '}
                {preset}
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function ExceptionsSubClause({
  values,
  onChange,
}: {
  values: string[]
  onChange: (next: string[]) => void
}) {
  return (
    <div className="editor__sub-clause" data-testid="editor-except">
      <div className="editor__sub-clause-row">
        <span className="editor__clause-label">except</span>
        <ChipList
          values={values}
          onChange={onChange}
          placeholder="add allow-list entry…"
          testid="editor-except-list"
        />
      </div>
      <span className="editor__help-text">
        {values.length === 0
          ? 'No exceptions — rule applies universally.'
          : `${values.length} call(s) matching these will pass through unaffected.`}
      </span>
    </div>
  )
}

/**
 * Renders the sub-clauses that depend on the rule's selected action:
 *
 *   - allow:            (none)
 *   - narrow:           narrow paths + except list
 *   - approval:         approver row + except list
 *   - scrub-then-allow: scrub tags + except list
 *   - deny:             except list only
 */
export function SubClauses({ ruleIndex: _ruleIndex, rule, onChange }: SubClausesProps) {
  const action: ActionKind = rule.action

  return (
    <>
      {action === 'narrow' ? (
        <NarrowSubClause
          resource={rule.resource}
          values={rule.narrowPaths ?? []}
          onChange={(narrowPaths) => onChange({ narrowPaths })}
        />
      ) : null}

      {action === 'approval' ? (
        <ApprovalSubClause
          value={rule.approver ?? DEFAULT_APPROVER}
          onChange={(approver) => onChange({ approver })}
        />
      ) : null}

      {action === 'scrub-then-allow' ? (
        <ScrubSubClause
          value={rule.scrubFields ?? []}
          onChange={(scrubFields) => onChange({ scrubFields })}
        />
      ) : null}

      {action !== 'allow' ? (
        <ExceptionsSubClause
          values={rule.exceptions ?? []}
          onChange={(exceptions) => onChange({ exceptions })}
        />
      ) : null}
    </>
  )
}
