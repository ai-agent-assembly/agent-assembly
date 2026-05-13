import { RES_OPTS, VERB_OPTS, defaultNarrowPaths } from './constants'
import type { ActionKind, ResourceOption, RuleDraft, VerbOption } from './types'
import { ActionPicker } from './ActionPicker'
import { ConditionList } from './ConditionList'
import { SubClauses } from './SubClauses'
import { WindowSeverityRow } from './WindowSeverityRow'

interface RuleCardProps {
  index: number
  rule: RuleDraft
  onChange: (patch: Partial<RuleDraft>) => void
  onDuplicate: () => void
  onRemove: () => void
}

function toggleVerb(current: VerbOption[], verb: VerbOption): VerbOption[] {
  if (current.includes(verb)) return current.filter((v) => v !== verb)
  return [...current, verb]
}

export function RuleCard({ index, rule, onChange, onDuplicate, onRemove }: RuleCardProps) {
  const isDeny = rule.action === 'deny'

  const handleActionChange = (next: ActionKind) => {
    // When switching to "narrow", seed the path list from the resource's
    // default suggestions if the user hasn't typed anything yet.
    if (next === 'narrow' && (!rule.narrowPaths || rule.narrowPaths.length === 0)) {
      onChange({ action: next, narrowPaths: defaultNarrowPaths(rule.resource) })
      return
    }
    onChange({ action: next })
  }

  return (
    <section
      className="editor__section"
      data-testid={`editor-rule-${index}`}
      aria-label={`rule ${index + 1}`}
    >
      <header className="editor__section-head">
        <span className="editor__rule-num">R{index + 1}</span>
        <div className="editor__section-actions">
          <button
            type="button"
            className="editor__btn-sm"
            data-testid={`editor-rule-${index}-duplicate`}
            onClick={onDuplicate}
          >
            duplicate
          </button>
          <button
            type="button"
            className="editor__btn-sm"
            data-testid={`editor-rule-${index}-remove`}
            onClick={onRemove}
          >
            remove
          </button>
        </div>
      </header>

      {/* WHEN clause */}
      <div className="editor__clause">
        <span className="editor__clause-label">when</span>
        <span>resource is</span>
        <select
          className="editor__select"
          aria-label="resource"
          value={rule.resource}
          onChange={(e) => onChange({ resource: e.target.value as ResourceOption })}
          data-testid={`editor-rule-${index}-resource`}
        >
          {RES_OPTS.map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
        <span>and verb is</span>
        <div className="editor__verb-group" role="group" aria-label="verbs">
          {VERB_OPTS.map((verb) => {
            const active = rule.verb.includes(verb)
            return (
              <button
                key={verb}
                type="button"
                aria-pressed={active}
                className={
                  active
                    ? `editor__verb editor__verb--active${isDeny ? ' editor__verb--danger' : ''}`
                    : 'editor__verb'
                }
                data-testid={`editor-rule-${index}-verb-${verb}`}
                onClick={() => onChange({ verb: toggleVerb(rule.verb, verb) })}
              >
                {verb}
              </button>
            )
          })}
        </div>
      </div>

      {/* IF clause */}
      <div className="editor__clause">
        <span className="editor__clause-label">if</span>
      </div>
      <ConditionList
        value={rule.condition}
        onChange={(condition) => onChange({ condition })}
      />

      {/* THEN clause */}
      <div className="editor__clause">
        <span className="editor__clause-label">then</span>
        <ActionPicker value={rule.action} onChange={handleActionChange} />
      </div>

      <SubClauses rule={rule} onChange={onChange} />

      <WindowSeverityRow
        window={rule.timeWindow}
        severity={rule.severity}
        onWindowChange={(timeWindow) => onChange({ timeWindow })}
        onSeverityChange={(severity) => onChange({ severity })}
      />
    </section>
  )
}
