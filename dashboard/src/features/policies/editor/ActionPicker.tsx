import { ACTION_OPTS } from './constants'
import type { ActionKind } from './types'

interface ActionPickerProps {
  value: ActionKind
  onChange: (next: ActionKind) => void
}

function variantClass(id: ActionKind, active: boolean): string {
  if (!active) return 'editor__action-btn'
  if (id === 'deny') return 'editor__action-btn editor__action-btn--active editor__action-btn--deny'
  if (id === 'allow') return 'editor__action-btn editor__action-btn--active editor__action-btn--ok'
  return 'editor__action-btn editor__action-btn--active'
}

/**
 * 5-button segmented control selecting the rule's effect: allow / narrow /
 * approval / scrub→allow / deny. The hint text is exposed as the button's
 * `title` so it appears as a native tooltip on hover.
 */
export function ActionPicker({ value, onChange }: ActionPickerProps) {
  return (
    <div
      className="editor__action-picker"
      role="radiogroup"
      aria-label="rule action"
      data-testid="editor-action-picker"
    >
      {ACTION_OPTS.map((opt) => {
        const active = opt.id === value
        return (
          <button
            key={opt.id}
            type="button"
            role="radio"
            aria-checked={active}
            title={opt.hint}
            className={variantClass(opt.id, active)}
            data-testid={`editor-action-${opt.id}`}
            onClick={() => onChange(opt.id)}
          >
            {opt.label}
          </button>
        )
      })}
    </div>
  )
}
