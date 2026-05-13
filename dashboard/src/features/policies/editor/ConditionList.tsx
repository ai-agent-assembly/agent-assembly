import { COND_PRESETS } from './constants'
import type { ConditionPreset } from './types'

interface ConditionListProps {
  value: ConditionPreset[]
  onChange: (next: ConditionPreset[]) => void
}

/**
 * Flat AND chain of condition presets (no nested OR groups — the prototype
 * doesn't model them, see AAASM-1281 scope decision). Each row is a select
 * pointing at the next preset; rows are separated by an "AND" label.
 */
export function ConditionList({ value, onChange }: ConditionListProps) {
  const handleChangeAt = (idx: number, next: ConditionPreset) => {
    onChange(value.map((c, i) => (i === idx ? next : c)))
  }

  const handleRemoveAt = (idx: number) => {
    onChange(value.filter((_, i) => i !== idx))
  }

  const handleAdd = () => {
    onChange([...value, 'always'])
  }

  return (
    <div className="editor__condition-list" data-testid="editor-conditions">
      {value.map((cond, idx) => (
        <div
          key={`${idx}-${cond}`}
          className="editor__condition-row"
          data-testid={`editor-condition-row-${idx}`}
        >
          {idx > 0 ? <span className="editor__condition-and">AND</span> : null}
          <select
            className="editor__select"
            value={cond}
            data-testid={`editor-condition-select-${idx}`}
            onChange={(e) => handleChangeAt(idx, e.target.value as ConditionPreset)}
          >
            {COND_PRESETS.map((preset) => (
              <option key={preset} value={preset}>
                {preset}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="editor__remove-cond"
            aria-label={`remove condition ${idx + 1}`}
            data-testid={`editor-condition-remove-${idx}`}
            onClick={() => handleRemoveAt(idx)}
          >
            ✕
          </button>
        </div>
      ))}
      <button
        type="button"
        className="editor__add-condition"
        data-testid="editor-condition-add"
        onClick={handleAdd}
      >
        + add condition
      </button>
    </div>
  )
}
