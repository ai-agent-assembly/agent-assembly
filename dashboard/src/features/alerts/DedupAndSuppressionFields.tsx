import { useFieldArray, useFormContext } from 'react-hook-form'
import type { RuleFormValues } from './ruleFormSchema'

const errorStyle = { color: '#dc2626', fontSize: '0.75rem' }

export function DedupAndSuppressionFields() {
  const { register, control, formState } = useFormContext<RuleFormValues>()
  const errors = formState.errors
  const { fields, append, remove } = useFieldArray({
    control,
    name: 'suppressionLabels',
  })

  return (
    <fieldset
      data-testid="rule-dedup-suppression"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '0.75rem',
        border: '1px solid #e5e7eb',
        borderRadius: '6px',
        padding: '0.75rem',
      }}
    >
      <legend style={{ padding: '0 0.5rem', color: '#6b7280', fontSize: '0.75rem' }}>
        Deduplication &amp; suppression
      </legend>

      <label
        style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.875rem' }}
      >
        <span>Dedup window (seconds)</span>
        <input
          id="rule-dedup"
          data-testid="rule-dedup-window"
          type="number"
          step="1"
          min={0}
          {...register('dedupWindowSeconds', { valueAsNumber: true })}
        />
        {errors.dedupWindowSeconds && (
          <span style={errorStyle}>{errors.dedupWindowSeconds.message}</span>
        )}
      </label>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '0.875rem',
          }}
        >
          <span>Suppression labels (key = value)</span>
          <button
            type="button"
            data-testid="rule-suppression-add"
            onClick={() => append({ key: '', value: '' })}
            style={{
              padding: '2px 8px',
              border: '1px solid #d1d5db',
              borderRadius: '4px',
              background: '#fff',
              cursor: 'pointer',
              fontSize: '0.75rem',
            }}
          >
            + Add
          </button>
        </div>

        {fields.length === 0 && (
          <span style={{ fontSize: '0.75rem', color: '#6b7280' }}>
            No suppression labels — the rule will fire regardless of labels.
          </span>
        )}

        {fields.map((field, idx) => (
          <div
            key={field.id}
            data-testid={`rule-suppression-row-${idx}`}
            style={{ display: 'flex', gap: '0.35rem', alignItems: 'flex-start' }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
              <input
                placeholder="env"
                data-testid={`rule-suppression-key-${idx}`}
                {...register(`suppressionLabels.${idx}.key` as const)}
              />
              {errors.suppressionLabels?.[idx]?.key && (
                <span style={errorStyle}>{errors.suppressionLabels[idx]?.key?.message}</span>
              )}
            </div>
            <span style={{ alignSelf: 'center', color: '#6b7280' }}>=</span>
            <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
              <input
                placeholder="prod"
                data-testid={`rule-suppression-value-${idx}`}
                {...register(`suppressionLabels.${idx}.value` as const)}
              />
              {errors.suppressionLabels?.[idx]?.value && (
                <span style={errorStyle}>{errors.suppressionLabels[idx]?.value?.message}</span>
              )}
            </div>
            <button
              type="button"
              data-testid={`rule-suppression-remove-${idx}`}
              onClick={() => remove(idx)}
              aria-label="Remove suppression label"
              style={{
                padding: '0 8px',
                border: '1px solid #d1d5db',
                borderRadius: '4px',
                background: '#fff',
                cursor: 'pointer',
                fontSize: '0.875rem',
              }}
            >
              ✕
            </button>
          </div>
        ))}
      </div>
    </fieldset>
  )
}
