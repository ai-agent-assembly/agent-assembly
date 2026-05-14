import { useFormContext } from 'react-hook-form'
import type { RuleFormValues } from './ruleFormSchema'

const METRIC_OPTIONS: ReadonlyArray<{ value: RuleFormValues['metric']; label: string }> = [
  { value: 'budget_spent_pct', label: 'Budget spent (%)' },
  { value: 'anomaly_score', label: 'Anomaly score' },
  { value: 'approval_pending_age', label: 'Approval pending age (seconds)' },
  { value: 'policy_violation_count', label: 'Policy violations' },
]

const OPERATOR_OPTIONS: RuleFormValues['operator'][] = ['>', '>=', '<', '=']

const WINDOW_OPTIONS: ReadonlyArray<{
  value: RuleFormValues['evaluationWindowSeconds']
  label: string
}> = [
  { value: 300, label: '5m' },
  { value: 900, label: '15m' },
  { value: 3600, label: '1h' },
]

const fieldStyle = {
  display: 'flex',
  flexDirection: 'column' as const,
  gap: '0.25rem',
  fontSize: '0.875rem',
}

const errorStyle = { color: 'var(--status-danger-solid)', fontSize: '0.75rem' }

export function ConditionBuilder() {
  const { register, formState, watch } = useFormContext<RuleFormValues>()
  const errors = formState.errors
  const metric = watch('metric')
  const isPercentage = metric === 'budget_spent_pct' || metric === 'anomaly_score'

  return (
    <fieldset
      data-testid="rule-condition-builder"
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '0.75rem',
        border: '1px solid var(--surface-card-border)',
        borderRadius: '6px',
        padding: '0.75rem',
      }}
    >
      <legend style={{ padding: '0 0.5rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
        Condition
      </legend>

      <label style={fieldStyle}>
        <span>Metric</span>
        <select id="rule-metric" data-testid="rule-metric" {...register('metric')}>
          {METRIC_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        {errors.metric && <span style={errorStyle}>{errors.metric.message}</span>}
      </label>

      <label style={fieldStyle}>
        <span>Operator</span>
        <select id="rule-operator" data-testid="rule-operator" {...register('operator')}>
          {OPERATOR_OPTIONS.map((op) => (
            <option key={op} value={op}>
              {op}
            </option>
          ))}
        </select>
        {errors.operator && <span style={errorStyle}>{errors.operator.message}</span>}
      </label>

      <label style={fieldStyle}>
        <span>
          Threshold
          {isPercentage && (
            <span style={{ color: 'var(--text-muted)', marginLeft: '0.25rem' }}>(0–100)</span>
          )}
        </span>
        <input
          id="rule-threshold"
          data-testid="rule-threshold"
          type="number"
          step="any"
          min={0}
          max={isPercentage ? 100 : undefined}
          {...register('threshold', { valueAsNumber: true })}
        />
        {errors.threshold && <span style={errorStyle}>{errors.threshold.message}</span>}
      </label>

      <label style={fieldStyle}>
        <span>Window</span>
        <select
          id="rule-window"
          data-testid="rule-window"
          {...register('evaluationWindowSeconds', { valueAsNumber: true })}
        >
          {WINDOW_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        {errors.evaluationWindowSeconds && (
          <span style={errorStyle}>{errors.evaluationWindowSeconds.message}</span>
        )}
      </label>
    </fieldset>
  )
}
