import { useFormContext } from 'react-hook-form'
import { SeverityBadge } from './SeverityBadge'
import type { Severity } from './types'
import type { RuleFormValues } from './ruleFormSchema'

const OPTIONS: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export function SeveritySelect() {
  const { register, formState } = useFormContext<RuleFormValues>()
  const error = formState.errors.severity

  return (
    <fieldset
      data-testid="rule-severity"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem',
        border: '1px solid var(--surface-card-border)',
        borderRadius: '6px',
        padding: '0.75rem',
      }}
    >
      <legend style={{ padding: '0 0.5rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
        Severity
      </legend>
      <div style={{ display: 'flex', gap: '0.75rem' }}>
        {OPTIONS.map((sev) => (
          <label
            key={sev}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}
          >
            <input
              type="radio"
              value={sev}
              data-testid={`rule-severity-${sev}`}
              {...register('severity')}
            />
            <SeverityBadge severity={sev} />
          </label>
        ))}
      </div>
      {error && (
        <span style={{ color: 'var(--status-danger-solid)', fontSize: '0.75rem' }}>{error.message}</span>
      )}
    </fieldset>
  )
}
