import { Controller, useFormContext } from 'react-hook-form'
import { useDestinationsQuery } from './api'
import type { RuleFormValues } from './ruleFormSchema'

export function DestinationsPicker() {
  const { control, formState } = useFormContext<RuleFormValues>()
  const { data, isLoading, isError } = useDestinationsQuery()
  const destinations = data ?? []
  const error = formState.errors.destinationIds

  return (
    <fieldset
      data-testid="rule-destinations"
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
        Routing destinations
      </legend>

      {isLoading && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Loading…</span>}
      {isError && (
        <span data-testid="rule-destinations-error" style={{ fontSize: '0.75rem', color: 'var(--status-danger-solid)' }}>
          Failed to load destinations
        </span>
      )}
      {!isLoading && !isError && destinations.length === 0 && (
        <span
          data-testid="rule-destinations-empty"
          style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}
        >
          No destinations configured yet — add one in the Destination Registry.
        </span>
      )}

      <Controller
        control={control}
        name="destinationIds"
        render={({ field }) => {
          const selected = new Set(field.value ?? [])
          const toggle = (id: string) => {
            const next = new Set(selected)
            if (next.has(id)) next.delete(id)
            else next.add(id)
            field.onChange(Array.from(next))
          }
          return (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {destinations.map((d) => {
                const active = selected.has(d.id)
                return (
                  <label
                    key={d.id}
                    data-testid={`rule-destination-${d.id}`}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      padding: '4px 10px',
                      borderRadius: '6px',
                      border: '1px solid var(--form-input-border)',
                      background: active ? 'var(--button-primary-bg)' : 'var(--surface-card)',
                      color: active ? 'var(--text-on-accent)' : 'var(--button-primary-bg)',
                      cursor: 'pointer',
                      fontSize: '0.75rem',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={active}
                      onChange={() => toggle(d.id)}
                      style={{ display: 'none' }}
                    />
                    <span style={{ fontWeight: 600, textTransform: 'uppercase' }}>{d.kind}</span>
                    <span>{d.name}</span>
                  </label>
                )
              })}
            </div>
          )
        }}
      />

      {error && (
        <span style={{ color: 'var(--status-danger-solid)', fontSize: '0.75rem' }}>{error.message}</span>
      )}
    </fieldset>
  )
}
