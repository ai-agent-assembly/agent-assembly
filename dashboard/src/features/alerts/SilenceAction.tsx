import { useState } from 'react'
import { useSilenceAlertMutation } from './api'
import { useToast } from '../../components/Toast'

interface SilenceActionProps {
  alertId: string
  /** Currently active silence — when set, the action is rendered as read-only. */
  silenced?: boolean
}

interface DurationOption {
  label: string
  /** seconds; `null` for the "custom" option (user supplies minutes inline). */
  value: number | null
}

const DURATIONS: readonly DurationOption[] = [
  { label: '5m', value: 5 * 60 },
  { label: '1h', value: 60 * 60 },
  { label: '4h', value: 4 * 60 * 60 },
  { label: '24h', value: 24 * 60 * 60 },
  { label: 'custom', value: null },
]

export function SilenceAction({ alertId, silenced = false }: SilenceActionProps) {
  const [selected, setSelected] = useState<DurationOption>(DURATIONS[1])
  const [customMinutes, setCustomMinutes] = useState<string>('30')
  const [reason, setReason] = useState<string>('')
  const silence = useSilenceAlertMutation()
  const { toast } = useToast()

  const resolveSeconds = (): number | null => {
    if (selected.value !== null) return selected.value
    const minutes = Number.parseInt(customMinutes, 10)
    return Number.isFinite(minutes) && minutes > 0 ? minutes * 60 : null
  }

  const submit = async () => {
    const seconds = resolveSeconds()
    if (seconds === null) {
      toast('Enter a positive number of minutes', 'error')
      return
    }
    try {
      await silence.mutateAsync({
        alertId,
        durationSeconds: seconds,
        reason: reason.trim() || undefined,
      })
      toast('Silence applied', 'success')
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to silence alert', 'error')
    }
  }

  if (silenced) {
    return (
      <p
        data-testid="silence-action-already"
        style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}
      >
        Alert is currently silenced.
      </p>
    )
  }

  return (
    <section
      data-testid="silence-action"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem',
        padding: '0.75rem',
        border: '1px solid var(--surface-card-border)',
        borderRadius: '6px',
      }}
    >
      <span
        style={{
          fontSize: '0.75rem',
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
          color: 'var(--text-muted)',
        }}
      >
        Silence this alert
      </span>

      <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
        {DURATIONS.map((opt) => {
          const active = selected.label === opt.label
          return (
            <button
              key={opt.label}
              type="button"
              data-testid={`silence-action-duration-${opt.label}`}
              aria-pressed={active}
              onClick={() => setSelected(opt)}
              style={{
                padding: '4px 10px',
                borderRadius: '4px',
                border: '1px solid var(--form-input-border)',
                background: active ? 'var(--button-primary-bg)' : 'var(--surface-card)',
                color: active ? 'var(--text-on-accent)' : 'var(--button-primary-bg)',
                cursor: 'pointer',
                fontSize: '0.75rem',
              }}
            >
              {opt.label}
            </button>
          )
        })}
      </div>

      {selected.value === null && (
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.25rem',
            fontSize: '0.875rem',
          }}
        >
          <input
            type="number"
            min={1}
            data-testid="silence-action-custom-minutes"
            value={customMinutes}
            onChange={(e) => setCustomMinutes(e.target.value)}
            style={{ width: '5rem' }}
          />
          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>minutes</span>
        </label>
      )}

      <label
        style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.875rem' }}
      >
        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Reason (optional)</span>
        <input
          data-testid="silence-action-reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Known maintenance window"
        />
      </label>

      <button
        type="button"
        data-testid="silence-action-submit"
        onClick={() => void submit()}
        disabled={silence.isPending}
        style={{
          alignSelf: 'flex-end',
          padding: '6px 14px',
          background: 'var(--button-primary-bg)',
          color: 'var(--text-on-accent)',
          border: 'none',
          borderRadius: '4px',
          cursor: silence.isPending ? 'wait' : 'pointer',
          fontSize: '0.875rem',
        }}
      >
        {silence.isPending ? 'Silencing…' : 'Silence'}
      </button>
    </section>
  )
}
