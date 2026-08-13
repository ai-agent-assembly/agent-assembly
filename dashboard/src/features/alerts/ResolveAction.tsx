// Acknowledge / resolve affordance for one alert (AAASM-5121).
//
// `POST /api/v1/alerts/{id}/resolve` (operationId `resolve_alert`) has been in
// openapi/v1.yaml and idempotent for some time, and `useAlertsStream` already
// consumes the `resolve` events it produces — but the dashboard had no way to
// produce one, so the Incidents tab could only ever fill from alerts something
// else resolved. The mock's per-row "Acknowledge" button
// (design/v2/hi-fi/alerts.jsx:86-88) is this action.
//
// Only the per-row action is wired. The mock's header-level "Acknowledge all"
// (alerts.jsx:134) is deliberately not built: there is no bulk endpoint, and
// fanning out N writes from a button labelled as one atomic action would report
// success it cannot guarantee.

import { useState } from 'react'
import { useResolveAlertMutation } from './api'
import { useToast } from '../../components/Toast'
import { usePermissions, WRITE_REQUIRED_HINT } from '../../auth/usePermissions'

interface ResolveActionProps {
  alertId: string
}

export function ResolveAction({ alertId }: Readonly<ResolveActionProps>) {
  const [reason, setReason] = useState('')
  const resolve = useResolveAlertMutation()
  const { toast } = useToast()
  const { canWrite } = usePermissions()

  const submit = async () => {
    try {
      await resolve.mutateAsync({ alertId, reason: reason.trim() || undefined })
      toast('Alert resolved', 'success')
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to resolve alert', 'error')
    }
  }

  return (
    <section
      data-testid="resolve-action"
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
        Resolve this alert
      </span>

      <label
        style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.875rem' }}
      >
        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Reason (optional)</span>
        <input
          data-testid="resolve-action-reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          disabled={!canWrite}
          placeholder="Root cause addressed"
        />
      </label>

      <button
        type="button"
        data-testid="resolve-action-submit"
        onClick={() => void submit()}
        disabled={!canWrite || resolve.isPending}
        title={canWrite ? undefined : WRITE_REQUIRED_HINT}
        style={{
          alignSelf: 'flex-end',
          padding: '6px 14px',
          background: 'var(--button-primary-bg)',
          color: 'var(--text-on-accent)',
          border: 'none',
          borderRadius: '4px',
          cursor: canWrite && !resolve.isPending ? 'pointer' : 'not-allowed',
          fontSize: '0.875rem',
        }}
      >
        {resolve.isPending ? 'Resolving…' : 'Resolve'}
      </button>
    </section>
  )
}
