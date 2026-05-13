import { useAlertQuery } from './api'
import { SeverityBadge } from './SeverityBadge'
import { StatusBadge } from './StatusBadge'
import { SilenceAction } from './SilenceAction'
import type { AlertDetail } from './types'

function ruleYaml(detail: AlertDetail): string {
  const r = detail.ruleSnapshot
  const labels = Object.entries(r.suppressionLabels)
  return [
    `name: ${JSON.stringify(r.name)}`,
    `metric: ${r.metric}`,
    `operator: ${JSON.stringify(r.operator)}`,
    `threshold: ${r.threshold}`,
    `evaluation_window_seconds: ${r.evaluationWindowSeconds}`,
    `severity: ${r.severity}`,
    `dedup_window_seconds: ${r.dedupWindowSeconds}`,
    `destinations: [${r.destinationIds.map((d) => JSON.stringify(d)).join(', ')}]`,
    labels.length
      ? `suppression_labels:\n${labels.map(([k, v]) => `  ${k}: ${JSON.stringify(v)}`).join('\n')}`
      : 'suppression_labels: {}',
  ].join('\n')
}

const sectionStyle = {
  display: 'flex',
  flexDirection: 'column' as const,
  gap: '0.25rem',
}

const sectionHeader = {
  fontSize: '0.75rem',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.04em',
  color: '#6b7280',
}

interface AlertDetailContentProps {
  alertId: string
}

export function AlertDetailContent({ alertId }: AlertDetailContentProps) {
  const { data, isLoading, isError, error } = useAlertQuery(alertId)

  if (isLoading) {
    return (
      <p data-testid="alert-detail-loading" style={{ fontSize: '0.875rem', color: '#6b7280' }}>
        Loading alert…
      </p>
    )
  }

  if (isError || !data) {
    return (
      <p data-testid="alert-detail-error" style={{ color: '#dc2626', fontSize: '0.875rem' }}>
        Failed to load alert: {error?.message ?? 'unknown error'}
      </p>
    )
  }

  return (
    <div data-testid="alert-detail-content" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <header style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <SeverityBadge severity={data.severity} />
          <StatusBadge status={data.status} />
        </div>
        <h3 style={{ margin: 0, fontSize: '1rem' }}>{data.ruleName}</h3>
        <p style={{ margin: 0, color: '#6b7280', fontSize: '0.75rem' }}>
          Fired {data.firstFiredAt}
          {data.resolvedAt && ` · Resolved ${data.resolvedAt}`}
          {data.agentId && ` · Agent ${data.agentId}`}
        </p>
      </header>

      <section style={sectionStyle}>
        <span style={sectionHeader}>Rule YAML</span>
        <pre
          data-testid="alert-detail-rule-yaml"
          style={{
            background: '#f3f4f6',
            padding: '0.75rem',
            borderRadius: '4px',
            fontSize: '0.75rem',
            margin: 0,
            overflowX: 'auto',
            whiteSpace: 'pre',
          }}
        >
          {ruleYaml(data)}
        </pre>
      </section>

      <section style={sectionStyle}>
        <span style={sectionHeader}>Firing timeline</span>
        <ul
          data-testid="alert-detail-timeline"
          style={{ listStyle: 'none', padding: 0, margin: 0, fontSize: '0.75rem' }}
        >
          <li>
            <strong>{data.firstFiredAt}</strong> — first fired
          </li>
          {data.silence && (
            <li>
              <strong>{data.silence.startsAt}</strong> — silenced until {data.silence.expiresAt}
              {data.silence.reason && ` (${data.silence.reason})`}
            </li>
          )}
          {data.resolvedAt && (
            <li>
              <strong>{data.resolvedAt}</strong> — resolved
            </li>
          )}
        </ul>
      </section>

      <section style={sectionStyle}>
        <span style={sectionHeader}>Event payload</span>
        <pre
          data-testid="alert-detail-event-payload"
          style={{
            background: '#f3f4f6',
            padding: '0.75rem',
            borderRadius: '4px',
            fontSize: '0.75rem',
            margin: 0,
            overflowX: 'auto',
            whiteSpace: 'pre',
          }}
        >
          {JSON.stringify(data.eventPayload, null, 2)}
        </pre>
      </section>

      {data.status !== 'RESOLVED' && (
        <SilenceAction alertId={data.id} silenced={data.status === 'SUPPRESSED'} />
      )}

      <section style={sectionStyle}>
        <span style={sectionHeader}>Routing log</span>
        {data.routingLog.length === 0 ? (
          <span style={{ fontSize: '0.75rem', color: '#6b7280' }}>No deliveries recorded.</span>
        ) : (
          <ul
            data-testid="alert-detail-routing-log"
            style={{ listStyle: 'none', padding: 0, margin: 0, fontSize: '0.75rem' }}
          >
            {data.routingLog.map((entry, i) => (
              <li key={i}>
                <strong>{entry.deliveredAt}</strong> → {entry.destinationId} ·{' '}
                <span style={{ color: entry.status === 'ok' ? '#166534' : '#991b1b' }}>
                  {entry.status}
                </span>
                {entry.errorMessage && ` (${entry.errorMessage})`}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
