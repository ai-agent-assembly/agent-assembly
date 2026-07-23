// Severity-bordered card-feed view — the alert cards from
// design/v1/hi-fi/alerts.jsx, with inline expand. Offered alongside the
// existing sortable table + detail drawer (AlertList / AlertDetailDrawer),
// not as a replacement; a card's "Open detail" action still opens that drawer.
//
// Each card carries a 3px left border in the alert's severity colour (the
// spec's signature treatment) and a derived category chip (see alertCategory).

import { useState } from 'react'
import { SeverityBadge } from './SeverityBadge'
import { StatusBadge } from './StatusBadge'
import { CATEGORY_META, deriveCategory } from './alertCategory'
import type { Alert, AlertRule, Severity } from './types'

const SEVERITY_BORDER: Record<Severity, string> = {
  CRITICAL: 'var(--severity-critical)',
  HIGH: 'var(--severity-high)',
  MEDIUM: 'var(--severity-medium)',
  LOW: 'var(--severity-low)',
}

function formatDuration(firstFiredAt: string, resolvedAt: string | null): string {
  const start = Date.parse(firstFiredAt)
  if (Number.isNaN(start)) return '—'
  const end = resolvedAt ? Date.parse(resolvedAt) : Date.now()
  const totalMinutes = Math.floor(Math.max(0, end - start) / 60_000)
  if (totalMinutes < 1) return '< 1m'
  if (totalMinutes < 60) return `${totalMinutes}m`
  const hours = Math.floor(totalMinutes / 60)
  if (hours < 24) return `${hours}h ${totalMinutes % 60}m`
  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}

function formatTimestamp(iso: string): string {
  const ts = Date.parse(iso)
  if (Number.isNaN(ts)) return iso
  return new Date(ts).toISOString().replace('T', ' ').slice(0, 16)
}

function CategoryChip({ alert, byId }: Readonly<{ alert: Alert; byId: ReadonlyMap<string, AlertRule> }>) {
  const cat = deriveCategory(alert, byId)
  const meta = CATEGORY_META[cat]
  return (
    <span
      data-testid={`alert-card-category-${cat}`}
      style={{
        display: 'inline-block',
        padding: '1px 8px',
        borderRadius: '9999px',
        fontSize: '0.625rem',
        fontWeight: 600,
        letterSpacing: '0.02em',
        background: meta.badgeBg,
        color: meta.badgeText,
      }}
    >
      {meta.label}
    </span>
  )
}

interface AlertCardProps {
  alert: Alert
  byId: ReadonlyMap<string, AlertRule>
  expanded: boolean
  onToggle: () => void
  onSelect?: (alertId: string) => void
}

function AlertCard({ alert, byId, expanded, onToggle, onSelect }: Readonly<AlertCardProps>) {
  return (
    <div
      data-testid="alert-card"
      style={{
        borderLeft: `3px solid ${SEVERITY_BORDER[alert.severity]}`,
        border: '1px solid var(--surface-card-border)',
        borderLeftWidth: '3px',
        borderLeftColor: SEVERITY_BORDER[alert.severity],
        borderRadius: '6px',
        background: expanded ? 'var(--surface-hover-bg)' : 'var(--surface-card)',
        marginBottom: '0.5rem',
      }}
    >
      <button
        type="button"
        data-testid={`alert-card-toggle-${alert.id}`}
        aria-expanded={expanded}
        onClick={onToggle}
        style={{
          display: 'flex',
          width: '100%',
          gap: '0.75rem',
          alignItems: 'flex-start',
          padding: '0.625rem 0.875rem',
          background: 'transparent',
          border: 'none',
          textAlign: 'left',
          cursor: 'pointer',
        }}
      >
        <div style={{ flexShrink: 0, paddingTop: '2px' }}>
          <SeverityBadge severity={alert.severity} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: '0.375rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '3px' }}>
            <CategoryChip alert={alert} byId={byId} />
            <StatusBadge status={alert.status} />
            {alert.agentId && (
              <span
                style={{
                  fontFamily: 'var(--font-mono, monospace)',
                  fontSize: '0.6875rem',
                  color: 'var(--text-muted)',
                }}
              >
                {alert.agentId}
              </span>
            )}
          </div>
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-primary, inherit)', lineHeight: 1.4 }}>
            {alert.ruleName}
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono, monospace)',
              fontSize: '0.625rem',
              color: 'var(--text-muted)',
              marginTop: '3px',
            }}
          >
            {alert.id} · {formatDuration(alert.firstFiredAt, alert.resolvedAt)}
          </div>
        </div>
        <span
          aria-hidden="true"
          style={{ color: 'var(--text-muted)', fontSize: '0.625rem', paddingTop: '4px', flexShrink: 0 }}
        >
          {expanded ? '▲' : '▼'}
        </span>
      </button>

      {expanded && (
        <div
          data-testid={`alert-card-detail-${alert.id}`}
          style={{
            borderTop: '1px dashed var(--surface-card-border)',
            padding: '0.75rem 0.875rem',
            fontSize: '0.75rem',
          }}
        >
          <dl
            style={{
              display: 'grid',
              gridTemplateColumns: '6.5rem 1fr',
              rowGap: '0.375rem',
              columnGap: '0.5rem',
              margin: 0,
            }}
          >
            <dt style={{ color: 'var(--text-muted)' }}>first fired</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono, monospace)' }}>
              {formatTimestamp(alert.firstFiredAt)}
            </dd>
            <dt style={{ color: 'var(--text-muted)' }}>agent</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono, monospace)' }}>{alert.agentId ?? '—'}</dd>
            <dt style={{ color: 'var(--text-muted)' }}>rule</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono, monospace)' }}>{alert.ruleName}</dd>
            <dt style={{ color: 'var(--text-muted)' }}>destinations</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono, monospace)' }}>
              {alert.destinationIds.length ? alert.destinationIds.join(', ') : '—'}
            </dd>
          </dl>
          {onSelect && (
            <button
              type="button"
              data-testid={`alert-card-open-detail-${alert.id}`}
              onClick={() => onSelect(alert.id)}
              style={{
                marginTop: '0.625rem',
                padding: '4px 10px',
                fontSize: '0.75rem',
                border: '1px solid var(--form-input-border)',
                borderRadius: '4px',
                background: 'var(--surface-card)',
                color: 'var(--button-primary-bg)',
                cursor: 'pointer',
              }}
            >
              Open detail →
            </button>
          )}
        </div>
      )}
    </div>
  )
}

interface AlertCardFeedProps {
  rows: readonly Alert[]
  rulesById: ReadonlyMap<string, AlertRule>
  onSelect?: (alertId: string) => void
}

export function AlertCardFeed({ rows, rulesById, onSelect }: Readonly<AlertCardFeedProps>) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  if (rows.length === 0) {
    return (
      <div
        data-testid="alert-card-feed-empty"
        style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8125rem' }}
      >
        no alerts match filters
      </div>
    )
  }

  return (
    <div data-testid="alert-card-feed">
      {rows.map((alert) => (
        <AlertCard
          key={alert.id}
          alert={alert}
          byId={rulesById}
          expanded={expandedId === alert.id}
          onToggle={() => setExpandedId((prev) => (prev === alert.id ? null : alert.id))}
          onSelect={onSelect}
        />
      ))}
    </div>
  )
}
