// Clickable 5-tile stats strip — the signature element of
// design/v1/hi-fi/alerts.jsx, adapted to this dashboard's taxonomy.
//
// The spec strip mixes two severities + three categories. This impl keeps its
// own enum (CRITICAL / HIGH / MEDIUM / LOW + FIRING / RESOLVED / SUPPRESSED),
// so the strip surfaces the four severity buckets plus the FIRING headline
// count. Counts are derived from the alerts currently loaded; each tile toggles
// the SAME server-side filter model the filter bar drives (single source of
// truth), so clicking a tile narrows the feed exactly as the matching filter
// chip would. Categories are a separate, client-derived filter (see
// AlertCategoryFilter) because no first-class category field exists to filter
// server-side.

import type { Alert, AlertStatus, Severity } from './types'

interface AlertStatsStripProps {
  /** Alerts the counts are derived from (the currently loaded window). */
  alerts: readonly Alert[]
  activeSeverities: readonly Severity[]
  activeStatuses: readonly AlertStatus[]
  onToggleSeverity: (severity: Severity) => void
  onToggleStatus: (status: AlertStatus) => void
}

type Tile =
  | { kind: 'severity'; key: Severity; label: string; color: string }
  | { kind: 'status'; key: AlertStatus; label: string; color: string }

const TILES: readonly Tile[] = [
  { kind: 'severity', key: 'CRITICAL', label: 'critical', color: 'var(--severity-critical)' },
  { kind: 'severity', key: 'HIGH', label: 'high', color: 'var(--severity-high)' },
  { kind: 'severity', key: 'MEDIUM', label: 'medium', color: 'var(--severity-medium)' },
  { kind: 'severity', key: 'LOW', label: 'low', color: 'var(--severity-low)' },
  { kind: 'status', key: 'FIRING', label: 'firing', color: 'var(--danger)' },
]

export function AlertStatsStrip({
  alerts,
  activeSeverities,
  activeStatuses,
  onToggleSeverity,
  onToggleStatus,
}: Readonly<AlertStatsStripProps>) {
  const severityCount = (s: Severity) => alerts.filter((a) => a.severity === s).length
  const statusCount = (s: AlertStatus) => alerts.filter((a) => a.status === s).length

  return (
    <div
      data-testid="alerts-stats-strip"
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(5, 1fr)',
        gap: '1px',
        background: 'var(--surface-card-border)',
        border: '1px solid var(--surface-card-border)',
        borderRadius: '6px',
        overflow: 'hidden',
        marginBottom: '0.75rem',
      }}
    >
      {TILES.map((tile) => {
        const count = tile.kind === 'severity' ? severityCount(tile.key) : statusCount(tile.key)
        const active =
          tile.kind === 'severity'
            ? activeSeverities.includes(tile.key)
            : activeStatuses.includes(tile.key)
        return (
          <button
            key={`${tile.kind}-${tile.key}`}
            type="button"
            data-testid={`alerts-stat-tile-${tile.key}`}
            aria-pressed={active}
            onClick={() =>
              tile.kind === 'severity'
                ? onToggleSeverity(tile.key)
                : onToggleStatus(tile.key)
            }
            style={{
              display: 'block',
              textAlign: 'left',
              border: 'none',
              padding: '0.625rem 1rem',
              cursor: 'pointer',
              transition: 'background 0.12s',
              background: active ? 'var(--button-primary-bg)' : 'var(--surface-card)',
            }}
          >
            <div
              data-testid={`alerts-stat-count-${tile.key}`}
              style={{
                fontFamily: 'var(--font-mono, monospace)',
                fontSize: '1.5rem',
                fontWeight: 700,
                lineHeight: 1.1,
                color: active ? 'var(--button-primary-text)' : tile.color,
              }}
            >
              {count}
            </div>
            <div
              style={{
                fontFamily: 'var(--font-mono, monospace)',
                fontSize: '0.625rem',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginTop: '2px',
                color: active
                  ? 'color-mix(in srgb, var(--button-primary-text) 70%, transparent)'
                  : 'var(--text-muted)',
              }}
            >
              {tile.label}
            </div>
          </button>
        )
      })}
    </div>
  )
}
