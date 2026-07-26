// Clickable 5-tile stats strip — the signature element of
// design/v1/hi-fi/alerts.jsx, adapted to this dashboard's taxonomy.
//
// The spec strip mixes two severities + three categories. This impl keeps its
// own enum (CRITICAL / HIGH / MEDIUM / LOW + FIRING / RESOLVED / SUPPRESSED),
// so the strip surfaces the four severity buckets plus the FIRING headline
// count. Each tile toggles the SAME filter model the filter bar drives (single
// source of truth). Categories are a separate, client-derived filter (see
// AlertCategoryFilter) because no first-class category field exists.
//
// AAASM-5123: the mock totals a complete in-memory feed; this strip totals one
// server page (50 rows by default, 100 max). It therefore takes the page as a
// `Certain` value plus the envelope's `total`, and says out loud when the two
// disagree. Presenting a page count as a fleet count is the
// truncation-as-completeness claim the truthfulness contract forbids, and
// rendering `0` for a page that failed to load is worse still.

import { TruthfulValue } from '../../components/truthfulness'
import { isKnown, mapCertain, type Certain } from '../../lib/truthfulness'
import { statsScopeNote } from './alertsCoverage'
import type { Alert, AlertStatus, Severity } from './types'

interface AlertStatsStripProps {
  /** The loaded page of alerts, or the absence that stands in for it. */
  alerts: Certain<readonly Alert[]>
  /** Alerts across all pages per the server envelope; absent when unknown. */
  total: Certain<number>
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
  total,
  activeSeverities,
  activeStatuses,
  onToggleSeverity,
  onToggleStatus,
}: Readonly<AlertStatsStripProps>) {
  const tileValue = (tile: Tile): Certain<number> =>
    mapCertain(
      alerts,
      (rows) =>
        rows.filter((a) => (tile.kind === 'severity' ? a.severity : a.status) === tile.key)
          .length,
    )
  const note = statsScopeNote(alerts, total)
  const interactive = isKnown(alerts)

  return (
    <div data-testid="alerts-stats" style={{ marginBottom: '0.75rem' }}>
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
        }}
      >
        {TILES.map((tile) => {
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
              // A tile derived from an absent page cannot narrow anything — the
              // click would only pretend a filter had been applied.
              disabled={!interactive}
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
                cursor: interactive ? 'pointer' : 'not-allowed',
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
                <TruthfulValue value={tileValue(tile)} />
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
      {note && (
        <p
          data-testid="alerts-stats-scope"
          style={{
            margin: '0.375rem 0 0',
            fontSize: '0.6875rem',
            color: 'var(--text-muted)',
          }}
        >
          {note}
        </p>
      )}
    </div>
  )
}
