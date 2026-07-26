import type { TopologyEdgeKind } from '../../features/topology/types'
import { EDGE_KINDS } from '../../features/topology/edgeKinds'
import './TopologySidebar.css'

/** Aggregate counters shown in the sidebar header stat badges. */
export interface TopologyStats {
  readonly active: number
  readonly flagged: number
  /** Cross-team edges across the whole fleet — not the filtered view. */
  readonly crossTeam: number
  /**
   * How many of `crossTeam` the canvas is currently not drawing (AAASM-5138).
   *
   * The counter describes the fleet while the canvas draws a subset, so without
   * this the two contradict each other and the operator has no way to tell.
   * Rather than silently narrowing the count to match the picture — which would
   * throw away the fleet-wide fact — the gap is stated outright.
   */
  readonly crossTeamHidden: number
  readonly hasCycles: boolean
}

export interface TopologySidebarProps {
  readonly stats: TopologyStats
  /** Distinct team ids present in the (unfiltered) graph. */
  readonly teams: readonly string[]
  /** Currently-selected team filter: `'all'` or a team id. */
  readonly filterTeam: string
  readonly onFilterTeam: (team: string) => void
  /** Model edge kinds currently drawn. */
  readonly visibleKinds: ReadonlySet<TopologyEdgeKind>
  readonly onToggleKind: (kind: TopologyEdgeKind) => void
  readonly showCrossTeam: boolean
  readonly onToggleCrossTeam: (next: boolean) => void
}

const ALL = 'all'

/** Status-stripe legend rows — colours match the node stripe CSS. */
const STATUS_LEGEND: ReadonlyArray<{ readonly color: string; readonly label: string }> = [
  { color: 'var(--ok)', label: 'active' },
  { color: 'var(--ink-4)', label: 'idle' },
  { color: 'var(--warn)', label: 'suspended' },
  { color: 'var(--danger)', label: 'error' },
]

/**
 * Left control rail for the topology view (AAASM-5071), mirroring
 * `design/v1/hi-fi/topology.jsx` `TopoSidebar`: header stat badges, a team
 * filter list, the six edge-type checkboxes (+ cross-team toggle), a
 * cycle-alert block, and the status-stripe legend.
 *
 * All six edge kinds are toggleable since the `/topology` projection widened to
 * emit them (AAASM-5099); a kind the projection stops emitting would render
 * disabled with a "soon" tag rather than fabricating edges.
 */
export function TopologySidebar({
  stats,
  teams,
  filterTeam,
  onFilterTeam,
  visibleKinds,
  onToggleKind,
  showCrossTeam,
  onToggleCrossTeam,
}: TopologySidebarProps) {
  const filterOptions = [{ id: ALL, label: 'All teams' }, ...teams.map((t) => ({ id: t, label: t }))]

  return (
    <aside className="topo-sidebar" data-testid="topology-sidebar" aria-label="Topology controls">
      {/* Header stat badges */}
      <div className="topo-sidebar__stats" data-testid="topology-stats">
        <span className="topo-sidebar__stat topo-sidebar__stat--ok" data-testid="topology-stat-active">
          ● {stats.active} active
        </span>
        {stats.flagged > 0 && (
          <span className="topo-sidebar__stat topo-sidebar__stat--danger" data-testid="topology-stat-flagged">
            ⚑ {stats.flagged} flagged
          </span>
        )}
        {stats.hasCycles && (
          <span className="topo-sidebar__stat topo-sidebar__stat--danger" data-testid="topology-stat-cycle">
            ⟳ cycle
          </span>
        )}
        <span className="topo-sidebar__stat topo-sidebar__stat--muted" data-testid="topology-stat-crossteam">
          ⇆ {stats.crossTeam} cross-team
        </span>
        {/* The count above is fleet-wide; when the canvas is showing fewer, say
            so rather than leaving a number that contradicts the picture. */}
        {stats.crossTeamHidden > 0 && (
          <span
            className="topo-sidebar__stat topo-sidebar__stat--hidden"
            data-testid="topology-stat-crossteam-hidden"
            data-hidden-count={stats.crossTeamHidden}
            title={
              `${stats.crossTeamHidden} of these cross-team ${stats.crossTeamHidden === 1 ? 'edge is' : 'edges are'} ` +
              'not drawn — hidden by the team filter, the cross-team toggle, or an unchecked edge type.'
            }
          >
            {stats.crossTeamHidden} not shown
          </span>
        )}
      </div>

      {/* Team filter */}
      <div className="topo-sidebar__group">
        <div className="topo-sidebar__heading">Teams</div>
        <div data-testid="topology-team-filter">
          {filterOptions.map((opt) => {
            const isActive = filterTeam === opt.id
            return (
              <button
                key={opt.id}
                type="button"
                className={`topo-sidebar__team${isActive ? ' topo-sidebar__team--active' : ''}`}
                data-testid="team-filter-item"
                data-team={opt.id}
                data-active={isActive ? 'true' : undefined}
                aria-pressed={isActive}
                onClick={() => onFilterTeam(opt.id)}
              >
                <span className="topo-sidebar__team-mark">{opt.id === ALL ? '◎' : '○'}</span>
                {opt.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Edge types */}
      <div className="topo-sidebar__group">
        <div className="topo-sidebar__heading">Edge types</div>
        {EDGE_KINDS.map((kind) => {
          const checked = kind.modelKind ? visibleKinds.has(kind.modelKind) : false
          return (
            <label
              key={kind.id}
              className={`topo-sidebar__edge${kind.available ? '' : ' topo-sidebar__edge--soon'}`}
              data-testid="topology-edge-toggle"
              data-kind={kind.id}
              data-available={kind.available ? 'true' : 'false'}
              title={
                kind.available
                  ? undefined
                  : 'Not emitted by the topology projection yet — lights up when the backend widens it.'
              }
            >
              <input
                type="checkbox"
                checked={checked}
                disabled={!kind.available}
                onChange={() => kind.modelKind && onToggleKind(kind.modelKind)}
              />
              <span className="topo-sidebar__edge-swatch" style={{ color: kind.color }} aria-hidden="true">—</span>
              <span className="topo-sidebar__edge-label">{kind.label}</span>
              {!kind.available && <span className="topo-sidebar__edge-soon">soon</span>}
            </label>
          )
        })}
        <label className="topo-sidebar__edge" data-testid="topology-crossteam-toggle">
          <input
            type="checkbox"
            checked={showCrossTeam}
            onChange={(e) => onToggleCrossTeam(e.target.checked)}
          />
          <span className="topo-sidebar__edge-label">show cross-team</span>
        </label>
      </div>

      {/* Cycle alert */}
      {stats.hasCycles && (
        <div className="topo-sidebar__group">
          <div className="topo-sidebar__alert" data-testid="topology-cycle-alert">
            <div className="topo-sidebar__alert-title">⟳ Cycle detected</div>
            <div className="topo-sidebar__alert-body">
              Highlighted in red on the canvas. Requires immediate review.
            </div>
          </div>
        </div>
      )}

      {/* Status legend */}
      <div className="topo-sidebar__group topo-sidebar__group--footer" data-testid="topology-status-legend">
        <div className="topo-sidebar__heading">Status stripe</div>
        {STATUS_LEGEND.map((row) => (
          <div key={row.label} className="topo-sidebar__legend-row">
            <span className="topo-sidebar__legend-swatch" style={{ background: row.color }} />
            {row.label}
          </div>
        ))}
        <div className="topo-sidebar__hint">Scroll = zoom · drag = pan</div>
      </div>
    </aside>
  )
}
