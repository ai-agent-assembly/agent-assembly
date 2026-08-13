import { useMemo } from 'react'
import type { TopologyEdge, TopologyNode } from '../../features/topology/types'
import { computeHierarchy } from '../../features/topology/hierarchy'
import { isUnclaimedTeam, teamLabel } from '../../features/topology/unclaimed'
import './TeamDetailPanel.css'

export interface TeamDetailPanelProps {
  readonly team: string
  /** All graph nodes (unfiltered) — members are derived from these. */
  readonly nodes: readonly TopologyNode[]
  /** All graph edges — cross-team relationships are derived from these. */
  readonly edges: readonly TopologyEdge[]
  readonly onClose: () => void
  /** Optional: drill into a member's node-detail panel. */
  readonly onSelectNode?: (node: TopologyNode) => void
}

function statusColor(status: TopologyNode['status']): string {
  if (status === 'active') return 'var(--ok)'
  if (status === 'suspended') return 'var(--danger)'
  if (status === 'error') return 'var(--danger)'
  return 'var(--ink-4)'
}

/**
 * Right-side detail panel for a selected team cluster (AAASM-5071), mirroring
 * `design/v1/hi-fi/topology.jsx` `TopoTeamPanel`. Read-only: it summarises the
 * team's members (depth-indented delegation forest), its root agents, and its
 * cross-team edge count. Team-level policy/cascade/shadow actions are
 * backend-blocked (Bucket-B) and intentionally omitted.
 */
export function TeamDetailPanel({ team, nodes, edges, onClose, onSelectNode }: TeamDetailPanelProps) {
  const { depthById, rootIds } = useMemo(() => computeHierarchy(nodes, edges), [nodes, edges])

  const members = useMemo(
    () =>
      nodes
        .filter((n) => n.team === team)
        .map((n) => ({ node: n, depth: depthById.get(n.id) ?? 0, isRoot: rootIds.has(n.id) }))
        .sort((a, b) => a.depth - b.depth || a.node.name.localeCompare(b.node.name)),
    [nodes, team, depthById, rootIds],
  )

  const roots = members.filter((m) => m.isRoot)

  const crossTeamCount = useMemo(() => {
    const teamIds = new Set(nodes.filter((n) => n.team === team).map((n) => n.id))
    const otherTeam = new Map(nodes.map((n) => [n.id, n.team]))
    return edges.filter((e) => {
      const srcIn = teamIds.has(e.source)
      const tgtIn = teamIds.has(e.target)
      if (srcIn === tgtIn) return false // wholly inside or wholly outside the team
      const peer = srcIn ? e.target : e.source
      return otherTeam.get(peer) !== undefined && otherTeam.get(peer) !== team
    }).length
  }, [nodes, edges, team])

  const unclaimed = isUnclaimedTeam(team)
  const label = teamLabel(team)

  return (
    <aside
      className="team-detail-panel"
      data-testid="team-detail-panel"
      data-unclaimed={unclaimed ? 'true' : undefined}
      aria-label={unclaimed ? 'Detail: agents belonging to no team' : `Team detail: ${label}`}
    >
      <header className="team-detail-panel__head">
        <div>
          <div className="team-detail-panel__eyebrow">{unclaimed ? 'no team' : 'team'}</div>
          <h2 className="team-detail-panel__title">{unclaimed ? `⚠ ${label}` : label}</h2>
          <div className="team-detail-panel__sub" data-testid="team-detail-roots">
            {members.length} agent{members.length === 1 ? '' : 's'} · {roots.length} root{roots.length === 1 ? '' : 's'}
          </div>
        </div>
        <button
          type="button"
          className="team-detail-panel__close"
          data-testid="team-detail-close"
          aria-label="Close team detail panel"
          onClick={onClose}
        >
          ✕
        </button>
      </header>

      {unclaimed && (
        <div className="team-detail-panel__note team-detail-panel__note--warn" data-testid="team-detail-unclaimed-note">
          These agents belong to no team, so no team-scoped policy or budget applies to them.
          Assigning each to a team is what brings it under team governance.
        </div>
      )}

      {roots.length > 1 && !unclaimed && (
        <div className="team-detail-panel__note" data-testid="team-detail-multiroot">
          {roots.length} independent root agents — each owns its delegation subtree within this team.
        </div>
      )}

      <section className="team-detail-panel__section">
        <div className="team-detail-panel__section-label">
          all members ({members.length})
        </div>
        <ul className="team-detail-panel__members">
          {members.map(({ node, depth, isRoot }) => {
            const inner = (
              <>
                <span
                  className="team-detail-panel__member-name"
                  style={{ paddingLeft: `${depth * 0.6}rem`, color: node.flagged ? 'var(--danger)' : 'var(--ink)' }}
                >
                  {depth > 0 ? '└ ' : ''}
                  {node.flagged ? '⚑ ' : ''}
                  {node.name}
                </span>
                <span className="team-detail-panel__member-meta">
                  <span style={{ color: statusColor(node.status) }}>●</span>
                  <span className="team-detail-panel__member-depth">L{depth}</span>
                </span>
              </>
            )
            return (
              <li key={node.id} data-testid="team-detail-member" data-node-id={node.id} data-root={isRoot ? 'true' : undefined}>
                {onSelectNode ? (
                  <button type="button" className="team-detail-panel__member-btn" onClick={() => onSelectNode(node)}>
                    {inner}
                  </button>
                ) : (
                  <div className="team-detail-panel__member-btn">{inner}</div>
                )}
              </li>
            )
          })}
        </ul>
      </section>

      {/* No cross-team count for the unclaimed group: an edge touching an agent
          with no team is not a boundary crossing — that is the server's own
          rule (`aa-api/src/routes/topology.rs:259`, which requires a team on
          *both* endpoints, mirrored by `/topology/edges`'s `is_cross_team`).
          Reporting a number here would have this panel contradict both the
          gateway and the sidebar's fleet-wide counter. */}
      {!unclaimed && (
        <section className="team-detail-panel__section">
          <div className="team-detail-panel__section-label">cross-team edges</div>
          <div className="team-detail-panel__crossteam" data-testid="team-detail-crossteam-count">
            {crossTeamCount} edge{crossTeamCount === 1 ? '' : 's'} to other teams
          </div>
        </section>
      )}
    </aside>
  )
}
