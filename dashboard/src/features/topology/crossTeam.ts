/**
 * The single definition of "this edge crosses a team boundary" (AAASM-5138).
 *
 * Three surfaces need this answer — the sidebar's `⇆ N cross-team` counter, the
 * canvas's bowed-curve styling, and the per-node `⇆N` badge — and before this
 * module the first two each carried their own copy of the rule. That is exactly
 * how a counter and the picture it describes drift apart, which is the defect
 * this module exists to make impossible: one predicate, one source of truth.
 *
 * The rule itself defers to the server's own `crossTeam` flag (AAASM-5099), so
 * the dashboard agrees with what `/topology/edges` reports as `is_cross_team`,
 * and only falls back to comparing endpoint teams for a payload that predates
 * the flag.
 *
 * Pure functions — no React, no fetch — so the agreement between count and
 * canvas is unit-testable without rendering anything.
 */
import type { TopologyEdge, TopologyEdgeKind, TopologyNode } from './types'

/** Team lookup keyed by node id, built once per graph. */
export function teamById(nodes: readonly TopologyNode[]): ReadonlyMap<string, string> {
  return new Map(nodes.map((n) => [n.id, n.team]))
}

/**
 * Whether an edge joins two different teams.
 *
 * An edge whose endpoints are not both present in `teams` cannot be classified,
 * and an unclassifiable edge is *not* reported as cross-team: claiming a
 * boundary crossing we cannot demonstrate would inflate the counter with edges
 * that may be entirely intra-team.
 */
export function isCrossTeamEdge(edge: TopologyEdge, teams: ReadonlyMap<string, string>): boolean {
  if (edge.crossTeam !== undefined) return edge.crossTeam
  const source = teams.get(edge.source)
  const target = teams.get(edge.target)
  return source !== undefined && target !== undefined && source !== target
}

/** Every cross-team edge in the graph, in input order. */
export function crossTeamEdges(
  edges: readonly TopologyEdge[],
  teams: ReadonlyMap<string, string>,
): readonly TopologyEdge[] {
  return edges.filter((e) => isCrossTeamEdge(e, teams))
}

/** The canvas controls that can remove an edge from the drawing. */
export interface EdgeVisibility {
  /** Edge kinds the operator has left checked. `undefined` means all kinds. */
  readonly visibleKinds?: ReadonlySet<TopologyEdgeKind>
  /** The sidebar's "show cross-team" checkbox. Defaults to `true`. */
  readonly showCrossTeam?: boolean
}

/**
 * Whether the canvas will actually draw this edge.
 *
 * This is the **single** statement of what reaches the screen, used both by
 * `TopologyGraph` to build its geometry and by `TopologyPage` to work out how
 * many counted crossings the picture is not showing. Keeping the two in one
 * place is the whole point: the AAASM-5138 defect was a counter and a canvas
 * that each decided independently what was visible and then disagreed.
 *
 * Four things stop an edge being drawn, and all four must be accounted for by
 * anything that claims a number about the graph:
 *
 *  1. its kind is unchecked in the sidebar;
 *  2. an endpoint is off-screen (the team filter trimmed it);
 *  3. it is a self-edge, which has no geometry;
 *  4. it crosses a boundary while "show cross-team" is unchecked.
 */
export function isEdgeDrawn(
  edge: TopologyEdge,
  visibleNodeIds: ReadonlySet<string>,
  teams: ReadonlyMap<string, string>,
  visibility: EdgeVisibility = {},
): boolean {
  const { visibleKinds, showCrossTeam = true } = visibility
  if (visibleKinds && !visibleKinds.has(edge.kind)) return false
  if (!visibleNodeIds.has(edge.source) || !visibleNodeIds.has(edge.target)) return false
  if (edge.source === edge.target) return false
  if (!showCrossTeam && isCrossTeamEdge(edge, teams)) return false
  return true
}

/**
 * How many cross-team edges the sidebar counts but the canvas is not drawing.
 *
 * The counter is a fleet-wide fact and stays one; this is the gap between it and
 * the picture, which the sidebar renders rather than leaving the operator to
 * infer. Deriving it as `counted − drawn` means it is correct for *every* reason
 * an edge can vanish, including the ones a per-node badge cannot express: a
 * crossing between two teams that are both off-screen belongs to neither visible
 * node, and unchecking "show cross-team" hides every curve while no team filter
 * is active at all.
 */
export function hiddenCrossTeamCount(
  edges: readonly TopologyEdge[],
  visibleNodeIds: ReadonlySet<string>,
  teams: ReadonlyMap<string, string>,
  visibility: EdgeVisibility = {},
): number {
  const crossings = crossTeamEdges(edges, teams)
  const drawn = crossings.filter((e) => isEdgeDrawn(e, visibleNodeIds, teams, visibility)).length
  return crossings.length - drawn
}

/**
 * Cross-team edge degree per node id — how many boundary-crossing relationships
 * each agent has, counting both directions.
 *
 * This is what the `⇆N` card badge renders. It is computed over the *whole*
 * graph, not the filtered view, which is the entire point: when a team filter
 * hides the far endpoint, the edge disappears from the canvas, and the badge is
 * what stops the remaining picture from reading as "this team has no external
 * dependencies" (`design/v2/hi-fi/topology.jsx:379-382,457`).
 *
 * A self-edge is skipped: it cannot cross a boundary, and counting it twice on
 * one node would misreport the degree.
 */
export function crossTeamDegreeByNode(
  edges: readonly TopologyEdge[],
  teams: ReadonlyMap<string, string>,
): ReadonlyMap<string, number> {
  const degree = new Map<string, number>()
  for (const edge of crossTeamEdges(edges, teams)) {
    if (edge.source === edge.target) continue
    degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1)
    degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1)
  }
  return degree
}
