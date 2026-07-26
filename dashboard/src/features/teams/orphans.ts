/**
 * Who counts as an orphan agent, and whether the Teams page can account for
 * every agent it claims to group (AAASM-5157).
 *
 * The bug this module exists to prevent: the page derived its "unclaimed" list
 * from `/topology/overview`'s `standalone_root_agents`, which the gateway
 * filters as `depth == 0 && team_id.is_none()`. An agent spawned by a parent
 * (`depth > 0`) that no team claims therefore appeared in **no** grouping at
 * all — not under a team, not under unclaimed — while the same response's
 * `total_agent_count` still counted it. A governance console that silently
 * omits precisely the ungoverned agents is worse than one that shows nothing.
 *
 * Pure functions, no React: the predicate and the reconciliation are the part
 * worth testing on their own, independent of how the pane renders them.
 */
import { absent, certain, isAbsent, known, type Certain } from '../../lib/truthfulness'
import type { AgentNode, TopologyOverview } from './api'

/**
 * Whether an agent belongs to no team — the *only* thing that makes it an
 * orphan.
 *
 * Delegation depth deliberately plays no part. An agent is ungoverned when no
 * team-scoped policy or budget can reach it, and that is decided by `team_id`
 * alone; whether some other agent happened to spawn it is irrelevant to the
 * question the "No governance applied" view answers.
 *
 * `certain` decides what "missing" means so this file cannot drift from the
 * rest of the dashboard: `null`, `undefined` and `''` are absences (a blank
 * team id is not a team), while `0`/`false`/`[]` would be real values.
 */
export function isOrphanAgent(node: AgentNode): boolean {
  return isAbsent(certain(node.team_id, 'unconfigured'))
}

/** Every agent no team claims, at any delegation depth. */
export function selectOrphanAgents(nodes: readonly AgentNode[]): AgentNode[] {
  return nodes.filter(isOrphanAgent)
}

/**
 * The Teams page's two independent statements about the fleet, put side by
 * side: how many agents its groupings *display*, and how many the registry
 * *reports*.
 */
export interface AgentCensus {
  /** Agents reachable from a team row plus the unclaimed section. */
  readonly grouped: number
  /** `total_agent_count` — the registry's own tally for the same tenant scope. */
  readonly total: number
  /** `total - grouped`; non-zero means the page is hiding agents from itself. */
  readonly unaccountedFor: number
}

/**
 * Cross-check the groupings against the registry tally.
 *
 * Both figures come from the caller's own tenant scope with no filters applied,
 * so in a healthy system they are equal by construction. Any difference is a
 * real disagreement the operator must see rather than a number the page gets to
 * pick between — hence a `Certain`: if either side is missing there is no
 * verdict to report, and it says so instead of assuming agreement.
 */
export function reconcileAgentCensus(
  overview: TopologyOverview | undefined,
  orphans: Certain<readonly AgentNode[]>,
): Certain<AgentCensus> {
  if (!overview) return absent('unknown', 'Topology overview unavailable')
  if (isAbsent(orphans)) {
    return absent('unknown', 'Unclaimed agents could not be counted')
  }
  const inTeams = (overview.teams ?? []).reduce((sum, team) => sum + team.agent_count, 0)
  const grouped = inTeams + orphans.value.length
  return known({
    grouped,
    total: overview.total_agent_count,
    unaccountedFor: overview.total_agent_count - grouped,
  })
}
