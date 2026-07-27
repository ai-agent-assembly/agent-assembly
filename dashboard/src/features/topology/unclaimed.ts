/**
 * The Topology surface's single definition of the group holding every agent no
 * team claims (AAASM-5184).
 *
 * The defect this module ends: `mapGraph` coerced a null `team_id` to `''`, and
 * every consumer downstream then treated that empty string as if it were a team
 * name. The header counted it in `N teams`, the sidebar offered a filter row
 * with an empty label, and the canvas drew an unlabelled cluster — three
 * separate statements asserting a team that does not exist.
 *
 * A team-less agent is a **real, known state**, not an absence. Reaching for
 * `lib/truthfulness`'s `NO_DATA` here would say "we could not find out which
 * team this is", when what we know is the opposite and more specific: no team
 * claims it. So the group is named and rendered like any other grouping, and
 * only the *team count* stops including it.
 *
 * The membership rule is deliberately **not** restated here. It is
 * `isOrphanAgent` from `features/teams/orphans.ts` — the definition AAASM-5157
 * established for the Teams page's unclaimed section. Two surfaces disagreeing
 * about what "unclaimed" means is precisely the failure `lib/truthfulness`
 * exists to prevent, so this module imports that predicate rather than forking a
 * second `team_id == null` test.
 */
import type { components } from '../../api/generated/schema'
import { isOrphanAgent } from '../teams/orphans'

type ApiNode = components['schemas']['AgentNode']

/**
 * Group key for agents no team claims.
 *
 * `design/v2/hi-fi/topology.jsx` (authoritative per ADR-0025) keys this group as
 * `__orphan__` — at `:190` for the cluster treatment, `:664` for the detail
 * panel and `:928` for the team count — so the key is reused verbatim and the
 * implementation cannot drift from the spec it is built against.
 *
 * It is a sentinel sharing a namespace with real team ids, so a team literally
 * named `__orphan__` would be mislabelled. That is accepted deliberately: the
 * alternative — widening `TopologyNode['team']` to `string | null` — pushes the
 * same either/or into the force layout, the filter state, and every
 * `Map<string, …>` keyed by team, in exchange for a collision no registry has
 * produced.
 */
export const UNCLAIMED_TEAM = '__orphan__'

/** Operator-facing name for the {@link UNCLAIMED_TEAM} group. */
export const UNCLAIMED_TEAM_LABEL = 'Unclaimed'

/** Whether a group key denotes the unclaimed group rather than a real team. */
export function isUnclaimedTeam(team: string): boolean {
  return team === UNCLAIMED_TEAM
}

/**
 * The group key for a wire node: its `team_id`, or {@link UNCLAIMED_TEAM} when
 * no team claims it.
 *
 * `isOrphanAgent` is the sole authority on what "no team" means, and it already
 * treats `null`, `undefined`, `''` and whitespace-only ids alike — so a node it
 * rejects is one carrying a real id. The `teamId` test that remains is type
 * narrowing (`string | null | undefined` → `string`), not a second rule: it can
 * only be falsy when `isOrphanAgent` has already returned `true`.
 *
 * A real id is returned **unchanged**, not trimmed, so the group still keys on
 * exactly what was registered — the same choice `aa-api`'s `team_of` makes.
 */
export function teamKeyOf(node: ApiNode): string {
  const teamId = node.team_id
  return !isOrphanAgent(node) && teamId ? teamId : UNCLAIMED_TEAM
}

/** How a group key should read on screen. */
export function teamLabel(team: string): string {
  return isUnclaimedTeam(team) ? UNCLAIMED_TEAM_LABEL : team
}

/**
 * The real teams among `teams`, with the unclaimed group removed.
 *
 * This is what `N teams` must be counted from: the unclaimed group is a
 * grouping the page renders, never a team the registry holds
 * (`design/v2/hi-fi/topology.jsx:928`).
 */
export function realTeams(teams: readonly string[]): readonly string[] {
  return teams.filter((t) => !isUnclaimedTeam(t))
}

/** How many graph nodes belong to no team. */
export function countUnclaimed(nodes: readonly { readonly team: string }[]): number {
  return nodes.filter((n) => isUnclaimedTeam(n.team)).length
}
