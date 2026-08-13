import type { CapabilityAgent, Resource, Verb } from './types'
import { VERBS } from './types'

/**
 * How many cells of the loaded grid carry a decision for one verb.
 *
 * A missing cap cell counts the same as an explicit `na`: both mean the
 * resource is outside that agent's scope, which is precisely the "nothing to
 * look at" the caller is trying to avoid landing the operator on.
 */
function populatedCellCount(agents: CapabilityAgent[], resources: Resource[], verb: Verb): number {
  let n = 0
  for (const agent of agents) {
    for (const resource of resources) {
      if ((agent.caps[resource.id]?.[verb] ?? 'na') !== 'na') n += 1
    }
  }
  return n
}

/**
 * The verb the Capability matrix should open on (AAASM-5125).
 *
 * The page used to hard-code `write`, which is the *least* representative
 * choice the projection can offer. `project_matrix` models read/write/delete on
 * the Filesystem column alone; Terminal, Network-outbound and every MCP-tool
 * column carry `exec` and nothing else
 * (`aa-api/src/routes/capability.rs:497-524`, `:626-641`). Landing on `write`
 * therefore showed one populated column beside a wall of `n/a`, and the
 * operator had to discover `exec` before the flagship governance page showed
 * anything.
 *
 * The default is derived from the loaded matrix rather than hard-coded to
 * `exec`, because the honest statement is *open on the verb this projection
 * actually populates*, not *open on the verb that happens to win today*. The
 * measure is the number of non-`na` cells: for any non-empty fleet that is
 * `agents × 1` for write against `agents × (2 + tools)` for exec, so it resolves
 * to `exec` on today's projection — the answer the ticket predicted, but reached
 * from the data, so it follows the backend if the capability families ever
 * change (AAASM-5090) instead of silently going stale.
 *
 * Ties resolve to the first verb in `VERBS` order. A tie only happens when the
 * grid gives no reason to prefer one verb — including the degenerate
 * all-`na`/empty grid, which the page never renders (it shows `EmptyState` or
 * `LoadingState` instead) — so the tie-break is deterministic rather than
 * meaningful, which is the most it can honestly be.
 *
 * This is a *default*, not a constraint: an operator's own choice always wins,
 * and the segmented control still offers all four verbs.
 */
export function defaultVerb(agents: CapabilityAgent[], resources: Resource[]): Verb {
  let best: Verb = VERBS[0]
  let bestCount = -1
  for (const verb of VERBS) {
    const n = populatedCellCount(agents, resources, verb)
    if (n > bestCount) {
      best = verb
      bestCount = n
    }
  }
  return best
}
