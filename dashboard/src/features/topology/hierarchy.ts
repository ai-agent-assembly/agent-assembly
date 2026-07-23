import type { TopologyEdge, TopologyNode } from './types'

/**
 * Delegation-graph analysis for the topology view (AAASM-5033).
 *
 * Root markers, hierarchical depth, and cycle detection all read the SAME
 * sub-graph — the `delegation` edges — because that is the parent→child
 * hierarchy the topology renders. `call` (and any future lateral) edges are
 * relationships, not structure, so including them would make a node's depth,
 * root-ness, and cycle membership disagree with one another. Keeping the three
 * on one graph means every badge is a consistent statement about the node's
 * place in the delegation forest.
 *
 * These are pure functions over the node/edge lists — no layout positions, no
 * server round-trip — so the analysis runs entirely client-side. The hi-fi
 * reference (`design/v1/hi-fi/topology.jsx` `topoDetectCycles`) ports the same
 * idea; this is the typed, delegation-scoped equivalent.
 */

const DELEGATION: TopologyEdge['kind'] = 'delegation'

export interface HierarchyResult {
  /** Depth of each node in the delegation forest; every root is 0. */
  readonly depthById: ReadonlyMap<string, number>
  /** Ids of nodes with no incoming delegation edge (delegation-tree roots). */
  readonly rootIds: ReadonlySet<string>
}

/** source → [targets] adjacency over delegation edges only. */
function delegationAdjacency(edges: readonly TopologyEdge[]): Map<string, string[]> {
  const adj = new Map<string, string[]>()
  for (const e of edges) {
    if (e.kind !== DELEGATION) continue
    const list = adj.get(e.source)
    if (list) list.push(e.target)
    else adj.set(e.source, [e.target])
  }
  return adj
}

/**
 * Node ids that sit on a delegation cycle, via Tarjan's strongly-connected-
 * components algorithm. A node is on a cycle when its SCC has more than one
 * member, or it delegates to itself (a self-loop). Only `delegation` edges are
 * considered — see the module doc for why.
 */
export function detectDelegationCycles(edges: readonly TopologyEdge[]): ReadonlySet<string> {
  const adj = delegationAdjacency(edges)
  const nodes = new Set<string>()
  for (const e of edges) {
    if (e.kind !== DELEGATION) continue
    nodes.add(e.source)
    nodes.add(e.target)
  }

  let counter = 0
  const index = new Map<string, number>()
  const low = new Map<string, number>()
  const onStack = new Set<string>()
  const stack: string[] = []
  const cycleNodes = new Set<string>()

  const strongConnect = (v: string): void => {
    index.set(v, counter)
    low.set(v, counter)
    counter += 1
    stack.push(v)
    onStack.add(v)

    for (const w of adj.get(v) ?? []) {
      if (!index.has(w)) {
        strongConnect(w)
        low.set(v, Math.min(low.get(v)!, low.get(w)!))
      } else if (onStack.has(w)) {
        low.set(v, Math.min(low.get(v)!, index.get(w)!))
      }
    }

    if (low.get(v) === index.get(v)) {
      const scc: string[] = []
      let w: string
      do {
        w = stack.pop()!
        onStack.delete(w)
        scc.push(w)
      } while (w !== v)
      const selfLoop = (adj.get(v) ?? []).includes(v)
      if (scc.length > 1 || selfLoop) {
        for (const id of scc) cycleNodes.add(id)
      }
    }
  }

  for (const n of nodes) if (!index.has(n)) strongConnect(n)
  return cycleNodes
}

/**
 * Delegation-tree roots and per-node depth.
 *
 * - A **root** is any node with no incoming delegation edge (BFS start, depth
 *   0). Isolated nodes — no delegation edges at all — are therefore roots too.
 * - **Depth** is the shortest delegation-hop distance from a root. The first
 *   (shortest) path wins, and already-visited nodes are skipped, so a cycle
 *   cannot re-enqueue a node into an infinite loop.
 * - A node reachable only through a pure cycle (no external root) is never hit
 *   by the BFS; it falls back to depth 0 so every node always has a depth.
 */
export function computeHierarchy(
  nodes: readonly TopologyNode[],
  edges: readonly TopologyEdge[],
): HierarchyResult {
  const adj = delegationAdjacency(edges)
  const hasIncoming = new Set<string>()
  for (const e of edges) {
    if (e.kind !== DELEGATION) continue
    hasIncoming.add(e.target)
  }

  const rootIds = new Set<string>()
  for (const n of nodes) if (!hasIncoming.has(n.id)) rootIds.add(n.id)

  const depthById = new Map<string, number>()
  const queue: Array<{ id: string; depth: number }> = []
  for (const id of rootIds) {
    depthById.set(id, 0)
    queue.push({ id, depth: 0 })
  }

  while (queue.length) {
    const { id, depth } = queue.shift()!
    for (const child of adj.get(id) ?? []) {
      if (depthById.has(child)) continue
      depthById.set(child, depth + 1)
      queue.push({ id: child, depth: depth + 1 })
    }
  }

  for (const n of nodes) if (!depthById.has(n.id)) depthById.set(n.id, 0)

  return { depthById, rootIds }
}
