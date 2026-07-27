import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent, type MouseEvent as ReactMouseEvent } from 'react'
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type Simulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force'
import type { TopologyEdge, TopologyNode } from '../../features/topology/types'
import { computeHierarchy, detectDelegationCycles } from '../../features/topology/hierarchy'
import { crossTeamDegreeByNode, isCrossTeamEdge, isEdgeDrawn, teamById } from '../../features/topology/crossTeam'
import { isUnclaimedTeam, teamLabel } from '../../features/topology/unclaimed'
import { NO_DATA, TRUTH_STATE_META } from '../../lib/truthfulness'
import { TeamBudgetBar } from './TeamBudgetBar'
import { Tooltip } from '../Tooltip'
import './TopologyGraph.css'

const SIZE_VARIANT: Record<'small' | 'medium' | 'large', { w: number; h: number }> = {
  small: { w: 76, h: 44 },
  medium: { w: 96, h: 56 },
  large: { w: 116, h: 68 },
}

const CLUSTER_PADDING = 18
const TEAM_LABEL_HEIGHT = 36
const TEAM_BUDGET_BAR_HEIGHT = 32

/**
 * Vertical pull, in px per delegation level, that makes the layout
 * depth-informed (AAASM-5033): a node's `teamY` target is offset downward by
 * `depth * DEPTH_ROW_GAP` so roots settle above their delegates within each
 * team cluster, giving a top-down tree feel. It is a soft force layered on top
 * of team clustering + collision, not a rigid grid — the existing
 * `forceCollide` still prevents overlap.
 */
const DEPTH_ROW_GAP = 62

/**
 * Leading glyph for the enforcement-mode badge, mirroring the hi-fi reference
 * (`design/v1/hi-fi/topology.jsx`): filled dot = enforce, half dot = shadow,
 * hollow dot = off. Colour is applied per-mode via CSS (see TopologyGraph.css).
 */
const MODE_GLYPH: Record<NonNullable<TopologyNode['mode']>, string> = {
  enforce: '●',
  shadow: '◐',
  off: '○',
}

/**
 * Per-kind edge styling, mirroring the hi-fi reference edge config
 * (`design/v1/hi-fi/topology.jsx` TOPO_EC). All six kinds the projection emits
 * (AAASM-5099) are styled: `delegation` as the primary solid line, the rest as
 * lighter dashed lines with distinct patterns so overlapping relations between
 * the same pair stay tellable apart.
 *
 * Dash patterns match `features/topology/edgeKinds.ts` so an edge on the canvas
 * looks like its sidebar swatch.
 *
 * `strokeWidth` is inlined; colour comes from CSS variables via the
 * `.topology-edge--<kind>` class so edges re-theme in light/dark like the rest
 * of the graph (the design's raw hex would not).
 */
const EDGE_STYLE: Record<TopologyEdge['kind'], { width: number; dash?: string }> = {
  delegation: { width: 1.75 },
  call: { width: 1.5, dash: '6 4' },
  reads: { width: 1.5, dash: '3 4' },
  writes: { width: 1.5, dash: '3 4' },
  approves: { width: 1.5, dash: '8 3' },
  messages: { width: 1, dash: '2 5' },
}

const EDGE_KINDS = Object.keys(EDGE_STYLE) as ReadonlyArray<TopologyEdge['kind']>

interface EdgeGeometry {
  readonly key: string
  readonly kind: TopologyEdge['kind']
  readonly crossTeam: boolean
  readonly d: string
}

/**
 * Point where the ray from a node centre toward `(towardX, towardY)` exits the
 * node's rectangular card. Used so an edge starts/ends flush against the card
 * border — the arrowhead then sits on the target card edge instead of being
 * hidden underneath it.
 */
function rectBorderPoint(
  cx: number,
  cy: number,
  w: number,
  h: number,
  towardX: number,
  towardY: number,
): { x: number; y: number } {
  const dx = towardX - cx
  const dy = towardY - cy
  if (dx === 0 && dy === 0) return { x: cx, y: cy }
  const scaleX = dx !== 0 ? w / 2 / Math.abs(dx) : Infinity
  const scaleY = dy !== 0 ? h / 2 / Math.abs(dy) : Infinity
  const scale = Math.min(scaleX, scaleY)
  return { x: cx + dx * scale, y: cy + dy * scale }
}

interface PositionedNode extends SimulationNodeDatum {
  id: string
  source: TopologyNode
}

interface PositionedEdge extends SimulationLinkDatum<PositionedNode> {
  kind: TopologyEdge['kind']
}

interface TeamLayoutEntry {
  readonly team: string
  readonly cx: number
  readonly cy: number
  readonly spent: number
  /**
   * Summed member ceilings, or `null` when any member has none configured.
   *
   * A total over a set with a hole in it is not a total. If one agent's limit is
   * unknown, the team's ceiling is unknown too — summing only the members that
   * happen to have one would understate the team's real budget and make the
   * cluster look closer to its limit than it is (AAASM-5135).
   */
  readonly limit: number | null
  readonly memberCount: number
}

/** Zoom bounds + step, mirroring the hi-fi reference (`TopoCanvas`). */
const ZOOM_MIN = 0.25
const ZOOM_MAX = 2.5
const ZOOM_BUTTON_STEP = 1.2
const ZOOM_WHEEL_IN = 1.09
const ZOOM_WHEEL_OUT = 0.91
/** Pointer travel (px) past which a mousedown→up is a pan, not a click. */
const PAN_CLICK_THRESHOLD = 4

const clampZoom = (z: number): number => Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, z))

export interface TopologyGraphProps {
  readonly nodes: readonly TopologyNode[]
  readonly edges: readonly TopologyEdge[]
  readonly width?: number
  readonly height?: number
  readonly onNodeClick?: (node: TopologyNode) => void
  /**
   * Which edge kinds to draw. When omitted, every kind renders (back-compat).
   * The sidebar edge-type checkboxes drive this so operators can declutter the
   * mesh (AAASM-5071).
   */
  readonly visibleKinds?: ReadonlySet<TopologyEdge['kind']>
  /** Draw cross-team (curved) edges. Defaults to `true`. */
  readonly showCrossTeam?: boolean
  /** Team whose cluster is highlighted (from the team panel selection). */
  readonly selectedTeam?: string | null
  /** Node whose card is highlighted (from the node panel selection). */
  readonly selectedNodeId?: string | null
  /** Fired when a team cluster is clicked (opens the team panel). */
  readonly onTeamClick?: (team: string) => void
  /** Fired when empty canvas is clicked (clears any open panel). */
  readonly onBackgroundClick?: () => void
  /**
   * The *unfiltered* edge set, used only to compute each visible node's
   * cross-team degree for the `⇆N` badge (AAASM-5138).
   *
   * `edges` above is the drawable set — already trimmed to edges whose two
   * endpoints are both on screen. That trimming is what silently deleted a
   * team's external relationships from the canvas while the sidebar went on
   * counting them, so the badge needs the untrimmed set to say how many were
   * dropped. Defaults to `edges`, which makes the badge zero everywhere when no
   * filter is applied — the correct answer, since nothing was dropped.
   */
  readonly allEdges?: readonly TopologyEdge[]
  /**
   * All graph nodes, unfiltered — needed to classify an edge whose far endpoint
   * is hidden. Defaults to `nodes`.
   */
  readonly allNodes?: readonly TopologyNode[]
  /**
   * Whether a team filter is currently narrowing the canvas.
   *
   * The badge is only shown while filtering, per `design/v2/hi-fi/topology.jsx`
   * (`crossTeamBadge={filterTeam !== 'all' ? … : 0}`): with the whole fleet on
   * screen every cross-team edge is already drawn, so a badge would restate
   * what the operator can see.
   */
  readonly teamFilterActive?: boolean
}

/**
 * Force-directed agent topology graph (AAASM-1335) with team clustering
 * + team-level budget overlay (AAASM-1339).
 *
 * - Nodes are rectangular cards with a status stripe on the left
 *   (mirrors `design/v1/hi-fi/topology.jsx` TopoNodeEl).
 * - Same-team nodes are pulled together via per-team `forceX/forceY`
 *   centers; each team renders as a rounded-rect cluster outline with
 *   a team label and budget bar above it.
 */
export function TopologyGraph({
  nodes,
  edges,
  width = 800,
  height = 500,
  onNodeClick,
  visibleKinds,
  showCrossTeam = true,
  selectedTeam,
  selectedNodeId,
  onTeamClick,
  onBackgroundClick,
  allEdges,
  allNodes,
  teamFilterActive = false,
}: TopologyGraphProps) {
  // Cross-team degree over the *whole* graph (AAASM-5138). Computed even when
  // no filter is active so the memo identity is stable; the badge itself is
  // gated on `teamFilterActive` at render time.
  const crossTeamDegree = useMemo(() => {
    const edgeSet = allEdges ?? edges
    const nodeSet = allNodes ?? nodes
    return crossTeamDegreeByNode(edgeSet, teamById(nodeSet))
  }, [allEdges, allNodes, edges, nodes])

  // Stable identity key — restart the sim only when the *set* of node/edge
  // ids changes, not on every parent re-render.
  const identityKey = useMemo(() => {
    const nodeIds = nodes.map(n => n.id).join(',')
    const edgeIds = edges.map(e => `${e.source}->${e.target}`).join(',')
    return `${nodeIds}|${edgeIds}`
  }, [nodes, edges])

  // Distinct teams, as a *string* key rather than an array identity.
  //
  // The force simulation is keyed off this (via `teamCenters`) so that a poll
  // carrying new spend figures for the same agents does not look like a new
  // layout. Before AAASM-5136 the graph only re-simulated on focus or a
  // mutation; a 5s poll made that recurring, and re-running the simulation
  // re-scatters every card from an un-positioned start — moving click targets
  // under the operator every 5 seconds on a live fleet.
  const teamsKey = useMemo(() => [...new Set(nodes.map(n => n.team))].join(' '), [nodes])

  /**
   * Live node data by id.
   *
   * Because the simulation is no longer rebuilt on a metrics-only update, the
   * `source` object each `PositionedNode` closed over is the one from the
   * payload that built the sim — and would go stale the moment spend or status
   * changed. Every read of node *data* therefore goes through this map, while
   * `positions` supplies only geometry. Getting this wrong is how "stop
   * re-scattering the graph" would silently have become "stop updating it".
   */
  const nodeById = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes])

  /** Team lookup for edge classification. Hoisted so it is not rebuilt per tick. */
  const nodeTeams = useMemo(() => teamById(nodes), [nodes])

  // Cluster centers: a grid laid out left-to-right, top-to-bottom. Depends only
  // on *which* teams exist and the canvas size — never on their budgets — so it
  // stays referentially stable across a metrics-only payload update.
  const teamCenters = useMemo<ReadonlyMap<string, { cx: number; cy: number }>>(() => {
    const teams = teamsKey === '' ? [] : teamsKey.split(' ')
    let cols = 4
    if (teams.length <= 2) cols = teams.length
    else if (teams.length <= 6) cols = 3
    const rows = Math.max(1, Math.ceil(teams.length / cols))
    const cellW = width / Math.max(1, cols)
    const cellH = height / rows
    const m = new Map<string, { cx: number; cy: number }>()
    teams.forEach((team, i) => {
      m.set(team, { cx: cellW * ((i % cols) + 0.5), cy: cellH * (Math.floor(i / cols) + 0.5) })
    })
    return m
  }, [teamsKey, width, height])

  // Per-team aggregates for the cluster label and budget bar. These *do* change
  // with every payload, which is why they are kept out of the layout memo above.
  const teamLayout = useMemo<readonly TeamLayoutEntry[]>(() => {
    const byTeam = new Map<string, { spent: number; limit: number | null; memberCount: number }>()
    for (const n of nodes) {
      const entry = byTeam.get(n.team) ?? { spent: 0, limit: 0, memberCount: 0 }
      entry.spent += n.budgetSpend
      // One unconfigured member limit makes the whole team total unknown — see
      // `TeamLayoutEntry.limit`. Once null it stays null.
      entry.limit = entry.limit === null || n.budgetLimit === null ? null : entry.limit + n.budgetLimit
      entry.memberCount += 1
      byTeam.set(n.team, entry)
    }
    return [...byTeam.keys()].map((team) => {
      const meta = byTeam.get(team)!
      const center = teamCenters.get(team) ?? { cx: width / 2, cy: height / 2 }
      return {
        team,
        cx: center.cx,
        cy: center.cy,
        spent: meta.spent,
        limit: meta.limit,
        memberCount: meta.memberCount,
      }
    })
  }, [nodes, teamCenters, width, height])

  // Delegation-tree analysis (AAASM-5033): per-node depth + root ids feed the
  // depth-informed layout and the root/depth badges; cycle ids drive the cycle
  // marker. All derived client-side from the edge data — no server round-trip.
  const { depthById, rootIds } = useMemo(() => computeHierarchy(nodes, edges), [nodes, edges])
  const cycleNodeIds = useMemo(() => detectDelegationCycles(edges), [edges])

  const simulation = useMemo<Simulation<PositionedNode, PositionedEdge>>(() => {
    const positioned: PositionedNode[] = nodes.map(n => ({ id: n.id, source: n }))
    const links: PositionedEdge[] = edges.map(e => ({ source: e.source, target: e.target, kind: e.kind }))
    return forceSimulation<PositionedNode, PositionedEdge>(positioned)
      .force('link', forceLink<PositionedNode, PositionedEdge>(links).id(d => d.id).distance(120))
      .force('charge', forceManyBody().strength(-220))
      .force('center', forceCenter(width / 2, height / 2).strength(0.05))
      // `teamCenters` is derived from the same `nodes` as the simulation's
      // nodes, so every node's team is always present — the `?? width/2` /
      // `?? height/2` fallbacks are unreachable defensive guards (dead branch),
      // so the two lines are excluded from coverage.
      /* v8 ignore start */
      .force('teamX', forceX<PositionedNode>(d => teamCenters.get(d.source.team)?.cx ?? width / 2).strength(0.12))
      // Depth-informed vertical target: team center shifted down by the node's
      // delegation depth so roots sit above their delegates within the cluster.
      .force('teamY', forceY<PositionedNode>(d =>
        (teamCenters.get(d.source.team)?.cy ?? height / 2) + (depthById.get(d.id) ?? 0) * DEPTH_ROW_GAP,
      ).strength(0.12))
      /* v8 ignore stop */
      // Keep same-team cards from stacking: the teamX/teamY centers pull all
      // members to one point, so without a collision force they overlap. Size
      // the collision circle to the card's half-width (widest dimension) plus a
      // gap so neither the card nor its inside-the-card labels visually clash.
      .force('collide', forceCollide<PositionedNode>()
        .radius(d => SIZE_VARIANT[bucketForRatio(d.source.budgetSpend, d.source.budgetLimit)].w / 2 + 10)
        .strength(0.85))
      .stop()
    // Deps are deliberately the *structural* identity (`identityKey`, and
    // `teamCenters`, which is memoised on `teamsKey`) rather than the `nodes` /
    // `edges` array identities. A poll that reports new spend for the same
    // agents must not rebuild the simulation: doing so restarts it at
    // `alpha(1)` over freshly-constructed, un-positioned nodes and re-scatters
    // the whole graph (AAASM-5136).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identityKey, width, height, teamCenters])

  const [positions, setPositions] = useState<readonly PositionedNode[]>(
    () => (simulation.nodes() as PositionedNode[]).map(n => ({ ...n })),
  )

  useEffect(() => {
    let alive = true
    const sim = simulation
    sim.on('tick', () => {
      if (!alive) return
      setPositions((sim.nodes() as PositionedNode[]).map(n => ({ ...n })))
    })
    sim.alpha(1).restart()
    return () => {
      alive = false
      sim.on('tick', null)
      sim.stop()
    }
  }, [simulation])

  // Cluster bounding boxes derived from current positions per team. Node data
  // is read live (see `nodeById`) because `p.source` predates the last poll.
  const clusters = useMemo(() => {
    const liveNode = (p: PositionedNode) => nodeById.get(p.id) ?? p.source
    const byTeam = new Map<string, PositionedNode[]>()
    for (const p of positions) {
      const team = liveNode(p).team
      const arr = byTeam.get(team) ?? []
      arr.push(p)
      byTeam.set(team, arr)
    }
    return teamLayout.map(t => {
      const members = byTeam.get(t.team) ?? []
      if (members.length === 0) {
        return { ...t, x: t.cx - 60, y: t.cy - 40, w: 120, h: 80 }
      }
      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
      for (const p of members) {
        const member = liveNode(p)
        const dims = SIZE_VARIANT[bucketForRatio(member.budgetSpend, member.budgetLimit)]
        const cx = p.x ?? t.cx
        const cy = p.y ?? t.cy
        minX = Math.min(minX, cx - dims.w / 2)
        maxX = Math.max(maxX, cx + dims.w / 2)
        minY = Math.min(minY, cy - dims.h / 2)
        maxY = Math.max(maxY, cy + dims.h / 2)
      }
      return {
        ...t,
        x: minX - CLUSTER_PADDING,
        y: minY - CLUSTER_PADDING - TEAM_LABEL_HEIGHT - TEAM_BUDGET_BAR_HEIGHT,
        w: maxX - minX + CLUSTER_PADDING * 2,
        h: maxY - minY + CLUSTER_PADDING * 2 + TEAM_LABEL_HEIGHT + TEAM_BUDGET_BAR_HEIGHT,
      }
    })
  }, [positions, teamLayout, nodeById])

  // Edge geometry derived from settled node positions. Intra-team edges are
  // straight lines; cross-team edges bow out along a quadratic curve so they
  // read as distinct long-range relationships rather than crossing clutter.
  // Endpoints are trimmed to each card's border so arrowheads land on the
  // target card edge. Drawn under the node cards (see render order below).
  const edgeGeometries = useMemo<readonly EdgeGeometry[]>(() => {
    const posById = new Map<string, PositionedNode>()
    for (const p of positions) posById.set(p.id, p)
    const drawnIds = new Set(posById.keys())

    const geoms: EdgeGeometry[] = []
    edges.forEach((edge, i) => {
      // One shared predicate decides what reaches the screen, so the sidebar's
      // hidden-crossing count and this canvas cannot disagree (AAASM-5138).
      if (!isEdgeDrawn(edge, drawnIds, nodeTeams, { visibleKinds, showCrossTeam })) return
      const src = posById.get(String(edge.source))
      const tgt = posById.get(String(edge.target))
      /* v8 ignore next -- `isEdgeDrawn` already required both ids in `drawnIds`. */
      if (!src || !tgt) return
      const crossTeam = isCrossTeamEdge(edge, nodeTeams)

      const srcNode = nodeById.get(src.id) ?? src.source
      const tgtNode = nodeById.get(tgt.id) ?? tgt.source
      const sDims = SIZE_VARIANT[bucketForRatio(srcNode.budgetSpend, srcNode.budgetLimit)]
      const tDims = SIZE_VARIANT[bucketForRatio(tgtNode.budgetSpend, tgtNode.budgetLimit)]
      const scx = src.x ?? width / 2
      const scy = src.y ?? height / 2
      const tcx = tgt.x ?? width / 2
      const tcy = tgt.y ?? height / 2

      const start = rectBorderPoint(scx, scy, sDims.w, sDims.h, tcx, tcy)
      const end = rectBorderPoint(tcx, tcy, tDims.w, tDims.h, scx, scy)

      let d: string
      if (crossTeam) {
        // Perpendicular offset at the midpoint gives the bowed control point.
        const mx = (start.x + end.x) / 2
        const my = (start.y + end.y) / 2
        const vx = end.x - start.x
        const vy = end.y - start.y
        const len = Math.hypot(vx, vy) || 1
        const off = Math.min(60, len * 0.25)
        const ctrlX = mx + (-vy / len) * off
        const ctrlY = my + (vx / len) * off
        d = `M${start.x} ${start.y} Q${ctrlX} ${ctrlY} ${end.x} ${end.y}`
      } else {
        d = `M${start.x} ${start.y} L${end.x} ${end.y}`
      }

      geoms.push({ key: `${edge.source}->${edge.target}-${edge.kind}-${i}`, kind: edge.kind, crossTeam, d })
    })
    return geoms
  }, [edges, positions, width, height, visibleKinds, showCrossTeam, nodeTeams, nodeById])

  // ── Pan + zoom (AAASM-5071) ────────────────────────────────────────────────
  // Wheel zooms, drag pans, and the overlay buttons step/reset — the same
  // scheme as the hi-fi reference (`TopoCanvas`). The transform lives on a
  // wrapper <g>, so each node's own `translate(x,y)` (which layout + tests read)
  // is untouched. A React `onWheel` would have to be passive; we attach a
  // non-passive listener via ref so `preventDefault()` stops the page scrolling.
  const svgRef = useRef<SVGSVGElement>(null)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [zoom, setZoom] = useState(1)
  const [dragging, setDragging] = useState(false)
  const dragRef = useRef<{ mx: number; my: number; px: number; py: number; moved: boolean } | null>(null)

  useEffect(() => {
    const el = svgRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      setZoom(z => clampZoom(z * (e.deltaY > 0 ? ZOOM_WHEEL_OUT : ZOOM_WHEEL_IN)))
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [])

  const handleMouseDown = (e: ReactMouseEvent<SVGSVGElement>) => {
    // Grabbing a node starts a selection, not a pan.
    if ((e.target as Element).closest('[data-testid="topology-node"]')) return
    setDragging(true)
    dragRef.current = { mx: e.clientX, my: e.clientY, px: pan.x, py: pan.y, moved: false }
  }
  const handleMouseMove = (e: ReactMouseEvent<SVGSVGElement>) => {
    const d = dragRef.current
    if (!dragging || !d) return
    const dx = e.clientX - d.mx
    const dy = e.clientY - d.my
    if (Math.abs(dx) > PAN_CLICK_THRESHOLD || Math.abs(dy) > PAN_CLICK_THRESHOLD) d.moved = true
    setPan({ x: d.px + dx, y: d.py + dy })
  }
  const endDrag = () => setDragging(false)

  // A cluster/background click that concludes a pan-drag must not also select.
  const consumePanClick = (): boolean => {
    const moved = dragRef.current?.moved ?? false
    dragRef.current = null
    return moved
  }

  const handleBackgroundClick = (e: ReactMouseEvent<SVGSVGElement>) => {
    if (consumePanClick()) return
    const target = e.target as Element
    if (target.closest('[data-testid="topology-node"]') || target.closest('[data-testid="team-cluster"]')) return
    onBackgroundClick?.()
  }

  const zoomIn = useCallback(() => setZoom(z => clampZoom(+(z * ZOOM_BUTTON_STEP).toFixed(2))), [])
  const zoomOut = useCallback(() => setZoom(z => clampZoom(+(z / ZOOM_BUTTON_STEP).toFixed(2))), [])
  const resetView = useCallback(() => { setPan({ x: 0, y: 0 }); setZoom(1) }, [])

  return (
    <div className="topology-graph-wrap" data-testid="topology-graph-wrap">
    <svg
      ref={svgRef}
      className="topology-graph"
      data-testid="topology-graph"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Agent topology graph"
      style={{ cursor: dragging ? 'grabbing' : 'grab', touchAction: 'none' }}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={endDrag}
      onMouseLeave={endDrag}
      onClick={handleBackgroundClick}
    >
      {/* Per-kind arrowhead markers. Fill is set from the same CSS variable as
          the matching edge stroke (via .topology-edge__arrow--<kind>) so the
          head colour tracks the line in both themes. */}
      <defs>
        {EDGE_KINDS.map(kind => (
          <marker
            key={kind}
            id={`topo-arrow-${kind}`}
            markerWidth="8"
            markerHeight="8"
            refX="6.5"
            refY="3"
            orient="auto"
            markerUnits="userSpaceOnUse"
          >
            <path
              className={`topology-edge__arrow topology-edge__arrow--${kind}`}
              d="M0 0 L0 6 L7 3 z"
            />
          </marker>
        ))}
      </defs>

      {/* Pan/zoom viewport — the transform lives here, not on the nodes, so the
          per-node translate the layout + tests rely on stays intact. */}
      <g
        className="topology-graph__viewport"
        data-testid="topology-graph-viewport"
        transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}
      >
      {/* Team clusters (drawn under nodes) */}
      {clusters.map(c => {
        // Agents no team claims form their own named group (AAASM-5184).
        //
        // AAASM-5140 left this cluster inert because it was keyed by the empty
        // string, which `TopologyPage` reads as falsy — the click opened
        // nothing, so an affordance with no successful path was worse than
        // none. Now that the group carries a real key and a real label, the
        // panel does open, and the cluster is selectable like any other.
        const unclaimed = isUnclaimedTeam(c.team)
        const label = teamLabel(c.team)
        const selectable = onTeamClick !== undefined
        return (
        <g
          key={`cluster-${c.team}`}
          className={`topology-cluster${unclaimed ? ' topology-cluster--unclaimed' : ''}`}
          data-testid="team-cluster"
          data-team={c.team}
          data-unclaimed={unclaimed ? 'true' : undefined}
          data-selectable={selectable ? undefined : 'false'}
          data-selected={selectedTeam === c.team ? 'true' : undefined}
          role={selectable ? 'button' : undefined}
          tabIndex={selectable ? 0 : undefined}
          aria-label={
            selectable
              ? (unclaimed ? 'Inspect agents belonging to no team' : `Inspect team ${label}`)
              : undefined
          }
          style={selectable ? { cursor: 'pointer' } : undefined}
          onClick={selectable ? (e) => { e.stopPropagation(); if (!consumePanClick()) onTeamClick(c.team) } : undefined}
          onKeyDown={selectable ? (e: KeyboardEvent<SVGGElement>) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onTeamClick(c.team) }
          } : undefined}
        >
          <rect
            className="topology-cluster__outline"
            x={c.x}
            y={c.y}
            width={c.w}
            height={c.h}
            rx={10}
          />
          <foreignObject
            x={c.x + 8}
            y={c.y + 6}
            width={Math.max(160, c.w - 16)}
            height={TEAM_LABEL_HEIGHT + TEAM_BUDGET_BAR_HEIGHT}
          >
            <div className="topology-cluster__overlay" data-testid="team-cluster-overlay">
              <Tooltip content={`${label} · ${c.memberCount} member${c.memberCount === 1 ? '' : 's'} · $${c.spent.toFixed(0)} / ${formatLimit(c.limit, 0)}`}>
                <span className="topology-cluster__label" data-testid="team-cluster-label">
                  {unclaimed ? `⚠ ${label}` : label}
                </span>
              </Tooltip>
              {/* The bar is labelled with the group's display name, not its
                  sentinel key — `TeamBudgetBar` renders `team` as visible text
                  and is shared with the Costs page. */}
              <TeamBudgetBar team={label} spent={c.spent} limit={c.limit} />
            </div>
          </foreignObject>
        </g>
        )
      })}

      {/* Relationship edges — above the cluster fills, under the node cards so
          nodes sit on top and arrowheads land on the target card border. */}
      {edgeGeometries.map(e => (
        <path
          key={e.key}
          className={`topology-edge topology-edge--${e.kind}`}
          data-testid="topology-edge"
          data-kind={e.kind}
          data-cross-team={e.crossTeam ? 'true' : undefined}
          d={e.d}
          fill="none"
          strokeWidth={EDGE_STYLE[e.kind].width}
          strokeDasharray={EDGE_STYLE[e.kind].dash}
          markerEnd={`url(#topo-arrow-${e.kind})`}
        />
      ))}

      {positions.map(pos => {
        // Live data, not `pos.source` — see `nodeById`.
        const node = nodeById.get(pos.id) ?? pos.source
        const bucket = bucketForRatio(node.budgetSpend, node.budgetLimit)
        const dims = SIZE_VARIANT[bucket]
        const x = (pos.x ?? width / 2) - dims.w / 2
        const y = (pos.y ?? height / 2) - dims.h / 2

        // Delegation-tree badges (AAASM-5033), all edge-derived client-side.
        const depth = depthById.get(node.id) ?? 0
        const isRoot = rootIds.has(node.id)
        const inCycle = cycleNodeIds.has(node.id)
        // Cross-team relationships the filtered canvas is not drawing
        // (AAASM-5138). Only meaningful while a team filter is narrowing the
        // view — see the `teamFilterActive` prop.
        const crossTeamCount = teamFilterActive ? (crossTeamDegree.get(node.id) ?? 0) : 0

        const handleClick = onNodeClick ? () => onNodeClick(node) : undefined
        const handleKeyDown = onNodeClick
          ? (e: KeyboardEvent<SVGGElement>) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onNodeClick(node)
              }
            }
          : undefined

        return (
          <g
            key={node.id}
            className="topology-node"
            data-testid="topology-node"
            data-status={node.status}
            data-size-bucket={bucket}
            data-selected={selectedNodeId === node.id ? 'true' : undefined}
            data-depth={depth}
            data-root={isRoot ? 'true' : undefined}
            data-in-cycle={inCycle ? 'true' : undefined}
            data-flagged={node.flagged ? 'true' : undefined}
            data-cross-team-count={crossTeamCount > 0 ? String(crossTeamCount) : undefined}
            data-mode={node.mode}
            data-trust={node.trust != null ? String(node.trust) : undefined}
            transform={`translate(${x}, ${y})`}
            role={onNodeClick ? 'button' : undefined}
            tabIndex={onNodeClick ? 0 : undefined}
            onClick={handleClick}
            onKeyDown={handleKeyDown}
            style={onNodeClick ? { cursor: 'pointer' } : undefined}
          >
            <rect className="topology-node__card" x={0} y={0} width={dims.w} height={dims.h} rx={4} />
            <rect className="topology-node__stripe" x={0} y={0} width={3} height={dims.h} rx={2} />
            <text className="topology-node__name" x={11} y={22}>
              {node.flagged ? '⚑ ' : ''}{truncate(node.name, node.flagged ? 12 : 14)}
            </text>
            {/* Root / depth badge (top-right): roots read `root`, delegates `L<n>`. */}
            <text
              className={`topology-node__depth${isRoot ? ' topology-node__depth--root' : ''}`}
              data-testid="topology-node-depth"
              x={dims.w - 6}
              y={12}
              textAnchor="end"
            >
              {isRoot ? 'root' : `L${depth}`}
            </text>
            {node.framework && (
              <text className="topology-node__framework" x={11} y={35}>
                {node.framework}
              </text>
            )}
            {/* Enforcement-mode badge (right of the framework row), rendered
                only when the node carries a mode — see types.ts / PR notes.
                Narrow (small-bucket) cards have no room for the word beside the
                framework text, so they show the colour-coded glyph alone; wider
                cards show `<glyph> <mode>`. */}
            {node.mode && (
              <text
                className={`topology-node__mode topology-node__mode--${node.mode}`}
                data-testid="topology-node-mode"
                data-mode-label={dims.w >= SIZE_VARIANT.medium.w ? 'full' : 'glyph'}
                x={dims.w - 6}
                y={35}
                textAnchor="end"
              >
                {dims.w >= SIZE_VARIANT.medium.w ? `${MODE_GLYPH[node.mode]} ${node.mode}` : MODE_GLYPH[node.mode]}
                {crossTeamCount > 0 && <CrossTeamBadge count={crossTeamCount} leadingSpace />}
              </text>
            )}
            {/* Same badge, standalone, for a node carrying no mode — the count
                must not depend on whether the mode badge happens to render. */}
            {!node.mode && crossTeamCount > 0 && (
              <text
                className="topology-node__mode"
                x={dims.w - 6}
                y={35}
                textAnchor="end"
              >
                <CrossTeamBadge count={crossTeamCount} />
              </text>
            )}
            {/* An unconfigured ceiling renders the shared `—` glyph rather than
                `$0`. SVG `<text>` cannot host the `<span>`-based TruthfulValue,
                so the glyph and the screen-reader sentence are placed by hand —
                from the same vocabulary, never a locally-invented one. */}
            <text
              className="topology-node__budget"
              data-testid="topology-node-budget"
              data-truth-state={node.budgetLimit === null ? 'unconfigured' : undefined}
              x={11}
              y={dims.h - 8}
            >
              {node.budgetLimit === null && (
                <title>{`Budget limit: ${TRUTH_STATE_META.unconfigured.announcement}`}</title>
              )}
              ${node.budgetSpend.toFixed(1)} / {formatLimit(node.budgetLimit, 0)}
            </text>
            {/* Trust badge (top-left): the agent's trust score. Rendered only
                when `trust` is a number — the topology API carries the field but
                currently always sends `null` (no trust-analytics source yet), so
                this stays hidden until real data lands (AAASM-5036). */}
            {node.trust != null && (
              <text
                className="topology-node__trust"
                data-testid="topology-node-trust"
                x={6}
                y={12}
                textAnchor="start"
              >
                ◈ {node.trust}
              </text>
            )}
            {/* Cycle marker (bottom-right): the danger dashed card border is the
                primary signal; this ⟳ glyph makes it unambiguous. */}
            {inCycle && (
              <text
                className="topology-node__cycle"
                data-testid="topology-node-cycle"
                x={dims.w - 6}
                y={dims.h - 6}
                textAnchor="end"
              >
                ⟳
              </text>
            )}
          </g>
        )
      })}
      </g>
    </svg>

    {/* Zoom controls (bottom-right overlay), mirroring the hi-fi reference. */}
    <div className="topology-graph__controls" data-testid="topology-zoom-controls">
      <button type="button" className="topology-graph__zoom-btn" data-testid="topology-zoom-in" aria-label="Zoom in" onClick={zoomIn}>＋</button>
      <button type="button" className="topology-graph__zoom-btn" data-testid="topology-zoom-out" aria-label="Zoom out" onClick={zoomOut}>－</button>
      <button type="button" className="topology-graph__zoom-btn" data-testid="topology-zoom-reset" aria-label="Reset view" onClick={resetView}>⤢</button>
      <div className="topology-graph__zoom-readout" data-testid="topology-zoom-readout">{Math.round(zoom * 100)}%</div>
    </div>
    </div>
  )
}

/**
 * The `⇆N` card badge: how many cross-team relationships this agent has that
 * the filtered canvas is not drawing (AAASM-5138).
 *
 * Mirrors `design/v2/hi-fi/topology.jsx:260`. It carries a `<title>` because the
 * glyph alone is not a sentence — an operator using assistive tech has to be
 * told that edges are missing from the picture, not just shown a symbol.
 */
function CrossTeamBadge({ count, leadingSpace = false }: Readonly<{ count: number; leadingSpace?: boolean }>) {
  return (
    <tspan
      className="topology-node__crossteam"
      data-testid="topology-node-crossteam"
      data-count={count}
      // Gap via `dx`, not literal spaces: SVG collapses whitespace under the
      // default `xml:space`, so padding the string left the badge abutting the
      // mode glyph.
      dx={leadingSpace ? 5 : 0}
    >
      <title>
        {`${count} cross-team ${count === 1 ? 'relationship is' : 'relationships are'} not drawn on this view.`}
      </title>
      {`\u21c6${count}`}
    </tspan>
  )
}

/**
 * Card size from budget burn. Purely a layout weighting, not a claim about the
 * budget — an unconfigured limit (`null`) has no ratio, so the card takes the
 * base size, exactly as a zero limit already did.
 */
function bucketForRatio(spend: number, limit: number | null): 'small' | 'medium' | 'large' {
  if (limit === null || limit <= 0) return 'small'
  const ratio = spend / limit
  if (ratio < 0.5) return 'small'
  if (ratio <= 0.8) return 'medium'
  return 'large'
}

/** `$12` for a known ceiling, the shared absence glyph for an unconfigured one. */
function formatLimit(limit: number | null, fractionDigits: number): string {
  return limit === null ? NO_DATA : `$${limit.toFixed(fractionDigits)}`
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}
