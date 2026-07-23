import { useEffect, useMemo, useState, type KeyboardEvent } from 'react'
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
 * Per-kind edge styling, mirroring the hi-fi reference edge config
 * (`design/v1/hi-fi/topology.jsx` TOPO_EC). The design defines six relation
 * kinds; the frontend data model (`features/topology/types.ts`) currently
 * exposes only `delegation` and `call`, so exactly those two are styled here —
 * `delegation` as the primary solid line, `call` as a lighter dashed line.
 *
 * `strokeWidth` is inlined; colour comes from CSS variables via the
 * `.topology-edge--<kind>` class so edges re-theme in light/dark like the rest
 * of the graph (the design's raw hex would not).
 */
const EDGE_STYLE: Record<TopologyEdge['kind'], { width: number; dash?: string }> = {
  delegation: { width: 1.75 },
  call: { width: 1.5, dash: '6 4' },
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
  readonly limit: number
  readonly memberCount: number
}

export interface TopologyGraphProps {
  readonly nodes: readonly TopologyNode[]
  readonly edges: readonly TopologyEdge[]
  readonly width?: number
  readonly height?: number
  readonly onNodeClick?: (node: TopologyNode) => void
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
}: TopologyGraphProps) {
  // Stable identity key — restart the sim only when the *set* of node/edge
  // ids changes, not on every parent re-render.
  const identityKey = useMemo(() => {
    const nodeIds = nodes.map(n => n.id).join(',')
    const edgeIds = edges.map(e => `${e.source}->${e.target}`).join(',')
    return `${nodeIds}|${edgeIds}`
  }, [nodes, edges])

  // Per-team layout: centers laid out left-to-right, top-to-bottom in a
  // grid based on team count, plus aggregated spend/limit/member count.
  const teamLayout = useMemo<readonly TeamLayoutEntry[]>(() => {
    const byTeam = new Map<string, { spent: number; limit: number; memberCount: number }>()
    for (const n of nodes) {
      const entry = byTeam.get(n.team) ?? { spent: 0, limit: 0, memberCount: 0 }
      entry.spent += n.budgetSpend
      entry.limit += n.budgetLimit
      entry.memberCount += 1
      byTeam.set(n.team, entry)
    }
    const teams = [...byTeam.keys()]
    let cols = 4
    if (teams.length <= 2) cols = teams.length
    else if (teams.length <= 6) cols = 3
    const rows = Math.max(1, Math.ceil(teams.length / cols))
    const cellW = width / Math.max(1, cols)
    const cellH = height / rows
    return teams.map((team, i) => {
      const col = i % cols
      const row = Math.floor(i / cols)
      const meta = byTeam.get(team)!
      return {
        team,
        cx: cellW * (col + 0.5),
        cy: cellH * (row + 0.5),
        spent: meta.spent,
        limit: meta.limit,
        memberCount: meta.memberCount,
      }
    })
  }, [nodes, width, height])

  const teamCenterById = useMemo(() => {
    const m = new Map<string, TeamLayoutEntry>()
    for (const t of teamLayout) m.set(t.team, t)
    return m
  }, [teamLayout])

  const simulation = useMemo<Simulation<PositionedNode, PositionedEdge>>(() => {
    const positioned: PositionedNode[] = nodes.map(n => ({ id: n.id, source: n }))
    const links: PositionedEdge[] = edges.map(e => ({ source: e.source, target: e.target, kind: e.kind }))
    return forceSimulation<PositionedNode, PositionedEdge>(positioned)
      .force('link', forceLink<PositionedNode, PositionedEdge>(links).id(d => d.id).distance(120))
      .force('charge', forceManyBody().strength(-220))
      .force('center', forceCenter(width / 2, height / 2).strength(0.05))
      .force('teamX', forceX<PositionedNode>(d => teamCenterById.get(d.source.team)?.cx ?? width / 2).strength(0.12))
      .force('teamY', forceY<PositionedNode>(d => teamCenterById.get(d.source.team)?.cy ?? height / 2).strength(0.12))
      // Keep same-team cards from stacking: the teamX/teamY centers pull all
      // members to one point, so without a collision force they overlap. Size
      // the collision circle to the card's half-width (widest dimension) plus a
      // gap so neither the card nor its inside-the-card labels visually clash.
      .force('collide', forceCollide<PositionedNode>()
        .radius(d => SIZE_VARIANT[bucketForRatio(d.source.budgetSpend, d.source.budgetLimit)].w / 2 + 10)
        .strength(0.85))
      .stop()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identityKey, width, height, teamCenterById])

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

  // Cluster bounding boxes derived from current positions per team.
  const clusters = useMemo(() => {
    const byTeam = new Map<string, PositionedNode[]>()
    for (const p of positions) {
      const arr = byTeam.get(p.source.team) ?? []
      arr.push(p)
      byTeam.set(p.source.team, arr)
    }
    return teamLayout.map(t => {
      const members = byTeam.get(t.team) ?? []
      if (members.length === 0) {
        return { ...t, x: t.cx - 60, y: t.cy - 40, w: 120, h: 80 }
      }
      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
      for (const p of members) {
        const dims = SIZE_VARIANT[bucketForRatio(p.source.budgetSpend, p.source.budgetLimit)]
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
  }, [positions, teamLayout])

  // Edge geometry derived from settled node positions. Intra-team edges are
  // straight lines; cross-team edges bow out along a quadratic curve so they
  // read as distinct long-range relationships rather than crossing clutter.
  // Endpoints are trimmed to each card's border so arrowheads land on the
  // target card edge. Drawn under the node cards (see render order below).
  const edgeGeometries = useMemo<readonly EdgeGeometry[]>(() => {
    const posById = new Map<string, PositionedNode>()
    for (const p of positions) posById.set(p.id, p)

    const geoms: EdgeGeometry[] = []
    edges.forEach((edge, i) => {
      const src = posById.get(String(edge.source))
      const tgt = posById.get(String(edge.target))
      if (!src || !tgt || src === tgt) return

      const sDims = SIZE_VARIANT[bucketForRatio(src.source.budgetSpend, src.source.budgetLimit)]
      const tDims = SIZE_VARIANT[bucketForRatio(tgt.source.budgetSpend, tgt.source.budgetLimit)]
      const scx = src.x ?? width / 2
      const scy = src.y ?? height / 2
      const tcx = tgt.x ?? width / 2
      const tcy = tgt.y ?? height / 2

      const start = rectBorderPoint(scx, scy, sDims.w, sDims.h, tcx, tcy)
      const end = rectBorderPoint(tcx, tcy, tDims.w, tDims.h, scx, scy)
      const crossTeam = src.source.team !== tgt.source.team

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
  }, [edges, positions, width, height])

  return (
    <svg
      className="topology-graph"
      data-testid="topology-graph"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Agent topology graph"
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

      {/* Team clusters (drawn under nodes) */}
      {clusters.map(c => (
        <g
          key={`cluster-${c.team}`}
          className="topology-cluster"
          data-testid="team-cluster"
          data-team={c.team}
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
              <Tooltip content={`${c.team} · ${c.memberCount} member${c.memberCount === 1 ? '' : 's'} · $${c.spent.toFixed(0)} / $${c.limit.toFixed(0)}`}>
                <span className="topology-cluster__label" data-testid="team-cluster-label">
                  {c.team}
                </span>
              </Tooltip>
              <TeamBudgetBar team={c.team} spent={c.spent} limit={c.limit} />
            </div>
          </foreignObject>
        </g>
      ))}

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
        const node = pos.source
        const bucket = bucketForRatio(node.budgetSpend, node.budgetLimit)
        const dims = SIZE_VARIANT[bucket]
        const x = (pos.x ?? width / 2) - dims.w / 2
        const y = (pos.y ?? height / 2) - dims.h / 2

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
              {truncate(node.name, 14)}
            </text>
            {node.framework && (
              <text className="topology-node__framework" x={11} y={35}>
                {node.framework}
              </text>
            )}
            <text className="topology-node__budget" x={11} y={dims.h - 8}>
              ${node.budgetSpend.toFixed(1)} / ${node.budgetLimit.toFixed(0)}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

function bucketForRatio(spend: number, limit: number): 'small' | 'medium' | 'large' {
  if (limit <= 0) return 'small'
  const ratio = spend / limit
  if (ratio < 0.5) return 'small'
  if (ratio <= 0.8) return 'medium'
  return 'large'
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}
