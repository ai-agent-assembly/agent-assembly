import { useEffect, useMemo, useState, type KeyboardEvent } from 'react'
import {
  forceCenter,
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
  const identityKey = useMemo(
    () => `${nodes.map(n => n.id).join(',')}|${edges.map(e => `${e.source}->${e.target}`).join(',')}`,
    [nodes, edges],
  )

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
    const cols = teams.length <= 2 ? teams.length : teams.length <= 6 ? 3 : 4
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
      .force('teamX', forceX<PositionedNode>(d => teamCenterById.get(d.source.team)?.cx ?? width / 2).strength(0.18))
      .force('teamY', forceY<PositionedNode>(d => teamCenterById.get(d.source.team)?.cy ?? height / 2).strength(0.18))
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

  return (
    <svg
      className="topology-graph"
      data-testid="topology-graph"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Agent topology graph"
    >
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
