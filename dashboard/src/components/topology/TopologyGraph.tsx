import { useEffect, useMemo, useState, type KeyboardEvent } from 'react'
import {
  forceCenter,
  forceLink,
  forceManyBody,
  forceSimulation,
  type Simulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force'
import type { TopologyEdge, TopologyNode } from '../../features/topology/types'
import './TopologyGraph.css'

const SIZE_VARIANT: Record<'small' | 'medium' | 'large', { w: number; h: number }> = {
  small: { w: 76, h: 44 },
  medium: { w: 96, h: 56 },
  large: { w: 116, h: 68 },
}

interface PositionedNode extends SimulationNodeDatum {
  id: string
  source: TopologyNode
}

interface PositionedEdge extends SimulationLinkDatum<PositionedNode> {
  kind: TopologyEdge['kind']
}

export interface TopologyGraphProps {
  readonly nodes: readonly TopologyNode[]
  readonly edges: readonly TopologyEdge[]
  readonly width?: number
  readonly height?: number
  readonly onNodeClick?: (node: TopologyNode) => void
}

/**
 * Force-directed agent topology graph. Renders rectangular cards with a
 * status stripe on the left, mirroring `design/v1/hi-fi/topology.jsx`'s
 * TopoNodeEl. Card size encodes the node's budget burn ratio; status
 * stripe color is keyed off `data-status` via tokens in TopologyGraph.css.
 *
 * Layout: a `d3-force` simulation memoised by node+edge identity so
 * structurally equal updates do not restart the sim. The simulation
 * stops on unmount to avoid leaking RAF handles.
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

  const simulation = useMemo<Simulation<PositionedNode, PositionedEdge>>(() => {
    const positioned: PositionedNode[] = nodes.map(n => ({ id: n.id, source: n }))
    const links: PositionedEdge[] = edges.map(e => ({ source: e.source, target: e.target, kind: e.kind }))
    return forceSimulation<PositionedNode, PositionedEdge>(positioned)
      .force('link', forceLink<PositionedNode, PositionedEdge>(links).id(d => d.id).distance(120))
      .force('charge', forceManyBody().strength(-220))
      .force('center', forceCenter(width / 2, height / 2))
      .stop()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identityKey, width, height])

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

  return (
    <svg
      className="topology-graph"
      data-testid="topology-graph"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Agent topology graph"
    >
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
