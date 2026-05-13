import type { TopologyEdge, TopologyNode } from '../../features/topology/types'

const CARD_WIDTH = 96
const CARD_HEIGHT = 56

const SIZE_VARIANT: Record<'small' | 'medium' | 'large', { w: number; h: number }> = {
  small: { w: 76, h: 44 },
  medium: { w: 96, h: 56 },
  large: { w: 116, h: 68 },
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
 * The d3-force simulation lands in a subsequent commit. For now nodes
 * use a deterministic grid layout so the rendering, status mapping, and
 * size bucketing can be verified independently.
 */
export function TopologyGraph({
  nodes,
  edges: _edges,
  width = 800,
  height = 500,
  onNodeClick,
}: TopologyGraphProps) {
  return (
    <svg
      className="topology-graph"
      data-testid="topology-graph"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Agent topology graph"
    >
      {nodes.map((node, i) => {
        const bucket = bucketForRatio(node.budgetSpend, node.budgetLimit)
        const dims = SIZE_VARIANT[bucket]
        // Temporary grid layout (replaced by d3-force in the next commit).
        const col = i % 4
        const row = Math.floor(i / 4)
        const x = 24 + col * (CARD_WIDTH + 32)
        const y = 24 + row * (CARD_HEIGHT + 32)

        const handleClick = onNodeClick ? () => onNodeClick(node) : undefined

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
