import { useMemo, useState } from 'react'
import { useTopologyQuery } from '../features/topology/api'
import { TopologyGraph } from '../components/topology/TopologyGraph'
import { NodeDetailPanel } from '../components/topology/NodeDetailPanel'
import { useTraceDrawer } from '../components/trace/useTraceDrawer'
import type { TopologyNode } from '../features/topology/types'
import './TopologyPage.css'

/**
 * Topology page shell — header, D3 force graph (AAASM-1335), and
 * node-detail panel (AAASM-1337) docked on the right when a node is
 * selected. Team grouping (AAASM-1339) and View-trace drawer wiring
 * (AAASM-1340) plug in next.
 *
 * Hi-fi reference: design/v1/hi-fi/topology.jsx — page-head + page-title
 * with "Topology · N agents · N teams" subtitle, canvas left, panel right.
 */
export function TopologyPage() {
  const { data, isLoading, isError, refetch } = useTopologyQuery()
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const { open: openTraceDrawer } = useTraceDrawer()
  const teamCount = useMemo(() => {
    if (!data) return 0
    return new Set(data.nodes.map(n => n.team)).size
  }, [data])
  const agentCount = data?.nodes.length ?? 0

  const handleViewTrace = (agentId: string, sessionId: string) => {
    openTraceDrawer(agentId, sessionId)
  }

  return (
    <main className="topology-page" data-testid="topology-view">
      <header className="topology-page__head" data-testid="topology-header">
        <h1 className="topology-page__title">
          Topology
          <span className="topology-page__meta" data-testid="topology-meta">
            · {agentCount} agent{agentCount === 1 ? '' : 's'} · {teamCount} team{teamCount === 1 ? '' : 's'}
          </span>
        </h1>
      </header>

      {isLoading && (
        <div data-testid="topology-loading" className="topology-page__loading">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} data-testid="topology-row-skeleton" className="topology-page__skeleton" />
          ))}
        </div>
      )}

      {isError && (
        <div data-testid="topology-error" className="topology-page__error">
          <p>Failed to load topology.</p>
          <button onClick={() => void refetch()}>Retry</button>
        </div>
      )}

      {!isLoading && !isError && (
        <div className="topology-page__body">
          <section
            className="topology-page__graph"
            data-testid="topology-graph-wrapper"
            aria-label="Topology graph"
          >
            <TopologyGraph
              nodes={data?.nodes ?? []}
              edges={data?.edges ?? []}
              onNodeClick={setSelectedNode}
            />
          </section>
          <aside
            className="topology-page__panel"
            data-testid="topology-panel-wrapper"
            aria-label="Node detail panel"
          >
            {selectedNode ? (
              <NodeDetailPanel
                node={selectedNode}
                onClose={() => setSelectedNode(null)}
                onViewTrace={handleViewTrace}
              />
            ) : (
              <div className="topology-page__panel-empty" data-testid="topology-panel-empty">
                Click an agent in the graph to see its details.
              </div>
            )}
          </aside>
        </div>
      )}
    </main>
  )
}
