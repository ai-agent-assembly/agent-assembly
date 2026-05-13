import { useMemo } from 'react'
import { useTopologyQuery } from '../features/topology/api'
import './TopologyPage.css'

/**
 * Topology page shell — header + slots for the D3 force graph and the
 * right-side node-detail panel. Lands as the entry point for AAASM-95's
 * topology half; the graph itself (AAASM-1335), node panel (AAASM-1337),
 * team grouping (AAASM-1339), and View-trace wiring (AAASM-1340) plug
 * into the placeholders below.
 *
 * Hi-fi reference: design/v1/hi-fi/topology.jsx — page-head + page-title
 * with "Topology · N agents · N teams" subtitle.
 */
export function TopologyPage() {
  const { data, isLoading, isError, refetch } = useTopologyQuery()
  const teamCount = useMemo(() => {
    if (!data) return 0
    return new Set(data.nodes.map(n => n.team)).size
  }, [data])
  const agentCount = data?.nodes.length ?? 0

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
            data-testid="topology-graph-placeholder"
            aria-label="Topology graph"
          >
            Graph component lands in AAASM-1335.
          </section>
          <aside
            className="topology-page__panel"
            data-testid="topology-panel-placeholder"
            aria-label="Node detail panel"
          >
            Node detail panel lands in AAASM-1337.
          </aside>
        </div>
      )}
    </main>
  )
}
