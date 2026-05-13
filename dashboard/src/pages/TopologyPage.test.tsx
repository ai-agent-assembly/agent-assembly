import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { TopologyPage } from './TopologyPage'
import { TraceDrawerProvider } from '../components/trace/TraceDrawerProvider'
import * as topologyApi from '../features/topology/api'
import type { TopologyGraph } from '../features/topology/types'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function renderPage() {
  return render(
    <QueryClientProvider client={makeClient()}>
      <TraceDrawerProvider>
        <TopologyPage />
      </TraceDrawerProvider>
    </QueryClientProvider>,
  )
}

function mockQuery(partial: Partial<UseQueryResult<TopologyGraph, Error>>): UseQueryResult<TopologyGraph, Error> {
  return partial as unknown as UseQueryResult<TopologyGraph, Error>
}

const GRAPH: TopologyGraph = {
  nodes: [
    { id: 'a1', name: 'support', status: 'active', team: 'support', owner: 'alice', policyCount: 2, budgetSpend: 1, budgetLimit: 10 },
    { id: 'a2', name: 'analyst', status: 'idle', team: 'analytics', owner: 'carol', policyCount: 1, budgetSpend: 0, budgetLimit: 5 },
    { id: 'a3', name: 'support-2', status: 'active', team: 'support', owner: 'alice', policyCount: 2, budgetSpend: 2, budgetLimit: 10 },
  ],
  edges: [{ source: 'a1', target: 'a2', kind: 'delegation' }],
}

describe('TopologyPage', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('renders the Topology header with agent + team counts derived from data', () => {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: GRAPH, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()

    const heading = screen.getByRole('heading', { level: 1 })
    expect(heading).toHaveTextContent('Topology')
    // 3 nodes across 2 teams (support × 2, analytics × 1).
    expect(screen.getByTestId('topology-meta')).toHaveTextContent('3 agents · 2 teams')
  })

  it('falls back to "0 agents · 0 teams" when data is undefined', () => {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: undefined, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()
    expect(screen.getByTestId('topology-meta')).toHaveTextContent('0 agents · 0 teams')
  })

  it('renders skeleton rows while loading and hides the body', () => {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    renderPage()

    expect(screen.getByTestId('topology-loading')).toBeInTheDocument()
    expect(screen.getAllByTestId('topology-row-skeleton')).toHaveLength(4)
    expect(screen.queryByTestId('topology-graph-wrapper')).not.toBeInTheDocument()
  })

  it('shows error banner with Retry button on failure and calls refetch on click', async () => {
    const refetch = vi.fn()
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    renderPage()

    expect(screen.getByTestId('topology-error')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('mounts the TopologyGraph (real component) and panel empty hint when no node is selected', () => {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: GRAPH, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()

    expect(screen.getByTestId('topology-graph-wrapper')).toBeInTheDocument()
    // Real graph component renders an SVG with one node per graph entry.
    expect(screen.getByTestId('topology-graph')).toBeInTheDocument()
    expect(screen.getAllByTestId('topology-node')).toHaveLength(GRAPH.nodes.length)
    // Until a node is clicked, the panel slot shows the empty hint, not the detail panel.
    expect(screen.getByTestId('topology-panel-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('node-detail-panel')).not.toBeInTheDocument()
  })

  it('opens the NodeDetailPanel when a graph node is clicked, and closes via Close button', async () => {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: GRAPH, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()

    expect(screen.queryByTestId('node-detail-panel')).not.toBeInTheDocument()
    // Click the first topology node — page should reflect the selection.
    await userEvent.click(screen.getAllByTestId('topology-node')[0])
    expect(screen.getByTestId('node-detail-panel')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('support')

    await userEvent.click(screen.getByTestId('node-detail-close'))
    expect(screen.queryByTestId('node-detail-panel')).not.toBeInTheDocument()
    expect(screen.getByTestId('topology-panel-empty')).toBeInTheDocument()
  })
})
