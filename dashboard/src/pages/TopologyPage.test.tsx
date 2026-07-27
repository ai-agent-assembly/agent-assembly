import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { TopologyPage } from './TopologyPage'
import { TraceDrawerProvider } from '../components/trace/TraceDrawerProvider'
import * as topologyApi from '../features/topology/api'
import type { TopologyGraph } from '../features/topology/types'
import { UNCLAIMED_TEAM } from '../features/topology/unclaimed'

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

  // ── The unclaimed group is not a team (AAASM-5184) ────────────────────────
  describe('agents that belong to no team', () => {
    /** Two agents, exactly one real team — the ticket's reproduction. */
    const WITH_UNCLAIMED: TopologyGraph = {
      nodes: [
        { id: 'a1', name: 'support', status: 'active', team: 'support', owner: 'alice', policyCount: 2, budgetSpend: 1, budgetLimit: 10 },
        { id: 'a2', name: 'teamless', status: 'active', team: UNCLAIMED_TEAM, owner: 'bob', policyCount: 0, budgetSpend: 0, budgetLimit: null },
      ],
      edges: [],
    }

    function renderWith(graph: TopologyGraph) {
      vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
        mockQuery({ data: graph, isLoading: false, isError: false, refetch: vi.fn() }),
      )
      return renderPage()
    }

    it('counts only real teams in the header', () => {
      renderWith(WITH_UNCLAIMED)
      // One real team exists. Counting the unclaimed group asserted two.
      expect(screen.getByTestId('topology-meta')).toHaveTextContent('2 agents · 1 team')
    })

    it('reports 0 teams when every agent is unclaimed', () => {
      renderWith({
        nodes: [
          { id: 'a1', name: 'one', status: 'active', team: UNCLAIMED_TEAM, owner: '', policyCount: 0, budgetSpend: 0, budgetLimit: null },
          { id: 'a2', name: 'two', status: 'active', team: UNCLAIMED_TEAM, owner: '', policyCount: 0, budgetSpend: 0, budgetLimit: null },
        ],
        edges: [],
      })
      expect(screen.getByTestId('topology-meta')).toHaveTextContent('2 agents · 0 teams')
    })

    it('gives the unclaimed filter row a visible label', () => {
      renderWith(WITH_UNCLAIMED)
      const row = screen
        .getAllByTestId('team-filter-item')
        .find((el) => el.dataset.team === UNCLAIMED_TEAM)!
      expect(row).toHaveTextContent(/unclaimed/i)
      // The operator could previously see a row but not what it selected.
      expect(row.textContent?.replace(/[⚠○◎\s]/g, '')).not.toBe('')
    })

    it('surfaces an unclaimed count in the sidebar stats', () => {
      renderWith(WITH_UNCLAIMED)
      expect(screen.getByTestId('topology-stat-unclaimed')).toHaveTextContent('1 unclaimed')
    })

    it('shows no unclaimed stat when every agent has a team', () => {
      renderWith(GRAPH)
      expect(screen.queryByTestId('topology-stat-unclaimed')).not.toBeInTheDocument()
      expect(screen.getByTestId('topology-meta')).toHaveTextContent('3 agents · 2 teams')
    })

    it('opens a detail panel for the unclaimed cluster instead of doing nothing', async () => {
      renderWith(WITH_UNCLAIMED)
      const cluster = screen
        .getAllByTestId('team-cluster')
        .find((el) => el.dataset.team === UNCLAIMED_TEAM)!
      await userEvent.click(cluster)

      const panel = await screen.findByTestId('team-detail-panel')
      expect(panel).toHaveAttribute('data-unclaimed', 'true')
      // Its own copy — it explains the governance gap rather than presenting
      // the group as a team like any other.
      expect(screen.getByTestId('team-detail-unclaimed-note')).toHaveTextContent(/no team-scoped policy or budget/i)
      // "cross-team edges" is a category error for a group that is not a team.
      expect(screen.queryByTestId('team-detail-crossteam-count')).not.toBeInTheDocument()
      expect(panel.textContent).not.toContain(UNCLAIMED_TEAM)
    })

    it('still shows the cross-team count for a real team', async () => {
      renderWith(WITH_UNCLAIMED)
      const cluster = screen
        .getAllByTestId('team-cluster')
        .find((el) => el.dataset.team === 'support')!
      await userEvent.click(cluster)
      expect(await screen.findByTestId('team-detail-crossteam-count')).toBeInTheDocument()
      expect(screen.queryByTestId('team-detail-unclaimed-note')).not.toBeInTheDocument()
    })
  })

  it('falls back to "0 agents · 0 teams" when data is undefined', () => {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: undefined, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()
    expect(screen.getByTestId('topology-meta')).toHaveTextContent('0 agents · 0 teams')
  })

  it('falls back to "0 agents · 0 teams" on a partial object missing the nodes field', () => {
    // A 200 with a partial object (no `nodes` array) must not crash the page.
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: {} as TopologyGraph, isLoading: false, isError: false, refetch: vi.fn() }),
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

  it('renders the control sidebar with stats and the export button', () => {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: GRAPH, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()
    expect(screen.getByTestId('topology-sidebar')).toBeInTheDocument()
    // 2 active agents (a1, a3), 1 cross-team edge (support→analytics).
    expect(screen.getByTestId('topology-stat-active')).toHaveTextContent('2 active')
    expect(screen.getByTestId('topology-stat-crossteam')).toHaveTextContent('1 cross-team')
    expect(screen.getByTestId('topology-export-button')).toBeInTheDocument()
  })

  it("counts cross-team edges from the server's flag, not the endpoints' teams", () => {
    // Both endpoints sit on `support`, so the client derivation would count 0;
    // the server flag (AAASM-5099) is the one definition all three surfaces
    // (badge, canvas, /topology/edges) share.
    const flagged: TopologyGraph = {
      ...GRAPH,
      edges: [{ source: 'a1', target: 'a3', kind: 'messages', crossTeam: true }],
    }
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: flagged, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()
    expect(screen.getByTestId('topology-stat-crossteam')).toHaveTextContent('1 cross-team')
  })

  it('opens the TeamDetailPanel when a team cluster is clicked', async () => {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: GRAPH, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()
    const supportCluster = screen.getAllByTestId('team-cluster').find(c => c.dataset.team === 'support')!
    await userEvent.click(supportCluster)
    expect(screen.getByTestId('team-detail-panel')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('support')
  })

  it('filters the graph to a single team via the sidebar team list', async () => {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: GRAPH, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()
    expect(screen.getAllByTestId('topology-node')).toHaveLength(3)
    const analytics = screen.getAllByTestId('team-filter-item').find(i => i.dataset.team === 'analytics')!
    await userEvent.click(analytics)
    expect(analytics).toHaveAttribute('data-active', 'true')
    // Only the single analytics agent remains on the canvas (force sim re-ticks
    // on the new node set, so let it settle).
    await waitFor(() => expect(screen.getAllByTestId('topology-node')).toHaveLength(1))
    expect(screen.getByTestId('topology-node')).toHaveTextContent('analyst')
  })
})

// ── Sidebar count vs. rendered canvas (AAASM-5138) ───────────────────────────
//
// The sidebar counts cross-team edges across the whole fleet; the canvas draws
// only a subset. An earlier revision of this lane claimed the per-node `⇆N`
// badges reconciled the two — `drawn + badged == counted` — and tested it on a
// 2-team fixture where every crossing touched the filtered team, a shape in
// which the claim cannot fail. It is false in general. The fixture below is
// three teams in a chain precisely so it can fail, and the shipped behaviour is
// that the sidebar *states the gap* rather than asserting a reconciled number.
describe('TopologyPage — the cross-team count never contradicts the canvas', () => {
  afterEach(() => { vi.restoreAllMocks() })

  // alpha–beta and beta–gamma. Filter to alpha and the beta–gamma crossing is
  // counted, undrawn, and touches no visible node — so no badge can represent it.
  const CHAIN: TopologyGraph = {
    nodes: [
      { id: 'a1', name: 'alpha-1', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
      { id: 'b1', name: 'beta-1', status: 'active', team: 'beta', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
      { id: 'c1', name: 'gamma-1', status: 'active', team: 'gamma', owner: 'c', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    ],
    edges: [
      { source: 'a1', target: 'b1', kind: 'delegation' },
      { source: 'b1', target: 'c1', kind: 'delegation' },
    ],
  }

  function mountChain() {
    vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
      mockQuery({ data: CHAIN, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderPage()
  }

  function counted() {
    return Number(/(\d+) cross-team/.exec(screen.getByTestId('topology-stat-crossteam').textContent ?? '')![1])
  }
  function drawn() {
    return screen.queryAllByTestId('topology-edge').filter(p => p.getAttribute('data-cross-team') === 'true').length
  }
  function hidden() {
    const el = screen.queryByTestId('topology-stat-crossteam-hidden')
    return el === null ? 0 : Number(el.getAttribute('data-hidden-count'))
  }

  it('reports nothing hidden when the canvas draws every counted crossing', () => {
    mountChain()
    expect(counted()).toBe(2)
    expect(drawn()).toBe(2)
    expect(hidden()).toBe(0)
  })

  /**
   * The ≥3-team break. Filtering to `alpha` leaves the beta–gamma crossing
   * counted but entirely unrepresented on the canvas — it has no endpoint on
   * screen, so the `⇆N` badges cannot account for it. Reverting the
   * `crossTeamHidden` wiring fails this test.
   */
  it('states the gap when a crossing between two off-screen teams is dropped', async () => {
    mountChain()
    await userEvent.click(screen.getAllByTestId('team-filter-item').find(i => i.dataset.team === 'alpha')!)
    await waitFor(() => expect(screen.getAllByTestId('topology-node')).toHaveLength(1))

    expect(drawn()).toBe(0)
    // The fleet-wide count is not narrowed to match the picture...
    expect(counted()).toBe(2)
    // ...instead the discrepancy is stated, and it covers *both* crossings —
    // including the one no badge touches.
    expect(hidden()).toBe(2)
    expect(drawn() + hidden()).toBe(counted())
  })

  /**
   * The `showCrossTeam` break, reachable from the checkbox sitting directly
   * beside the counter with no team filter at all. Every node is on screen and
   * every curve is gone, so `teamFilterActive` is false and no badge renders.
   */
  it('states the gap when the cross-team toggle hides every curve', async () => {
    mountChain()
    await userEvent.click(screen.getByTestId('topology-crossteam-toggle').querySelector('input')!)

    await waitFor(() => expect(drawn()).toBe(0))
    expect(screen.queryAllByTestId('topology-node-crossteam')).toHaveLength(0)
    expect(counted()).toBe(2)
    expect(hidden()).toBe(2)
  })

  it('states the gap when an edge kind is unchecked', async () => {
    mountChain()
    const delegation = screen
      .getAllByTestId('topology-edge-toggle')
      .find(l => l.dataset.kind === 'delegates_to')!
    await userEvent.click(delegation.querySelector('input')!)

    await waitFor(() => expect(drawn()).toBe(0))
    expect(counted()).toBe(2)
    expect(hidden()).toBe(2)
  })

  // The per-node badge keeps its own, narrower job: telling the operator which
  // visible agents have relationships the filtered view is not drawing.
  it('still badges the visible team’s own crossings', async () => {
    mountChain()
    await userEvent.click(screen.getAllByTestId('team-filter-item').find(i => i.dataset.team === 'beta')!)
    await waitFor(() => expect(screen.getAllByTestId('topology-node')).toHaveLength(1))
    // beta touches both crossings.
    const badges = screen.getAllByTestId('topology-node-crossteam')
    expect(badges).toHaveLength(1)
    expect(badges[0]).toHaveAttribute('data-count', '2')
  })
})
