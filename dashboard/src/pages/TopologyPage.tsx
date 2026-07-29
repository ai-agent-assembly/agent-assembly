import { useCallback, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ignorePromise } from '../lib/ignorePromise'
import { useTopologyQuery } from '../features/topology/api'
import { detectDelegationCycles } from '../features/topology/hierarchy'
import { crossTeamEdges, hiddenCrossTeamCount, teamById } from '../features/topology/crossTeam'
import { defaultVisibleKinds } from '../features/topology/edgeKinds'
import { countUnclaimed, realTeams } from '../features/topology/unclaimed'
import { exportGraphJson, exportGraphSvg } from '../features/topology/exportGraph'
import { EmptyState } from '../components/EmptyState'
import { TopologyGraph } from '../components/topology/TopologyGraph'
import { TopologySidebar } from '../components/topology/TopologySidebar'
import { NodeDetailPanel } from '../components/topology/NodeDetailPanel'
import { TeamDetailPanel } from '../components/topology/TeamDetailPanel'
import { ExportGraphButton } from '../components/topology/ExportGraphButton'
import { useTraceDrawer } from '../components/trace/useTraceDrawer'
import type { TopologyEdgeKind, TopologyNode } from '../features/topology/types'
import './TopologyPage.css'

const TOPOLOGY_SKELETON_KEYS = Array.from({ length: 4 }, (_, i) => `topology-skeleton-${i}`)
const ALL_TEAMS = 'all'

/**
 * Topology page (AAASM-5071 FE parity). Three-column shell — control sidebar,
 * the D3 force graph (with pan/zoom) in the centre, and a node- or team-detail
 * panel on the right. Preserves the existing force layout + team-budget bars;
 * the sidebar drives team filtering, edge-kind visibility, and the cross-team
 * toggle. `export graph` snapshots the view client-side.
 *
 * Hi-fi reference: design/v1/hi-fi/topology.jsx.
 */
export function TopologyPage() {
  const { data, isLoading, isError, refetch } = useTopologyQuery()
  const { open: openTraceDrawer } = useTraceDrawer()
  const navigate = useNavigate()

  // The selection is held as an *id*, not as the node object.
  //
  // Storing the object froze the panel at the moment of the click: neither the
  // 5s poll nor `onAgentMutated -> refetch()` reached it, so the surface an
  // operator is actually reading kept showing the spend and status from
  // whenever they clicked. That directly undercut the point of polling
  // (AAASM-5136), so the node is re-derived from the latest payload on every
  // render. If the agent leaves the fleet the panel closes, which is the honest
  // outcome — better than presenting a record that no longer exists.
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [selectedTeam, setSelectedTeam] = useState<string | null>(null)
  const [filterTeam, setFilterTeam] = useState<string>(ALL_TEAMS)
  const [visibleKinds, setVisibleKinds] = useState<Set<TopologyEdgeKind>>(() => defaultVisibleKinds())
  const [showCrossTeam, setShowCrossTeam] = useState(true)

  const graphRef = useRef<HTMLElement>(null)

  const allNodes = useMemo(() => data?.nodes ?? [], [data])
  const allEdges = useMemo(() => data?.edges ?? [], [data])

  // Every group the canvas draws, including the unclaimed group — the sidebar
  // filter needs a row for each.
  const teams = useMemo(() => [...new Set(allNodes.map((n) => n.team))].sort((a, b) => a.localeCompare(b)), [allNodes])
  // ...but `N teams` counts only teams that exist. The unclaimed group is a
  // grouping this page renders, not a team the registry holds, and counting it
  // asserted one more team than the fleet has (AAASM-5184;
  // `design/v2/hi-fi/topology.jsx:928`).
  const teamCount = useMemo(() => realTeams(teams).length, [teams])
  const agentCount = allNodes.length

  /** The selected agent as of the latest payload — see `selectedNodeId`. */
  const selectedNode = useMemo(
    () => (selectedNodeId === null ? null : allNodes.find((n) => n.id === selectedNodeId) ?? null),
    [allNodes, selectedNodeId],
  )

  // Graph shows the whole forest, or one team when a filter is applied. Edges
  // are trimmed to those whose endpoints are both visible so depth/cycle badges
  // stay consistent with what is on screen.
  const visibleNodes = useMemo(
    () => (filterTeam === ALL_TEAMS ? allNodes : allNodes.filter((n) => n.team === filterTeam)),
    [allNodes, filterTeam],
  )
  const visibleEdges = useMemo(() => {
    if (filterTeam === ALL_TEAMS) return allEdges
    const ids = new Set(visibleNodes.map((n) => n.id))
    return allEdges.filter((e) => ids.has(e.source) && ids.has(e.target))
  }, [allEdges, visibleNodes, filterTeam])

  // Header/sidebar stats reflect the whole graph, not the filtered view.
  //
  // `⇆ N cross-team` is deliberately a fleet-wide fact — but that is also how it
  // came to contradict the canvas, which draws only a subset (AAASM-5138). The
  // count is not narrowed to match; instead the sidebar states the gap outright,
  // as `crossTeamHidden`.
  //
  // The gap is derived as `counted − drawn` rather than from the per-node `⇆N`
  // badges, because badges cannot express every way a crossing disappears. Three
  // reachable cases they miss: a crossing between two teams that are *both*
  // off-screen belongs to no visible node; unchecking "show cross-team" hides
  // every curve while no team filter is active, so no badge renders at all; and
  // unchecking an edge kind removes those edges too. Only `counted − drawn`
  // covers all of them, and it uses the same `isEdgeDrawn` predicate the canvas
  // itself uses, so the two cannot drift apart again.
  const stats = useMemo(() => {
    const teamsById = teamById(allNodes)
    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id))
    const active = allNodes.filter((n) => n.status === 'active').length
    const flagged = allNodes.filter((n) => n.flagged).length
    const crossTeam = crossTeamEdges(allEdges, teamsById).length
    const crossTeamHidden = hiddenCrossTeamCount(allEdges, visibleNodeIds, teamsById, {
      visibleKinds,
      showCrossTeam,
    })
    const hasCycles = detectDelegationCycles(allEdges).size > 0
    // Agents no team claims. Surfaced as its own warn-toned stat rather than
    // folded into the team count, which is what made the group invisible while
    // still inflating `N teams` (AAASM-5184;
    // `design/v2/hi-fi/topology.jsx:952`).
    const unclaimed = countUnclaimed(allNodes)
    return { active, flagged, crossTeam, crossTeamHidden, hasCycles, unclaimed }
  }, [allNodes, allEdges, visibleNodes, visibleKinds, showCrossTeam])

  const handleNodeClick = useCallback((node: TopologyNode) => {
    setSelectedNodeId(node.id)
    setSelectedTeam(null)
  }, [])
  const handleTeamClick = useCallback((team: string) => {
    setSelectedTeam(team)
    setSelectedNodeId(null)
  }, [])
  const clearSelection = useCallback(() => {
    setSelectedNodeId(null)
    setSelectedTeam(null)
  }, [])
  const handleFilterTeam = useCallback((team: string) => {
    setFilterTeam(team)
    clearSelection()
  }, [clearSelection])

  const handleToggleKind = useCallback((kind: TopologyEdgeKind) => {
    setVisibleKinds((prev) => {
      const next = new Set(prev)
      if (next.has(kind)) next.delete(kind)
      else next.add(kind)
      return next
    })
  }, [])

  const handleViewTrace = (agentId: string, sessionId: string) => {
    openTraceDrawer(agentId, sessionId)
  }

  const handleExportSvg = useCallback(() => {
    const svg = graphRef.current?.querySelector<SVGSVGElement>('[data-testid="topology-graph"]')
    if (svg) exportGraphSvg(svg)
  }, [])
  const handleExportJson = useCallback(() => {
    exportGraphJson(allNodes, allEdges)
  }, [allNodes, allEdges])

  // Right-hand panel is node-first, then team, else the empty prompt. Kept as a
  // named element rather than an inline nested ternary for readability (S3358).
  let detailPanel
  if (selectedNode) {
    detailPanel = (
      <NodeDetailPanel
        node={selectedNode}
        nodes={allNodes}
        edges={allEdges}
        onClose={() => setSelectedNodeId(null)}
        onViewTrace={handleViewTrace}
        onAgentMutated={() => ignorePromise(refetch())}
      />
    )
  } else if (selectedTeam) {
    detailPanel = (
      <TeamDetailPanel
        team={selectedTeam}
        nodes={allNodes}
        edges={allEdges}
        onClose={() => setSelectedTeam(null)}
        onSelectNode={handleNodeClick}
      />
    )
  } else {
    detailPanel = (
      <div className="topology-page__panel-empty" data-testid="topology-panel-empty">
        Click an agent or team in the graph to see its details.
      </div>
    )
  }

  return (
    <main className="topology-page" data-testid="topology-view">
      <header className="topology-page__head" data-testid="topology-header">
        <h1 className="topology-page__title">
          Topology{' '}<span className="topology-page__meta" data-testid="topology-meta">
            · {agentCount} agent{agentCount === 1 ? '' : 's'} · {teamCount} team{teamCount === 1 ? '' : 's'}
          </span>
        </h1>
        {!isLoading && !isError && (
          <ExportGraphButton onExportSvg={handleExportSvg} onExportJson={handleExportJson} />
        )}
      </header>

      {isLoading && (
        <div data-testid="topology-loading" className="topology-page__loading">
          {TOPOLOGY_SKELETON_KEYS.map((key) => (
            <div key={key} data-testid="topology-row-skeleton" className="topology-page__skeleton" />
          ))}
        </div>
      )}

      {isError && (
        <div data-testid="topology-error" className="topology-page__error">
          <p>Failed to load topology.</p>
          <button type="button" onClick={() => ignorePromise(refetch())}>Retry</button>
        </div>
      )}

      {/* A resolved graph with no nodes is a registered-but-empty fleet, not a
          blank canvas beside a control sidebar that governs nothing. It gets the
          shared EmptyState the other empty surfaces use — honest "no agents have
          phoned home" copy, no fabricated stats (AAASM-5172; cf. CapabilityPage,
          PoliciesPage). */}
      {!isLoading && !isError && allNodes.length === 0 && (
        <EmptyState
          page="overview"
          onCta={() => navigate('/onboarding')}
          onSecondary={() => navigate('/onboarding')}
        />
      )}

      {!isLoading && !isError && allNodes.length > 0 && (
        <div className="topology-page__body">
          <TopologySidebar
            stats={stats}
            teams={teams}
            filterTeam={filterTeam}
            onFilterTeam={handleFilterTeam}
            visibleKinds={visibleKinds}
            onToggleKind={handleToggleKind}
            showCrossTeam={showCrossTeam}
            onToggleCrossTeam={setShowCrossTeam}
          />

          <section
            ref={graphRef}
            className="topology-page__graph"
            data-testid="topology-graph-wrapper"
            aria-label="Topology graph"
          >
            <TopologyGraph
              nodes={visibleNodes}
              edges={visibleEdges}
              onNodeClick={handleNodeClick}
              onTeamClick={handleTeamClick}
              onBackgroundClick={clearSelection}
              visibleKinds={visibleKinds}
              showCrossTeam={showCrossTeam}
              selectedNodeId={selectedNode?.id ?? null}
              selectedTeam={selectedTeam}
              allNodes={allNodes}
              allEdges={allEdges}
              teamFilterActive={filterTeam !== ALL_TEAMS}
            />
          </section>

          <aside
            className="topology-page__panel"
            data-testid="topology-panel-wrapper"
            aria-label="Detail panel"
          >
            {detailPanel}
          </aside>
        </div>
      )}
    </main>
  )
}
