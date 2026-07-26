import { useCallback, useMemo, useRef, useState } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import { useTopologyQuery } from '../features/topology/api'
import { detectDelegationCycles } from '../features/topology/hierarchy'
import { defaultVisibleKinds } from '../features/topology/edgeKinds'
import { exportGraphJson, exportGraphSvg } from '../features/topology/exportGraph'
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

  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [selectedTeam, setSelectedTeam] = useState<string | null>(null)
  const [filterTeam, setFilterTeam] = useState<string>(ALL_TEAMS)
  const [visibleKinds, setVisibleKinds] = useState<Set<TopologyEdgeKind>>(() => defaultVisibleKinds())
  const [showCrossTeam, setShowCrossTeam] = useState(true)

  const graphRef = useRef<HTMLElement>(null)

  const allNodes = useMemo(() => data?.nodes ?? [], [data])
  const allEdges = useMemo(() => data?.edges ?? [], [data])

  const teams = useMemo(() => [...new Set(allNodes.map((n) => n.team))].sort((a, b) => a.localeCompare(b)), [allNodes])
  const teamCount = teams.length
  const agentCount = allNodes.length

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
  const stats = useMemo(() => {
    const active = allNodes.filter((n) => n.status === 'active').length
    const flagged = allNodes.filter((n) => n.flagged).length
    // Cross-team count comes from the server's own `crossTeam` flag
    // (AAASM-5099) so this badge, the canvas curves, and `/topology/edges` agree
    // on one definition. Falls back to comparing endpoint teams for a payload
    // that predates the flag.
    const teamById = new Map(allNodes.map((n) => [n.id, n.team]))
    const crossTeam = allEdges.filter((e) => {
      if (e.crossTeam !== undefined) return e.crossTeam
      const s = teamById.get(e.source)
      const t = teamById.get(e.target)
      return s !== undefined && t !== undefined && s !== t
    }).length
    const hasCycles = detectDelegationCycles(allEdges).size > 0
    return { active, flagged, crossTeam, hasCycles }
  }, [allNodes, allEdges])

  const handleNodeClick = useCallback((node: TopologyNode) => {
    setSelectedNode(node)
    setSelectedTeam(null)
  }, [])
  const handleTeamClick = useCallback((team: string) => {
    setSelectedTeam(team)
    setSelectedNode(null)
  }, [])
  const clearSelection = useCallback(() => {
    setSelectedNode(null)
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
        onClose={() => setSelectedNode(null)}
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

      {!isLoading && !isError && (
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
