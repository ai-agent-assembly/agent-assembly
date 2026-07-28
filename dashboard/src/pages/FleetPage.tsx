import { Link, Outlet, useNavigate, useSearchParams } from 'react-router-dom'
import { ignorePromise } from '../lib/ignorePromise'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table'
import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent } from 'react'
import { useAgentsQuery, useActiveSessionsQuery, useAgentEnforcementQuery, type Agent } from '../features/agents/api'
import { ActiveSessionsView } from './ActiveSessionsView'
import { toFleetAgent, formatLastSeen, type FleetAgent } from '../features/agents/fleetTypes'
import {
  applyFleetFilters,
  fleetFiltersFromParams,
  fleetFiltersToParamsRecord,
  frameworkOptions,
  DEFAULT_FLEET_FILTERS,
  type FleetFilters,
} from '../features/agents/fleetFilters'
import { certainFromQuery, certainText, isKnown, NO_DATA, type Certain } from '../lib/truthfulness'
import { StatusChip } from '../components/fleet/StatusChip'
import { ModeChip } from '../components/fleet/ModeChip'
import { TrustBar } from '../components/fleet/TrustBar'
import { useToast } from '../components/Toast'
import { SuspendReasonDialog } from '../components/SuspendReasonDialog'
import { Tooltip } from '../components/Tooltip'
import { useSuspendAgent, useResumeAgent } from '../features/agents/mutations'
import { usePermissions, WRITE_REQUIRED_HINT } from '../auth/usePermissions'
import { FleetFilterBar } from './FleetFilterBar'
import './FleetPage.css'

const COLUMN_COUNT = 11

/** Columns that render right-aligned numeric values (AAASM-5161). */
const NUMERIC_COLUMN_IDS: ReadonlySet<string> = new Set(['blocked24h', 'scrubbed24h'])

const SKELETON_ROW_KEYS = Array.from({ length: 5 }, (_, i) => `skeleton-row-${i}`)
const SKELETON_CELL_KEYS = Array.from({ length: COLUMN_COUNT }, (_, j) => `skeleton-cell-${j}`)

function SkeletonRows() {
  return (
    <>
      {SKELETON_ROW_KEYS.map((rowKey) => (
        <tr key={rowKey} data-testid="agent-row-skeleton">
          {SKELETON_CELL_KEYS.map((cellKey) => (
            <td key={cellKey} className="fleet-table__cell fleet-table__cell--skeleton">
              <span className="fleet-table__skeleton" />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

type NumericCellTone = 'danger' | 'scrub'

function NumericCell({
  value,
  tone,
}: Readonly<{ value: number | null; tone?: NumericCellTone }>) {
  return (
    <span className={`fleet-table__numeric${tone ? ` fleet-table__numeric--${tone}` : ''}`}>
      {value ?? '—'}
    </span>
  )
}

function sortIndicator(sorted: false | 'asc' | 'desc'): { glyph: string; label: string } {
  if (sorted === 'asc') return { glyph: '▲', label: 'sorted ascending' }
  if (sorted === 'desc') return { glyph: '▼', label: 'sorted descending' }
  return { glyph: '↕', label: 'not sorted' }
}

const columnHelper = createColumnHelper<FleetAgent>()

interface SelectColumnControls {
  selected: ReadonlySet<string>
  allSelected: boolean
  someSelected: boolean
  toggleAll: () => void
  toggleSelect: (id: string) => void
}

function buildSelectColumn(ctrl: SelectColumnControls): ColumnDef<FleetAgent> {
  return columnHelper.display({
    id: 'select',
    header: () => (
      <input
        type="checkbox"
        checked={ctrl.allSelected}
        ref={(el) => {
          if (el) el.indeterminate = !ctrl.allSelected && ctrl.someSelected
        }}
        onChange={ctrl.toggleAll}
        data-testid="fleet-select-all"
        aria-label="Select all agents"
      />
    ),
    cell: ({ row }) => (
      <input
        type="checkbox"
        checked={ctrl.selected.has(row.original.id)}
        onChange={() => ctrl.toggleSelect(row.original.id)}
        data-testid={`fleet-select-${row.original.id}`}
        aria-label={`Select ${row.original.name}`}
      />
    ),
  })
}

const baseColumns: ColumnDef<FleetAgent>[] = [
  columnHelper.accessor('name', {
    header: 'Agent',
    enableSorting: true,
    cell: (info) => {
      const agent = info.row.original
      return (
        <div className="fleet-table__agent">
          {agent.flagged && (
            <span className="fleet-table__flag" aria-label="flagged" title="flagged">●</span>
          )}
          <Link
            to={`/agents/${agent.id}`}
            className="fleet-table__agent-name"
            data-testid="fleet-row-name"
          >
            {agent.name}
          </Link>
          {agent.note && <span className="fleet-table__agent-note">{agent.note}</span>}
        </div>
      )
    },
  }),
  columnHelper.accessor('framework', {
    header: 'Framework',
    enableSorting: true,
    cell: (info) => <span className="fleet-table__chip">{info.getValue()}</span>,
  }),
  columnHelper.accessor('owner', {
    header: 'Owner',
    enableSorting: true,
    cell: (info) => {
      const owner = info.getValue()
      return <span className="fleet-table__owner">{owner ? `@${owner}` : '—'}</span>
    },
  }),
  columnHelper.accessor('mode', {
    id: 'mode',
    header: 'Mode',
    enableSorting: false,
    cell: (info) => <ModeChip mode={info.getValue()} />,
  }),
  columnHelper.accessor('status', {
    header: 'Status',
    enableSorting: true,
    cell: (info) => <StatusChip status={info.getValue()} />,
  }),
  columnHelper.accessor('trust', {
    header: 'Trust',
    enableSorting: true,
    cell: (info) => <TrustBar score={info.getValue()} />,
  }),
  columnHelper.accessor('blocked24h', {
    header: 'Blocked / 24h',
    enableSorting: true,
    cell: (info) => <NumericCell value={info.getValue()} />,
  }),
  columnHelper.accessor('scrubbed24h', {
    header: 'Scrubbed / 24h',
    enableSorting: true,
    cell: (info) => <NumericCell value={info.getValue()} />,
  }),
  columnHelper.accessor('lastSeen', {
    header: 'Last seen',
    enableSorting: true,
    cell: (info) => (
      <span className="fleet-table__last-seen">{formatLastSeen(info.getValue())}</span>
    ),
  }),
  columnHelper.display({
    id: 'actions',
    header: '',
    cell: (info) => (
      <Link
        to={`/agents/${info.row.original.id}?tab=capability`}
        className="fleet-table__action"
        data-testid="fleet-row-action"
      >
        caps →
      </Link>
    ),
  }),
] as ColumnDef<FleetAgent>[]

type FleetView = 'agents' | 'sessions'

/**
 * Why the agents view has no rows — the four cases a bare headers-only table
 * used to conflate (AAASM-5130, ADR-0017 correction C1).
 *
 * They are genuinely different facts and must never render alike:
 * `filter-empty` and `fleet-empty` are *successful, known* results with
 * different remedies (clear the filter vs. onboard an agent), while
 * `unavailable` and `loading` have established nothing at all.
 */
type FleetTableState = 'loading' | 'unavailable' | 'fleet-empty' | 'filter-empty' | 'rows'

/**
 * Classify the agents view from the query outcome plus the post-filter count.
 *
 * The absence branch comes first and is deliberately terminal: a failed or
 * in-flight request has not established that the fleet is empty, so it may not
 * borrow either empty-state copy. Only once the list is `known` — where `[]` is
 * a real answer, not a missing one — does the filtered count decide which of
 * the two empty results applies.
 *
 * Which absence it is comes from `Certain.state`, not from a second boolean.
 * That distinction is the whole point of the vocabulary: only `unavailable`
 * means the request failed, and only `unavailable` may say so. Every other
 * absence — `unknown` above all, which is what a query paused offline reports —
 * means "asked, do not yet know", and that is the skeleton, not a failure
 * banner for a request that was never sent.
 */
function fleetTableState(agents: Certain<Agent[]>, filteredCount: number): FleetTableState {
  if (!isKnown(agents)) return agents.state === 'unavailable' ? 'unavailable' : 'loading'
  if (agents.value.length === 0) return 'fleet-empty'
  return filteredCount === 0 ? 'filter-empty' : 'rows'
}

/**
 * `true` when the click landed on an interactive element inside the row
 * (link, button, input, label). Used to suppress the row-level navigation
 * so the inner control's own handler stays authoritative.
 */
function clickOnInteractive(e: MouseEvent<HTMLTableRowElement>): boolean {
  const target = e.target as HTMLElement | null
  return target?.closest('a, button, input, label') !== null
}

export function FleetPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  // `isPending`, not `isLoading`: TanStack derives `isLoading = isPending &&
  // isFetching`, so a query that is pending but *paused* (the default
  // `networkMode: 'online'` behaviour when the browser is offline) reports
  // `isLoading === false` with no data and no error. Feeding that to
  // `certainFromQuery` as the pending flag would classify a request that was
  // never sent as a failed one.
  const { data: agents, isPending, isError, refetch } = useAgentsQuery()
  const { data: activeSessions } = useActiveSessionsQuery()
  const { data: enforcement } = useAgentEnforcementQuery('24h')
  // Default sort mirrors the hi-fi Fleet (sortKey='trust', sortDir='asc') so the
  // least-trusted agents surface first (AAASM-5069).
  const [sorting, setSorting] = useState<SortingState>([{ id: 'trust', desc: false }])
  const [view, setView] = useState<FleetView>('agents')

  const [searchParams, setSearchParams] = useSearchParams()
  const filters = useMemo<FleetFilters>(
    () => fleetFiltersFromParams(searchParams),
    [searchParams],
  )
  const setFilters = useCallback(
    (next: FleetFilters) => {
      setSearchParams(fleetFiltersToParamsRecord(next), { replace: true })
    },
    [setSearchParams],
  )

  const fleetAgents = useMemo(
    () => (agents ?? []).map((a) => toFleetAgent(a, enforcement)),
    [agents, enforcement],
  )
  const frameworks = useMemo(() => frameworkOptions(fleetAgents), [fleetAgents])
  const filteredFleet = useMemo(
    () => applyFleetFilters(fleetAgents, filters),
    [fleetAgents, filters],
  )

  // Selection state: persists across filter / sort; cleared via the bulk
  // action bar (next commit). Drop selections for ids that disappear from
  // the data source (e.g. an agent was deregistered).
  const [selected, setSelected] = useState<Set<string>>(() => new Set())
  const [showBulkSuspendDialog, setShowBulkSuspendDialog] = useState(false)
  const [bulkSuspendPending, setBulkSuspendPending] = useState(false)
  const [bulkResumePending, setBulkResumePending] = useState(false)
  const knownIds = useRef<Set<string>>(new Set())
  useEffect(() => {
    const next = new Set(fleetAgents.map((a) => a.id))
    knownIds.current = next
    setSelected((prev) => {
      let changed = false
      const filtered = new Set<string>()
      for (const id of prev) {
        if (next.has(id)) filtered.add(id)
        else changed = true
      }
      return changed ? filtered : prev
    })
  }, [fleetAgents])

  const visibleIds = useMemo(() => filteredFleet.map((a) => a.id), [filteredFleet])
  const allSelected = visibleIds.length > 0 && visibleIds.every((id) => selected.has(id))
  const someSelected = !allSelected && visibleIds.some((id) => selected.has(id))

  const toggleSelect = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const toggleAll = useCallback(() => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (visibleIds.every((id) => prev.has(id))) {
        for (const id of visibleIds) next.delete(id)
      } else {
        for (const id of visibleIds) next.add(id)
      }
      return next
    })
  }, [visibleIds])

  const columns = useMemo<ColumnDef<FleetAgent>[]>(
    () => [
      buildSelectColumn({ selected, allSelected, someSelected, toggleAll, toggleSelect }),
      ...baseColumns,
    ],
    [selected, allSelected, someSelected, toggleAll, toggleSelect],
  )

  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: filteredFleet,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  const agentsCertain = useMemo<Certain<Agent[]>>(
    () => certainFromQuery<Agent[]>({ isError, isPending, data: agents }),
    [isError, isPending, agents],
  )
  const filteredCount = filteredFleet.length
  const tableState = fleetTableState(agentsCertain, filteredCount)
  // Counts are claims about the fleet, so they fold to `—` rather than `0`
  // whenever the fleet size is not yet a known fact.
  const totalAgentsText = certainText(agentsCertain, (list) => String(list.length))
  const filteredCountText = isKnown(agentsCertain) ? String(filteredCount) : NO_DATA

  const suspend = useSuspendAgent()
  const resume = useResumeAgent()
  const { canWrite } = usePermissions()

  const reportBulkResult = useCallback(
    (verb: 'suspended' | 'resumed', ids: string[], results: PromiseSettledResult<unknown>[]) => {
      const okCount = results.filter((r) => r.status === 'fulfilled').length
      const failCount = results.length - okCount
      if (failCount === 0) {
        setSelected(new Set())
        toast(`${okCount} ${verb}`, 'success')
      } else if (okCount === 0) {
        toast(`${failCount} failed`, 'error')
      } else {
        // Keep failed ids in the selection so the user can retry without
        // re-clicking each row.
        const failedIds = new Set(
          results
            .map((r, i) => (r.status === 'rejected' ? ids[i] : null))
            .filter((x): x is string => Boolean(x)),
        )
        setSelected(failedIds)
        toast(`${okCount} ${verb}, ${failCount} failed`, 'error')
      }
    },
    [toast],
  )

  const onConfirmBulkSuspend = useCallback(
    async (reason: string) => {
      const ids = Array.from(selected)
      setBulkSuspendPending(true)
      const results = await Promise.allSettled(
        ids.map((id) => suspend.mutateAsync({ id, reason })),
      )
      setBulkSuspendPending(false)
      setShowBulkSuspendDialog(false)
      reportBulkResult('suspended', ids, results)
    },
    [selected, suspend, reportBulkResult],
  )

  const onClickBulkResume = useCallback(async () => {
    const ids = Array.from(selected)
    setBulkResumePending(true)
    const results = await Promise.allSettled(
      ids.map((id) => resume.mutateAsync({ id })),
    )
    setBulkResumePending(false)
    reportBulkResult('resumed', ids, results)
  }, [selected, resume, reportBulkResult])

  return (
    <main className="fleet-page" data-testid="fleet-page">
      <header className="fleet-page__head" data-testid="fleet-page-head">
        <div className="fleet-page__heading">
          <h1 className="fleet-page__title">
            Fleet{' '}<span className="fleet-page__count" data-testid="fleet-page-count">
              · {filteredCountText} of {totalAgentsText} agents
            </span>
          </h1>
          <p className="fleet-page__sub">
            All registered agents across frameworks. Click a row to inspect, or select multiple for bulk actions.
          </p>
        </div>
        <div className="fleet-page__actions">
          <button type="button" className="fleet-page__btn" disabled data-testid="fleet-action-register">
            + register agent
          </button>
          <button type="button" className="fleet-page__btn" disabled data-testid="fleet-action-export">
            ⏏ export csv
          </button>
        </div>
      </header>

      <div className="fleet-tabs" data-testid="fleet-tabs" role="tablist" aria-label="Fleet views">
        <button
          type="button"
          role="tab"
          aria-selected={view === 'agents'}
          className={`fleet-tabs__tab${view === 'agents' ? ' fleet-tabs__tab--active' : ''}`}
          onClick={() => setView('agents')}
          data-testid="fleet-tab-agents"
        >
          Agents<span className="fleet-tabs__count" data-testid="fleet-tab-agents-count">{totalAgentsText}</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={view === 'sessions'}
          className={`fleet-tabs__tab${view === 'sessions' ? ' fleet-tabs__tab--active' : ''}`}
          onClick={() => setView('sessions')}
          data-testid="fleet-tab-sessions"
        >
          Active Sessions
          {' '}
          <span
            className={`fleet-tabs__count${view !== 'sessions' ? ' fleet-tabs__count--live' : ''}`}
            data-testid="fleet-tab-sessions-count"
          >
            {activeSessions?.length ?? 0}
          </span>
        </button>
      </div>

      {view === 'sessions' && <ActiveSessionsView />}

      {view === 'agents' && (
        <FleetFilterBar
          filters={filters}
          frameworks={frameworks}
          onChange={setFilters}
          rightSlot={selected.size > 0 ? (
            <div className="fleet-bulkbar" data-testid="fleet-bulkbar">
              <span className="fleet-bulkbar__count" data-testid="fleet-bulkbar-count">
                {selected.size} selected
              </span>
              <Tooltip content={canWrite ? '' : WRITE_REQUIRED_HINT}>
                <button
                  type="button"
                  className="fleet-bulkbar__btn"
                  onClick={() => toast(`Switched ${selected.size} agents to shadow mode (mock)`, 'info')}
                  disabled={!canWrite}
                  title={canWrite ? undefined : WRITE_REQUIRED_HINT}
                  data-testid="fleet-bulkbar-shadow"
                >
                  → shadow mode
                </button>
                <button
                  type="button"
                  className="fleet-bulkbar__btn fleet-bulkbar__btn--danger"
                  onClick={() => setShowBulkSuspendDialog(true)}
                  disabled={bulkSuspendPending || bulkResumePending || !canWrite}
                  title={canWrite ? undefined : WRITE_REQUIRED_HINT}
                  data-testid="fleet-bulkbar-suspend"
                >
                  ■ suspend
                </button>
                <button
                  type="button"
                  className="fleet-bulkbar__btn"
                  onClick={() => ignorePromise(onClickBulkResume())}
                  disabled={bulkSuspendPending || bulkResumePending || !canWrite}
                  title={canWrite ? undefined : WRITE_REQUIRED_HINT}
                  data-testid="fleet-bulkbar-resume"
                >
                  {bulkResumePending ? 'Resuming…' : '▶ resume'}
                </button>
              </Tooltip>
              <button
                type="button"
                className="fleet-bulkbar__btn fleet-bulkbar__btn--ghost"
                onClick={() => setSelected(new Set())}
                data-testid="fleet-bulkbar-clear"
              >
                clear
              </button>
            </div>
          ) : undefined}
        />
      )}

      {view === 'agents' && tableState === 'unavailable' && (
        <div className="fleet-error" data-testid="agents-error" role="alert">
          <span>Failed to load agents.</span>
          <button type="button" onClick={() => ignorePromise(refetch())}>Retry</button>
        </div>
      )}

      {view === 'agents' && tableState === 'fleet-empty' && (
        <p className="fleet-empty fleet-empty--inline" data-testid="agents-empty">
          No agents registered yet.{' '}
          <a href="https://docs.agent-assembly.com/quickstart" target="_blank" rel="noreferrer">
            Read the quickstart guide →
          </a>
        </p>
      )}

      {/* The table is suppressed for every state that has no rows *and* no
          rows to hope for: an empty grid under an error banner or an
          onboarding callout reads as "the fleet is empty", which is exactly
          the claim neither state is entitled to make. `filter-empty` keeps
          it — the columns are still meaningful there. */}
      {view === 'agents' && tableState !== 'unavailable' && tableState !== 'fleet-empty' && (
        <div className="fleet-table__wrap">
          <table className="fleet-table" data-testid="agents-table">
            <thead>
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers.map((header) => (
                    <th
                      key={header.id}
                      className={`fleet-table__th${header.column.getCanSort() ? ' fleet-table__th--sortable' : ''}${NUMERIC_COLUMN_IDS.has(header.column.id) ? ' fleet-table__th--numeric' : ''}`}
                      onClick={header.column.getToggleSortingHandler()}
                    >
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {header.column.getCanSort() && (() => {
                        const sorted = header.column.getIsSorted()
                        const { glyph, label } = sortIndicator(sorted)
                        return (
                          <span
                            className={`fleet-table__sort${sorted ? '' : ' fleet-table__sort--inactive'}`}
                            data-testid={`fleet-sort-${header.column.id}`}
                            aria-label={label}
                          >
                            {glyph}
                          </span>
                        )
                      })()}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {tableState === 'loading' ? (
                <SkeletonRows />
              ) : (
                table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    data-testid="agent-row"
                    className={`fleet-table__row${row.original.flagged ? ' fleet-table__row--flagged' : ''}`}
                    onClick={(e) => {
                      if (clickOnInteractive(e)) return
                      navigate(`/agents/${row.original.id}`)
                    }}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td
                        key={cell.id}
                        className={`fleet-table__cell${NUMERIC_COLUMN_IDS.has(cell.column.id) ? ' fleet-table__cell--numeric' : ''}`}
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {tableState === 'filter-empty' && (
            <output className="fleet-empty fleet-empty--filtered" data-testid="fleet-filter-empty">
              <p className="fleet-empty__title">no agents match these filters</p>
              <p className="fleet-empty__body">
                All {totalAgentsText} registered agents were excluded by the current filters.
                They are URL-persisted, so a shared or bookmarked link can arrive already narrowed.
              </p>
              <div className="fleet-empty__action">
                <button
                  type="button"
                  className="fleet-page__btn"
                  onClick={() => setFilters(DEFAULT_FLEET_FILTERS)}
                  data-testid="fleet-filter-empty-clear"
                >
                  Clear filters
                </button>
              </div>
            </output>
          )}
        </div>
      )}

      {/* Drawer overlay (Agent Detail) renders via nested route — sits on top
          of the page via fixed positioning, so the Fleet table stays mounted
          underneath and filter state is preserved when the drawer closes. */}
      <Outlet />

      {showBulkSuspendDialog && (
        <SuspendReasonDialog
          title={`Suspend ${selected.size} agent${selected.size === 1 ? '' : 's'}`}
          body="The reason is logged once for the entire batch. Per-agent failures stay selected so you can retry."
          pending={bulkSuspendPending}
          onConfirm={onConfirmBulkSuspend}
          onCancel={() => setShowBulkSuspendDialog(false)}
        />
      )}
    </main>
  )
}
