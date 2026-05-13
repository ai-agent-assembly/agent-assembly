import { Link } from 'react-router-dom'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
} from '@tanstack/react-table'
import { useCallback, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useAgentsQuery } from '../features/agents/api'
import { toFleetAgent, type FleetAgent } from '../features/agents/fleetTypes'
import {
  applyFleetFilters,
  fleetFiltersFromParams,
  fleetFiltersToParamsRecord,
  frameworkOptions,
  type FleetFilters,
} from '../features/agents/fleetFilters'
import { StatusChip } from '../components/fleet/StatusChip'
import { ModeChip } from '../components/fleet/ModeChip'
import { TrustBar } from '../components/fleet/TrustBar'
import { FleetFilterBar } from './FleetFilterBar'
import './FleetPage.css'

const COLUMN_COUNT = 10

function SkeletonRows() {
  return (
    <>
      {Array.from({ length: 5 }).map((_, i) => (
        <tr key={i} data-testid="agent-row-skeleton">
          {Array.from({ length: COLUMN_COUNT }).map((_, j) => (
            <td key={j} className="fleet-table__cell fleet-table__cell--skeleton">
              <span className="fleet-table__skeleton" />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

function NumericCell({ value }: { value: number | null }) {
  return (
    <span className="fleet-table__numeric">
      {value === null ? '—' : value}
    </span>
  )
}

const columnHelper = createColumnHelper<FleetAgent>()

const fleetColumns = [
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
      <span className="fleet-table__last-seen">{info.getValue() ?? '—'}</span>
    ),
  }),
  columnHelper.display({
    id: 'actions',
    header: '',
    cell: (info) => (
      <Link
        to={`/agents/${info.row.original.id}`}
        className="fleet-table__action"
        data-testid="fleet-row-action"
      >
        caps →
      </Link>
    ),
  }),
]

type FleetView = 'agents' | 'sessions'

export function FleetPage() {
  const { data: agents, isLoading, isError, refetch } = useAgentsQuery()
  const [sorting, setSorting] = useState<SortingState>([])
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

  const fleetAgents = useMemo(() => (agents ?? []).map(toFleetAgent), [agents])
  const frameworks = useMemo(() => frameworkOptions(fleetAgents), [fleetAgents])
  const filteredFleet = useMemo(
    () => applyFleetFilters(fleetAgents, filters),
    [fleetAgents, filters],
  )

  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: filteredFleet,
    columns: fleetColumns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  const totalAgents = agents?.length ?? 0
  const filteredCount = filteredFleet.length

  return (
    <main className="fleet-page" data-testid="fleet-page">
      <header className="fleet-page__head" data-testid="fleet-page-head">
        <div className="fleet-page__heading">
          <h1 className="fleet-page__title">
            Fleet
            <span className="fleet-page__count" data-testid="fleet-page-count">
              · {filteredCount} of {totalAgents} agents
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

      <nav className="fleet-tabs" data-testid="fleet-tabs" role="tablist" aria-label="Fleet views">
        <button
          type="button"
          role="tab"
          aria-selected={view === 'agents'}
          className={`fleet-tabs__tab${view === 'agents' ? ' fleet-tabs__tab--active' : ''}`}
          onClick={() => setView('agents')}
          data-testid="fleet-tab-agents"
        >
          Agents
          <span className="fleet-tabs__count">{filteredCount}</span>
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
        </button>
      </nav>

      {view === 'sessions' && (
        <div className="fleet-empty" data-testid="fleet-sessions-empty">
          <p className="fleet-empty__title">Active sessions view</p>
          <p className="fleet-empty__body">
            Wired in a follow-up sub-task. Tracking continues per agent on the Agent
            Detail drawer (AAASM-1052).
          </p>
        </div>
      )}

      {view === 'agents' && (
        <FleetFilterBar
          filters={filters}
          frameworks={frameworks}
          onChange={setFilters}
        />
      )}

      {view === 'agents' && isError && (
        <div className="fleet-error" data-testid="agents-error">
          <span>Failed to load agents.</span>
          <button onClick={() => void refetch()}>Retry</button>
        </div>
      )}

      {view === 'agents' && !isLoading && !isError && agents?.length === 0 && (
        <p className="fleet-empty fleet-empty--inline" data-testid="agents-empty">
          No agents registered yet.{' '}
          <a href="https://docs.agent-assembly.io/quickstart" target="_blank" rel="noreferrer">
            Read the quickstart guide →
          </a>
        </p>
      )}

      {view === 'agents' && (
        <div className="fleet-table__wrap">
          <table className="fleet-table" data-testid="agents-table">
            <thead>
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers.map((header) => (
                    <th
                      key={header.id}
                      className={`fleet-table__th${header.column.getCanSort() ? ' fleet-table__th--sortable' : ''}`}
                      onClick={header.column.getToggleSortingHandler()}
                    >
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {header.column.getCanSort() && (() => {
                        const sorted = header.column.getIsSorted()
                        const glyph = sorted === 'asc' ? '▲' : sorted === 'desc' ? '▼' : '↕'
                        return (
                          <span
                            className={`fleet-table__sort${sorted ? '' : ' fleet-table__sort--inactive'}`}
                            data-testid={`fleet-sort-${header.column.id}`}
                            aria-label={
                              sorted === 'asc'
                                ? 'sorted ascending'
                                : sorted === 'desc'
                                  ? 'sorted descending'
                                  : 'not sorted'
                            }
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
              {isLoading ? (
                <SkeletonRows />
              ) : (
                table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    data-testid="agent-row"
                    className={`fleet-table__row${row.original.flagged ? ' fleet-table__row--flagged' : ''}`}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="fleet-table__cell">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </main>
  )
}
