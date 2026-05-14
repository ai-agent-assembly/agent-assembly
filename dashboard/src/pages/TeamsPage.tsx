import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
} from '@tanstack/react-table'
import {
  joinTeamRows,
  useCostSummaryQuery,
  useTopologyOverviewQuery,
  type TeamListRow,
} from '../features/teams/api'

const PAGE_SIZE = 25

function SkeletonRows({ cols }: { cols: number }) {
  return (
    <>
      {Array.from({ length: 5 }).map((_, i) => (
        <tr key={i} data-testid="team-row-skeleton">
          {Array.from({ length: cols }).map((_, j) => (
            <td key={j} style={{ padding: '0.5rem' }}>
              <span
                style={{
                  display: 'block',
                  height: '1rem',
                  background: 'var(--surface-skeleton-shimmer)',
                  borderRadius: '4px',
                }}
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

function BurnCell({ pct }: { pct: number | null }) {
  if (pct == null) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  const color =
    pct >= 90
      ? 'var(--status-danger-solid)'
      : pct >= 70
        ? 'var(--status-caution-solid)'
        : 'var(--status-success-solid)'
  return (
    <span style={{ color, fontFamily: 'JetBrains Mono, monospace' }}>
      {pct.toFixed(1)}%
    </span>
  )
}

const columnHelper = createColumnHelper<TeamListRow>()

const columns = [
  columnHelper.accessor('team_id', {
    header: 'Team ID',
    cell: info => (
      <Link to={`/teams/${encodeURIComponent(info.getValue())}`}>{info.getValue()}</Link>
    ),
  }),
  columnHelper.accessor('agent_count', { header: 'Member Count' }),
  columnHelper.accessor('root_agent_count', { header: 'Root Agents' }),
  columnHelper.accessor('burn_pct', {
    header: 'Avg Budget Burn %',
    cell: info => <BurnCell pct={info.getValue()} />,
    sortUndefined: 'last',
  }),
  columnHelper.display({
    id: 'created_at',
    header: 'Created At',
    cell: () => <span style={{ color: 'var(--text-muted)' }}>—</span>,
  }),
]

export function TeamsPage() {
  const overviewQuery = useTopologyOverviewQuery()
  const costsQuery = useCostSummaryQuery()
  const [sorting, setSorting] = useState<SortingState>([{ id: 'agent_count', desc: true }])
  const [search, setSearch] = useState('')

  const rows = useMemo(
    () => joinTeamRows(overviewQuery.data, costsQuery.data).slice(0, 100),
    [overviewQuery.data, costsQuery.data],
  )

  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, globalFilter: search },
    onSortingChange: setSorting,
    onGlobalFilterChange: setSearch,
    globalFilterFn: (row, _columnId, filterValue: string) => {
      const needle = filterValue.trim().toLowerCase()
      if (!needle) return true
      return row.original.team_id.toLowerCase().startsWith(needle)
    },
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: PAGE_SIZE } },
  })

  const isLoading = overviewQuery.isLoading || costsQuery.isLoading
  const isError = overviewQuery.isError
  const totalRows = table.getFilteredRowModel().rows.length
  const pageIndex = table.getState().pagination.pageIndex
  const pageCount = table.getPageCount()

  return (
    <main style={{ padding: '1.5rem' }}>
      <h1>Teams</h1>

      {isError && (
        <div
          data-testid="teams-error"
          style={{ color: 'var(--status-danger-solid)', marginBottom: '1rem', display: 'flex', gap: '1rem', alignItems: 'center' }}
        >
          <span>Failed to load teams.</span>
          <button onClick={() => void overviewQuery.refetch()}>Retry</button>
        </div>
      )}

      <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '0.75rem' }}>
        <input
          data-testid="teams-search"
          aria-label="Search teams by ID prefix"
          placeholder="Filter by team ID prefix…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            padding: '0.4rem 0.6rem',
            border: '1px solid var(--form-input-border)',
            borderRadius: '4px',
            minWidth: '16rem',
          }}
        />
        <span data-testid="teams-count" style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
          {totalRows} team{totalRows === 1 ? '' : 's'}
        </span>
      </div>

      {!isLoading && !isError && rows.length === 0 && (
        <p data-testid="teams-empty" style={{ color: 'var(--text-muted)' }}>
          No teams registered yet.
        </p>
      )}

      <table data-testid="teams-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          {table.getHeaderGroups().map(hg => (
            <tr key={hg.id}>
              {hg.headers.map(header => (
                <th
                  key={header.id}
                  style={{
                    textAlign: 'left',
                    padding: '0.5rem',
                    borderBottom: '2px solid var(--surface-card-border)',
                    cursor: header.column.getCanSort() ? 'pointer' : undefined,
                  }}
                  onClick={header.column.getToggleSortingHandler()}
                >
                  {flexRender(header.column.columnDef.header, header.getContext())}
                  {header.column.getIsSorted() === 'asc'
                    ? ' ↑'
                    : header.column.getIsSorted() === 'desc'
                      ? ' ↓'
                      : ''}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {isLoading ? (
            <SkeletonRows cols={columns.length} />
          ) : (
            table.getRowModel().rows.map(row => (
              <tr key={row.id} data-testid="team-row" style={{ borderBottom: '1px solid var(--surface-hover-bg)' }}>
                {row.getVisibleCells().map(cell => (
                  <td key={cell.id} style={{ padding: '0.5rem' }}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>

      {pageCount > 1 && (
        <div
          data-testid="teams-pagination"
          style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginTop: '0.75rem' }}
        >
          <button
            data-testid="teams-prev"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            ←
          </button>
          <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            Page {pageIndex + 1} of {pageCount}
          </span>
          <button
            data-testid="teams-next"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            →
          </button>
        </div>
      )}
    </main>
  )
}
