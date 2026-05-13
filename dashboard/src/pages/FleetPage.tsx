import { Link } from 'react-router-dom'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
} from '@tanstack/react-table'
import { useState } from 'react'
import { useAgentsQuery, type Agent } from '../features/agents/api'

const STATUS_COLOR: Record<string, string> = {
  active: '#16a34a',
  idle: '#ca8a04',
  suspended: '#d97706',
  error: '#dc2626',
  deregistered: '#6b7280',
}

function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLOR[status] ?? '#6b7280'
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 600,
        color: '#fff',
        background: color,
      }}
    >
      {status}
    </span>
  )
}

function SkeletonRows() {
  return (
    <>
      {Array.from({ length: 5 }).map((_, i) => (
        <tr key={i} data-testid="agent-row-skeleton">
          {Array.from({ length: 5 }).map((_, j) => (
            <td key={j} style={{ padding: '0.5rem' }}>
              <span
                style={{
                  display: 'block',
                  height: '1rem',
                  background: '#e5e7eb',
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

const columnHelper = createColumnHelper<Agent>()

const columns = [
  columnHelper.accessor('name', {
    header: 'Name',
    cell: info => (
      <Link to={`/agents/${info.row.original.id}`}>{info.getValue()}</Link>
    ),
  }),
  columnHelper.accessor('framework', { header: 'Framework' }),
  columnHelper.accessor('status', {
    header: 'Status',
    cell: info => <StatusBadge status={info.getValue()} />,
  }),
  columnHelper.accessor('last_event', {
    header: 'Last seen',
    cell: info => info.getValue() ?? '—',
  }),
  columnHelper.accessor(row => row.recent_events.length, {
    id: 'recent_events_count',
    header: 'Recent events',
  }),
]

export function FleetPage() {
  const { data: agents, isLoading, isError, refetch } = useAgentsQuery()
  const [sorting, setSorting] = useState<SortingState>([])

  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: agents ?? [],
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  return (
    <main style={{ padding: '1.5rem' }}>
      <h1>Agents</h1>

      {isError && (
        <div
          data-testid="agents-error"
          style={{ color: '#dc2626', marginBottom: '1rem', display: 'flex', gap: '1rem', alignItems: 'center' }}
        >
          <span>Failed to load agents.</span>
          <button onClick={() => void refetch()}>Retry</button>
        </div>
      )}

      {!isLoading && !isError && agents?.length === 0 && (
        <p data-testid="agents-empty">
          No agents registered yet.{' '}
          <a href="https://docs.agent-assembly.io/quickstart" target="_blank" rel="noreferrer">
            Read the quickstart guide →
          </a>
        </p>
      )}

      <table data-testid="agents-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          {table.getHeaderGroups().map(hg => (
            <tr key={hg.id}>
              {hg.headers.map(header => (
                <th
                  key={header.id}
                  style={{
                    textAlign: 'left',
                    padding: '0.5rem',
                    borderBottom: '2px solid #e5e7eb',
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
            <SkeletonRows />
          ) : (
            table.getRowModel().rows.map(row => (
              <tr
                key={row.id}
                data-testid="agent-row"
                style={{ borderBottom: '1px solid #f3f4f6' }}
              >
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
    </main>
  )
}
