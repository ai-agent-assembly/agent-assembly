import { useState } from 'react'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
  type SortingFn,
} from '@tanstack/react-table'
import { SeverityBadge } from './SeverityBadge'
import { StatusBadge } from './StatusBadge'
import { SEVERITY_ORDER, type Alert, type AlertStatus, type Severity } from './types'

interface AlertListProps {
  rows: readonly Alert[]
  onSelect?: (alertId: string) => void
  /** When true, render skeleton placeholder rows instead of `rows`. */
  loading?: boolean
}

// CRITICAL > HIGH > MEDIUM > LOW (descending = most severe first).
const SEVERITY_RANK: Record<Severity, number> = Object.fromEntries(
  SEVERITY_ORDER.map((s, i) => [s, SEVERITY_ORDER.length - i]),
) as Record<Severity, number>

const STATUS_RANK: Record<AlertStatus, number> = {
  FIRING: 3,
  SUPPRESSED: 2,
  RESOLVED: 1,
}

const sortSeverity: SortingFn<Alert> = (a, b) =>
  SEVERITY_RANK[a.original.severity] - SEVERITY_RANK[b.original.severity]

const sortStatus: SortingFn<Alert> = (a, b) =>
  STATUS_RANK[a.original.status] - STATUS_RANK[b.original.status]

const sortDuration: SortingFn<Alert> = (a, b) =>
  Date.parse(a.original.firstFiredAt) - Date.parse(b.original.firstFiredAt)

function formatDuration(firstFiredAt: string, resolvedAt: string | null): string {
  const start = Date.parse(firstFiredAt)
  if (Number.isNaN(start)) return '—'
  const end = resolvedAt ? Date.parse(resolvedAt) : Date.now()
  const ms = Math.max(0, end - start)
  const totalMinutes = Math.floor(ms / 60_000)
  if (totalMinutes < 1) return '< 1m'
  if (totalMinutes < 60) return `${totalMinutes}m`
  const hours = Math.floor(totalMinutes / 60)
  if (hours < 24) return `${hours}h ${totalMinutes % 60}m`
  const days = Math.floor(hours / 24)
  return `${days}d ${hours % 24}h`
}

function formatFirstFired(iso: string): string {
  const ts = Date.parse(iso)
  if (Number.isNaN(ts)) return iso
  return new Date(ts).toISOString().replace('T', ' ').slice(0, 16)
}

const columnHelper = createColumnHelper<Alert>()

const columns = [
  columnHelper.accessor('severity', {
    header: 'Severity',
    cell: (info) => <SeverityBadge severity={info.getValue()} />,
    sortingFn: sortSeverity,
  }),
  columnHelper.accessor('ruleName', {
    header: 'Alert',
    cell: (info) => info.getValue(),
    enableSorting: false,
  }),
  columnHelper.accessor((row) => row.agentId ?? '—', {
    id: 'agent',
    header: 'Agent / fleet',
    enableSorting: false,
  }),
  columnHelper.accessor('status', {
    header: 'Status',
    cell: (info) => <StatusBadge status={info.getValue()} />,
    sortingFn: sortStatus,
  }),
  columnHelper.accessor('firstFiredAt', {
    header: 'First fired',
    cell: (info) => formatFirstFired(info.getValue()),
    enableSorting: false,
  }),
  columnHelper.accessor(
    (row) => Date.now() - Date.parse(row.firstFiredAt),
    {
      id: 'duration',
      header: 'Duration',
      cell: (info) => formatDuration(info.row.original.firstFiredAt, info.row.original.resolvedAt),
      sortingFn: sortDuration,
    },
  ),
  columnHelper.accessor((row) => row.destinationIds.join(', ') || '—', {
    id: 'destination',
    header: 'Destination',
    enableSorting: false,
  }),
]

function SkeletonRows({ columnCount }: { columnCount: number }) {
  return (
    <>
      {Array.from({ length: 5 }).map((_, i) => (
        <tr key={i} data-testid="alert-row-skeleton" style={{ borderBottom: '1px solid #f3f4f6' }}>
          {Array.from({ length: columnCount }).map((_, j) => (
            <td key={j} style={{ padding: '0.5rem' }}>
              <span
                style={{
                  display: 'block',
                  height: '0.875rem',
                  background: '#e5e7eb',
                  borderRadius: '4px',
                  opacity: 0.6 + (i % 2) * 0.2,
                }}
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

export function AlertList({ rows, onSelect, loading = false }: AlertListProps) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: 'severity', desc: true },
  ])

  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: rows as Alert[],
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    enableSortingRemoval: false,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  return (
    <table
      data-testid="alerts-table"
      style={{ width: '100%', borderCollapse: 'collapse' }}
    >
      <thead>
        {table.getHeaderGroups().map((hg) => (
          <tr key={hg.id}>
            {hg.headers.map((header) => (
              <th
                key={header.id}
                onClick={header.column.getToggleSortingHandler()}
                style={{
                  textAlign: 'left',
                  padding: '0.5rem',
                  borderBottom: '2px solid #e5e7eb',
                  fontSize: '0.75rem',
                  textTransform: 'uppercase',
                  color: '#6b7280',
                  letterSpacing: '0.04em',
                  cursor: header.column.getCanSort() ? 'pointer' : 'default',
                  userSelect: 'none',
                }}
                data-testid={`alerts-th-${header.column.id}`}
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
        {loading ? (
          <SkeletonRows columnCount={columns.length} />
        ) : (
          table.getRowModel().rows.map((row) => (
            <tr
              key={row.id}
              data-testid="alert-row"
              onClick={() => onSelect?.(row.original.id)}
              style={{
                borderBottom: '1px solid #f3f4f6',
                cursor: onSelect ? 'pointer' : 'default',
              }}
            >
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} style={{ padding: '0.5rem', fontSize: '0.875rem' }}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))
        )}
      </tbody>
    </table>
  )
}
