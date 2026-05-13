import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  createColumnHelper,
} from '@tanstack/react-table'
import { SeverityBadge } from './SeverityBadge'
import { StatusBadge } from './StatusBadge'
import type { Alert } from './types'

interface AlertListProps {
  rows: readonly Alert[]
  onSelect?: (alertId: string) => void
}

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
  }),
  columnHelper.accessor('ruleName', {
    header: 'Alert',
    cell: (info) => info.getValue(),
  }),
  columnHelper.accessor((row) => row.agentId ?? '—', {
    id: 'agent',
    header: 'Agent / fleet',
  }),
  columnHelper.accessor('status', {
    header: 'Status',
    cell: (info) => <StatusBadge status={info.getValue()} />,
  }),
  columnHelper.accessor('firstFiredAt', {
    header: 'First fired',
    cell: (info) => formatFirstFired(info.getValue()),
  }),
  columnHelper.accessor(
    (row) => Date.now() - Date.parse(row.firstFiredAt),
    {
      id: 'duration',
      header: 'Duration',
      cell: (info) => formatDuration(info.row.original.firstFiredAt, info.row.original.resolvedAt),
    },
  ),
  columnHelper.accessor((row) => row.destinationIds.join(', ') || '—', {
    id: 'destination',
    header: 'Destination',
  }),
]

export function AlertList({ rows, onSelect }: AlertListProps) {
  const table = useReactTable({
    data: rows as Alert[],
    columns,
    getCoreRowModel: getCoreRowModel(),
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
                style={{
                  textAlign: 'left',
                  padding: '0.5rem',
                  borderBottom: '2px solid #e5e7eb',
                  fontSize: '0.75rem',
                  textTransform: 'uppercase',
                  color: '#6b7280',
                  letterSpacing: '0.04em',
                }}
              >
                {flexRender(header.column.columnDef.header, header.getContext())}
              </th>
            ))}
          </tr>
        ))}
      </thead>
      <tbody>
        {table.getRowModel().rows.map((row) => (
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
        ))}
      </tbody>
    </table>
  )
}
