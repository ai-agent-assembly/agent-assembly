import type { PerAgentRow } from '../../features/costs/perAgentRows'
import './PerAgentTable.css'

interface PerAgentTableProps {
  readonly rows: readonly PerAgentRow[]
}

function usd(value: number | null): string {
  return value == null ? '—' : `$${value.toFixed(2)}`
}

/** Share-of-top-spender band → colour bucket (relative ranking, not budget burn). */
function shareBucket(pct: number): 'hot' | 'warm' | 'cool' {
  if (pct >= 80) return 'hot'
  if (pct >= 50) return 'warm'
  return 'cool'
}

/**
 * Per-agent cost table for the Costs page Per-agent tab
 * (design/v1/hi-fi/costs.jsx). Columns: agent, team, daily spend (with a bar
 * showing its share of the top spender), monthly spend. The mock's 7-day trend
 * sparkline column is intentionally dropped — no per-agent history endpoint
 * exists to back it (AAASM-5076), so it is omitted rather than fabricated.
 */
export function PerAgentTable({ rows }: PerAgentTableProps) {
  if (rows.length === 0) {
    return (
      <p className="costs-agent-table__empty" data-testid="costs-agent-empty">
        No per-agent spend recorded yet.
      </p>
    )
  }

  return (
    <div className="costs-agent-table__scroll">
      <table className="costs-agent-table" data-testid="costs-agent-table">
        <thead>
          <tr>
            <th>Agent</th>
            <th>Team</th>
            <th>Daily spend</th>
            <th>Monthly spend</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(row => {
            const bucket = shareBucket(row.sharePct)
            return (
              <tr key={row.agentId} data-testid="costs-agent-row" data-agent={row.agentId}>
                <td className="costs-agent-table__id">{row.agentId}</td>
                <td>
                  <span className="costs-agent-table__team">{row.team ?? '—'}</span>
                </td>
                <td>
                  <div className="costs-agent-table__daily">
                    <span
                      className="costs-agent-table__amount"
                      data-share-bucket={bucket}
                    >
                      {usd(row.daily)}
                    </span>
                    <span className="costs-agent-table__share" aria-hidden="true">
                      <span
                        className="costs-agent-table__share-fill"
                        data-share-bucket={bucket}
                        style={{ width: `${Math.min(100, row.sharePct)}%` }}
                      />
                    </span>
                  </div>
                </td>
                <td className="costs-agent-table__monthly">{usd(row.monthly)}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
