import { useEffect, useState } from 'react'
import type { components } from '../api/generated/schema'
import { ApprovalRoutingBadge } from '../components/ApprovalRoutingBadge'
import './ApprovalsPage.css'

type ApprovalRow = components['schemas']['ApprovalResponse']

export function ApprovalsPage() {
  const [approvals, setApprovals] = useState<ApprovalRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/v1/approvals')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ items: ApprovalRow[] }>
      })
      .then(data => setApprovals(data.items))
      .catch(err => setError(String(err)))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <p className="approvals-state">Loading…</p>
  if (error) return <p className="approvals-state approvals-state--error">{error}</p>

  return (
    <main className="approvals-page">
      <h1>Pending Approvals</h1>
      {approvals.length === 0 ? (
        <p className="approvals-state">No pending approvals.</p>
      ) : (
        <table className="approvals-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Agent</th>
              <th>Action</th>
              <th>Reason</th>
              <th>Routing</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {approvals.map(row => (
              <tr key={row.id}>
                <td className="approvals-table__id">{row.id}</td>
                <td>{row.agent_id}</td>
                <td>{row.action}</td>
                <td>{row.reason}</td>
                <td>
                  {row.routing_status ? (
                    <ApprovalRoutingBadge routingStatus={row.routing_status} />
                  ) : (
                    <span className="approvals-table__unrouted">—</span>
                  )}
                </td>
                <td>{row.created_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  )
}
