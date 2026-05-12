import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApprovalRoutingBadge } from '../components/ApprovalRoutingBadge'
import { useToast } from '../components/Toast'
import {
  useApprovalsQuery,
  useApproveAction,
  useRejectAction,
  type Approval,
} from '../features/approvals/api'
import { useApprovalsStream } from '../features/approvals/useApprovalsStream'
import './ApprovalsPage.css'

// ── Reject dialog ─────────────────────────────────────────────────────────────

interface RejectDialogProps {
  count: number
  onConfirm: (reason: string) => void
  onCancel: () => void
}

function RejectDialog({ count, onConfirm, onCancel }: RejectDialogProps) {
  const [reason, setReason] = useState('')
  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
      }}
      data-testid="reject-dialog"
    >
      <div style={{
        background: '#fff', borderRadius: '0.5rem', padding: '1.5rem',
        width: '24rem', display: 'flex', flexDirection: 'column', gap: '1rem',
      }}>
        <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>
          Reject {count > 1 ? `${count} requests` : 'request'}
        </h2>
        <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.875rem' }}>
          Reason (required)
          <textarea
            data-testid="reject-reason-input"
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            style={{ padding: '0.5rem', borderRadius: '0.25rem', border: '1px solid #d1d5db', resize: 'vertical' }}
          />
        </label>
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          <button
            onClick={onCancel}
            style={{ padding: '0.4rem 0.75rem', borderRadius: '0.25rem', border: '1px solid #d1d5db', cursor: 'pointer' }}
          >
            Cancel
          </button>
          <button
            data-testid="reject-confirm-btn"
            disabled={!reason.trim()}
            onClick={() => onConfirm(reason.trim())}
            style={{
              padding: '0.4rem 0.75rem', borderRadius: '0.25rem', border: 'none',
              background: !reason.trim() ? '#9ca3af' : '#dc2626',
              color: '#fff', cursor: !reason.trim() ? 'not-allowed' : 'pointer',
              fontWeight: 600,
            }}
          >
            Confirm reject
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Tab bar ───────────────────────────────────────────────────────────────────

function TabBar({
  active,
  pendingCount,
  decidedCount,
  onChange,
}: {
  active: 'pending' | 'decided'
  pendingCount: number
  decidedCount: number
  onChange: (t: 'pending' | 'decided') => void
}) {
  function tabStyle(t: 'pending' | 'decided') {
    return {
      padding: '0.5rem 1rem',
      borderBottom: `2px solid ${active === t ? '#2563eb' : 'transparent'}`,
      fontWeight: active === t ? 600 : 400,
      color: active === t ? '#2563eb' : '#6b7280',
      cursor: 'pointer',
      background: 'none',
      border: 'none',
      borderBottom: `2px solid ${active === t ? '#2563eb' : 'transparent'}`,
      fontSize: '0.875rem',
    } as React.CSSProperties
  }

  return (
    <div style={{ display: 'flex', borderBottom: '1px solid #e5e7eb', marginBottom: '1rem' }} data-testid="tab-bar">
      <button style={tabStyle('pending')} onClick={() => onChange('pending')} data-testid="tab-pending">
        Pending ({pendingCount})
      </button>
      <button style={tabStyle('decided')} onClick={() => onChange('decided')} data-testid="tab-decided">
        Decided ({decidedCount})
      </button>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export function ApprovalsPage() {
  const queryClient = useQueryClient()
  const { data: approvals, isLoading, isError, refetch } = useApprovalsQuery()
  const { connected } = useApprovalsStream()
  const approveMutation = useApproveAction()
  const rejectMutation = useRejectAction()
  const { toast, ToastContainer } = useToast()

  const [tab, setTab] = useState<'pending' | 'decided'>('pending')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [decidedHistory, setDecidedHistory] = useState<Approval[]>([])
  const [rejectFor, setRejectFor] = useState<string[] | null>(null)

  const pending = approvals ?? []
  const allSelected = pending.length > 0 && pending.every((a) => selected.has(a.id))

  function toggleRow(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(pending.map((a) => a.id)))
  }

  async function handleApprove(ids: string[]) {
    const snapshot = queryClient.getQueryData<Approval[]>(['approvals']) ?? []
    const targets = snapshot.filter((a) => ids.includes(a.id))
    // Optimistic remove
    queryClient.setQueryData<Approval[]>(['approvals'], (prev) => prev?.filter((a) => !ids.includes(a.id)) ?? [])

    const results = await Promise.allSettled(ids.map((id) => approveMutation.mutateAsync({ id })))
    const failedIds = ids.filter((_, i) => results[i].status === 'rejected')
    const succeededIds = ids.filter((_, i) => results[i].status === 'fulfilled')

    if (failedIds.length > 0) {
      // Restore failed rows
      const failedRows = targets.filter((a) => failedIds.includes(a.id))
      queryClient.setQueryData<Approval[]>(['approvals'], (prev) => [...failedRows, ...(prev ?? [])])
      toast(`Approved ${succeededIds.length}, failed ${failedIds.length}.`, 'error')
    } else {
      toast(`Approved ${succeededIds.length} request${succeededIds.length !== 1 ? 's' : ''}.`, 'success')
    }

    const succeededRows = targets.filter((a) => succeededIds.includes(a.id))
    setDecidedHistory((prev) => [...succeededRows.map((a) => ({ ...a, status: 'approved' })), ...prev])
    setSelected(new Set())
  }

  async function handleReject(ids: string[], reason: string) {
    setRejectFor(null)
    const snapshot = queryClient.getQueryData<Approval[]>(['approvals']) ?? []
    const targets = snapshot.filter((a) => ids.includes(a.id))
    // Optimistic remove
    queryClient.setQueryData<Approval[]>(['approvals'], (prev) => prev?.filter((a) => !ids.includes(a.id)) ?? [])

    const results = await Promise.allSettled(ids.map((id) => rejectMutation.mutateAsync({ id, reason })))
    const failedIds = ids.filter((_, i) => results[i].status === 'rejected')
    const succeededIds = ids.filter((_, i) => results[i].status === 'fulfilled')

    if (failedIds.length > 0) {
      const failedRows = targets.filter((a) => failedIds.includes(a.id))
      queryClient.setQueryData<Approval[]>(['approvals'], (prev) => [...failedRows, ...(prev ?? [])])
      toast(`Rejected ${succeededIds.length}, failed ${failedIds.length}.`, 'error')
    } else {
      toast(`Rejected ${succeededIds.length} request${succeededIds.length !== 1 ? 's' : ''}.`, 'success')
    }

    const succeededRows = targets.filter((a) => succeededIds.includes(a.id))
    setDecidedHistory((prev) => [...succeededRows.map((a) => ({ ...a, status: 'rejected' })), ...prev])
    setSelected(new Set())
  }

  return (
    <main className="approvals-page" data-testid="approvals-page">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <h1 style={{ margin: 0 }}>Approvals</h1>
        {!connected && (
          <div
            data-testid="ws-disconnected-banner"
            style={{
              fontSize: '0.75rem', padding: '0.25rem 0.75rem',
              background: '#fef9c3', border: '1px solid #fde047',
              borderRadius: '9999px', color: '#854d0e',
            }}
          >
            Live updates disconnected — reconnecting…
          </div>
        )}
      </div>

      <TabBar
        active={tab}
        pendingCount={pending.length}
        decidedCount={decidedHistory.length}
        onChange={setTab}
      />

      {tab === 'pending' && (
        <>
          {/* Bulk toolbar */}
          {selected.size > 0 && (
            <div
              data-testid="bulk-toolbar"
              style={{
                display: 'flex', gap: '0.5rem', alignItems: 'center',
                padding: '0.5rem 0.75rem', background: '#eff6ff',
                borderRadius: '0.375rem', marginBottom: '0.75rem', fontSize: '0.875rem',
              }}
            >
              <span style={{ color: '#1d4ed8', fontWeight: 500 }}>{selected.size} selected</span>
              <button
                data-testid="bulk-approve-btn"
                onClick={() => void handleApprove(Array.from(selected))}
                style={{
                  padding: '0.25rem 0.75rem', borderRadius: '0.25rem',
                  background: '#16a34a', color: '#fff', border: 'none', cursor: 'pointer', fontWeight: 600,
                }}
              >
                Approve selected
              </button>
              <button
                data-testid="bulk-reject-btn"
                onClick={() => setRejectFor(Array.from(selected))}
                style={{
                  padding: '0.25rem 0.75rem', borderRadius: '0.25rem',
                  background: '#dc2626', color: '#fff', border: 'none', cursor: 'pointer', fontWeight: 600,
                }}
              >
                Reject selected
              </button>
            </div>
          )}

          {isError && (
            <div
              data-testid="approvals-error"
              style={{ color: '#dc2626', marginBottom: '0.75rem', display: 'flex', gap: '0.75rem', alignItems: 'center', fontSize: '0.875rem' }}
            >
              <span>Failed to load approvals.</span>
              <button onClick={() => void refetch()}>Retry</button>
            </div>
          )}

          {!isLoading && !isError && pending.length === 0 && (
            <p data-testid="approvals-empty" className="approvals-state">No pending approval requests.</p>
          )}

          {(isLoading || pending.length > 0) && (
            <table className="approvals-table" data-testid="approvals-table">
              <thead>
                <tr>
                  <th style={{ width: '2rem' }}>
                    <input
                      type="checkbox"
                      data-testid="select-all-checkbox"
                      checked={allSelected}
                      onChange={toggleAll}
                      aria-label="Select all"
                    />
                  </th>
                  <th>Agent</th>
                  <th>Action</th>
                  <th>Reason</th>
                  <th>Routing</th>
                  <th>Requested at</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading
                  ? Array.from({ length: 3 }).map((_, i) => (
                    <tr key={i} data-testid="approval-row-skeleton">
                      {Array.from({ length: 7 }).map((_, j) => (
                        <td key={j} style={{ padding: '8px 12px' }}>
                          <span style={{ display: 'block', height: '0.875rem', background: '#e5e7eb', borderRadius: '4px' }} />
                        </td>
                      ))}
                    </tr>
                  ))
                  : pending.map((row) => (
                    <tr key={row.id} data-testid="approval-row" style={{ borderBottom: '1px solid #f3f4f6' }}>
                      <td style={{ padding: '8px 12px' }}>
                        <input
                          type="checkbox"
                          data-testid="row-checkbox"
                          checked={selected.has(row.id)}
                          onChange={() => toggleRow(row.id)}
                          aria-label={`Select approval ${row.id}`}
                        />
                      </td>
                      <td className="approvals-table__id">{row.agent_id}</td>
                      <td>{row.action}</td>
                      <td>{row.reason}</td>
                      <td>
                        {row.routing_status
                          ? <ApprovalRoutingBadge routingStatus={row.routing_status} />
                          : <span className="approvals-table__unrouted">—</span>}
                      </td>
                      <td>{row.created_at}</td>
                      <td style={{ display: 'flex', gap: '0.375rem' }}>
                        <button
                          data-testid="approve-btn"
                          onClick={() => void handleApprove([row.id])}
                          style={{
                            padding: '0.2rem 0.6rem', borderRadius: '0.25rem',
                            background: '#16a34a', color: '#fff', border: 'none', cursor: 'pointer', fontSize: '0.75rem',
                          }}
                        >
                          Approve
                        </button>
                        <button
                          data-testid="reject-btn"
                          onClick={() => setRejectFor([row.id])}
                          style={{
                            padding: '0.2rem 0.6rem', borderRadius: '0.25rem',
                            background: '#dc2626', color: '#fff', border: 'none', cursor: 'pointer', fontSize: '0.75rem',
                          }}
                        >
                          Reject
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {tab === 'decided' && (
        <>
          {decidedHistory.length === 0 ? (
            <p data-testid="decided-empty" className="approvals-state">
              No decisions in this session.{' '}
              <span style={{ color: '#9ca3af', fontSize: '0.8rem' }}>
                (Historical decided approvals are not available via the current API.)
              </span>
            </p>
          ) : (
            <table className="approvals-table" data-testid="decided-table">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Action</th>
                  <th>Reason</th>
                  <th>Decision</th>
                  <th>Requested at</th>
                </tr>
              </thead>
              <tbody>
                {decidedHistory.map((row) => (
                  <tr key={row.id} data-testid="decided-row">
                    <td className="approvals-table__id">{row.agent_id}</td>
                    <td>{row.action}</td>
                    <td>{row.reason}</td>
                    <td>
                      <span
                        style={{
                          display: 'inline-block', padding: '2px 8px', borderRadius: '9999px',
                          fontSize: '0.75rem', fontWeight: 600, color: '#fff',
                          background: row.status === 'approved' ? '#16a34a' : '#dc2626',
                        }}
                      >
                        {row.status}
                      </span>
                    </td>
                    <td>{row.created_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {rejectFor && (
        <RejectDialog
          count={rejectFor.length}
          onConfirm={(reason) => void handleReject(rejectFor, reason)}
          onCancel={() => setRejectFor(null)}
        />
      )}

      <ToastContainer />
    </main>
  )
}
