import { useState } from 'react'
import { useApiKeysQuery, useRevokeApiKeyMutation } from './apiKeys'
import { useToast } from '../../components/Toast'
import type { ApiKey } from './types'
import './ApiKeyList.css'

function maskedPrefix(prefix: string): string {
  return `${prefix}•••••`
}

function formatDate(value: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toISOString().slice(0, 16).replace('T', ' ')
}

function ConfirmRevoke({ keyRecord, onCancel, onConfirm }: {
  keyRecord: ApiKey
  onCancel: () => void
  onConfirm: () => void
}) {
  return (
    <div className="iam-dialog__backdrop" role="dialog" aria-modal="true" data-testid="confirm-revoke-key">
      <div className="iam-dialog">
        <h2 className="iam-dialog__title">Revoke API key?</h2>
        <p style={{ fontSize: '0.9rem', margin: 0 }}>
          Revoking <strong>{keyRecord.label}</strong> ({keyRecord.prefix}…) immediately invalidates it. Existing callers will start receiving 401.
        </p>
        <div className="iam-dialog__actions">
          <button type="button" className="iam-dialog__btn" onClick={onCancel} data-testid="confirm-revoke-cancel">
            Cancel
          </button>
          <button
            type="button"
            className="iam-dialog__btn iam-dialog__btn--danger"
            onClick={onConfirm}
            data-testid="confirm-revoke-confirm"
          >
            Revoke
          </button>
        </div>
      </div>
    </div>
  )
}

export interface ApiKeyListProps {
  /** Currently-selected api-key id, drives the row highlight (AAASM-1396). */
  selectedKeyId?: string | null
  /** Row click handler; receives the full ApiKey record so the consumer
   *  can render IdentityDetailCard without re-querying. Omit to disable
   *  row selection (preserves the previous click-through-nothing behaviour). */
  onSelect?: (key: ApiKey) => void
}

export function ApiKeyList({ selectedKeyId = null, onSelect }: ApiKeyListProps = {}) {
  const { data, isLoading, isError, refetch } = useApiKeysQuery()
  const revoke = useRevokeApiKeyMutation()
  const { toast } = useToast()
  const [pendingRevoke, setPendingRevoke] = useState<ApiKey | null>(null)

  if (isError) {
    return (
      <div className="iam-api-key-list__error" data-testid="api-key-list-error">
        <span>Failed to load API keys.</span>
        <button type="button" onClick={() => void refetch()}>Retry</button>
      </div>
    )
  }

  function handleConfirmRevoke() {
    if (!pendingRevoke) return
    const target = pendingRevoke
    setPendingRevoke(null)
    revoke.mutate(target.id, {
      onSuccess: () => toast(`Revoked ${target.label}`, 'success'),
      onError: (err) => toast(err instanceof Error ? err.message : 'Revoke failed', 'error'),
    })
  }

  return (
    <>
      <table className="iam-api-key-list" data-testid="api-key-list">
        <thead>
          <tr>
            <th data-testid="api-key-col-id">ID</th>
            <th data-testid="api-key-col-name">Name</th>
            <th data-testid="api-key-col-owner">Owner</th>
            <th data-testid="api-key-col-role">Role</th>
            <th data-testid="api-key-col-status">Status</th>
            <th data-testid="api-key-col-last-seen">Last seen</th>
            <th data-testid="api-key-col-policy-count">Policy count</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {isLoading && (
            <tr data-testid="api-key-list-loading">
              <td colSpan={8} className="iam-api-key-list__loading">Loading…</td>
            </tr>
          )}
          {!isLoading && data?.length === 0 && (
            <tr data-testid="api-key-list-empty">
              <td colSpan={8} className="iam-api-key-list__empty">No API keys issued yet.</td>
            </tr>
          )}
          {data?.map((k) => {
            const revoked = k.status === 'revoked'
            const selected = selectedKeyId === k.id
            const classes = [
              revoked ? 'iam-api-key-list__row--revoked' : '',
              selected ? 'iam-api-key-list__row--selected' : '',
              onSelect ? 'iam-api-key-list__row--clickable' : '',
            ]
              .filter(Boolean)
              .join(' ')
            // AAASM-1399 reshaped the columns to the Story-level vocabulary
            // (AAASM-119 AC #4): ID · name · owner · role · status · last seen ·
            // policy count. Scope / created details still live on the row record
            // and are surfaced by IdentityDetailCard (AAASM-1396) when a row is
            // selected — keeps the table itself scannable.
            const policyCount = k.assigned_policies.length
            return (
              <tr
                key={k.id}
                data-testid={`api-key-row-${k.id}`}
                data-selected={selected ? 'true' : undefined}
                className={classes}
                onClick={onSelect ? () => onSelect(k) : undefined}
                aria-selected={onSelect ? selected : undefined}
              >
                <td
                  className="iam-api-key-list__mono"
                  data-testid={`api-key-cell-id-${k.id}`}
                >
                  {maskedPrefix(k.prefix)}
                </td>
                <td
                  className="iam-api-key-list__label"
                  data-testid={`api-key-cell-name-${k.id}`}
                >
                  {k.label}
                </td>
                <td data-testid={`api-key-cell-owner-${k.id}`}>{k.owner}</td>
                <td
                  className="iam-api-key-list__mono"
                  data-testid={`api-key-cell-role-${k.id}`}
                >
                  {k.role}
                </td>
                <td data-testid={`api-key-cell-status-${k.id}`}>
                  <span
                    className={`iam-status iam-status--${k.status === 'active' ? 'active' : 'suspended'}`}
                  >
                    {k.status}
                  </span>
                </td>
                <td
                  className="iam-api-key-list__mono"
                  data-testid={`api-key-cell-last-seen-${k.id}`}
                >
                  {formatDate(k.last_used)}
                </td>
                <td
                  className="iam-api-key-list__mono"
                  data-testid={`api-key-cell-policy-count-${k.id}`}
                >
                  {policyCount}
                </td>
                <td>
                  {!revoked && (
                    <button
                      type="button"
                      className="iam-api-key-list__revoke-btn"
                      data-testid={`api-key-revoke-${k.id}`}
                      onClick={(e) => {
                        // Don't bubble to the row's onClick selection handler.
                        e.stopPropagation()
                        setPendingRevoke(k)
                      }}
                      disabled={revoke.isPending}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {pendingRevoke && (
        <ConfirmRevoke
          keyRecord={pendingRevoke}
          onCancel={() => setPendingRevoke(null)}
          onConfirm={handleConfirmRevoke}
        />
      )}
    </>
  )
}
