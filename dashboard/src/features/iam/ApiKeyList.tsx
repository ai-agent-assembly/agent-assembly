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

export function ApiKeyList() {
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
            <th>Label</th>
            <th>Prefix</th>
            <th>Scopes</th>
            <th>Created</th>
            <th>Last used</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {isLoading && (
            <tr data-testid="api-key-list-loading">
              <td colSpan={7} className="iam-api-key-list__loading">Loading…</td>
            </tr>
          )}
          {!isLoading && data?.length === 0 && (
            <tr data-testid="api-key-list-empty">
              <td colSpan={7} className="iam-api-key-list__empty">No API keys issued yet.</td>
            </tr>
          )}
          {data?.map((k) => {
            const revoked = k.status === 'revoked'
            return (
              <tr key={k.id} data-testid={`api-key-row-${k.id}`} className={revoked ? 'iam-api-key-list__row--revoked' : ''}>
                <td className="iam-api-key-list__label">{k.label}</td>
                <td className="iam-api-key-list__mono">{maskedPrefix(k.prefix)}</td>
                <td>
                  <div className="iam-api-key-list__scopes">
                    {k.scopes.map((s) => (
                      <span key={s} className="iam-scope-chip">{s}</span>
                    ))}
                  </div>
                </td>
                <td className="iam-api-key-list__mono">{formatDate(k.created_at)}</td>
                <td className="iam-api-key-list__mono">{formatDate(k.last_used)}</td>
                <td>
                  <span className={`iam-status iam-status--${k.status === 'active' ? 'active' : 'suspended'}`}>{k.status}</span>
                </td>
                <td>
                  {!revoked && (
                    <button
                      type="button"
                      className="iam-api-key-list__revoke-btn"
                      data-testid={`api-key-revoke-${k.id}`}
                      onClick={() => setPendingRevoke(k)}
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
