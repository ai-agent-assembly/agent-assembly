import { useState } from 'react'
import { SeverityBadge } from './SeverityBadge'
import { useAlertRulesQuery, useDeleteAlertRuleMutation } from './api'
import { useToast } from '../../components/Toast'
import { EmptyStateNoRules } from './EmptyStateNoRules'
import type { AlertRule } from './types'

interface AlertRulesTableProps {
  /** Open the rule form in create mode. */
  onCreate: () => void
  /** Open the rule form in edit mode for a specific rule. */
  onEdit: (rule: AlertRule) => void
  /** Open the destination manager (toolbar action surface). */
  onOpenDestinations: () => void
}

const cellStyle = {
  padding: '0.5rem 0.75rem',
  fontSize: '0.875rem',
  verticalAlign: 'middle' as const,
}

const headerStyle = {
  ...cellStyle,
  fontWeight: 600,
  textAlign: 'left' as const,
  color: 'var(--text-muted)',
  fontSize: '0.75rem',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.04em',
  borderBottom: '1px solid var(--surface-card-border)',
}

/**
 * Rules-tab table (AAASM-1393). Lists every alert rule with row-level
 * Edit + Delete actions and a toolbar offering "+ New rule" plus an
 * "Add destination" link that opens the existing DestinationManager.
 *
 * Wired into AlertsPage in the same Story; rules state is fetched via
 * `useAlertRulesQuery` (same hook AlertsPage already uses).
 */
export function AlertRulesTable({ onCreate, onEdit, onOpenDestinations }: AlertRulesTableProps) {
  const rulesQuery = useAlertRulesQuery()
  const deleteMutation = useDeleteAlertRuleMutation()
  const { toast } = useToast()
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null)

  const rules = rulesQuery.data ?? []
  const isLoading = rulesQuery.isLoading
  const isError = rulesQuery.isError

  function handleDelete(rule: AlertRule) {
    if (pendingDeleteId) return // ignore double-clicks while one delete is in flight
    setPendingDeleteId(rule.id)
    deleteMutation.mutate(rule.id, {
      onSuccess: () => {
        toast(`Deleted rule "${rule.name}"`, 'success')
        setPendingDeleteId(null)
      },
      onError: (err) => {
        toast(`Failed to delete rule: ${err.message}`, 'error')
        setPendingDeleteId(null)
      },
    })
  }

  return (
    <section data-testid="alert-rules-tab">
      <div
        data-testid="alert-rules-toolbar"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0.5rem 0',
          gap: '0.5rem',
        }}
      >
        <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.875rem' }}>
          {isLoading
            ? 'Loading rules…'
            : `${rules.length} alert rule${rules.length === 1 ? '' : 's'} configured`}
        </p>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            data-testid="alert-rules-open-destinations"
            onClick={onOpenDestinations}
            style={{ padding: '6px 12px', fontSize: '0.875rem' }}
          >
            Add destination
          </button>
          <button
            type="button"
            data-testid="alert-rules-create"
            onClick={onCreate}
            style={{
              padding: '6px 12px',
              background: 'var(--button-primary-bg)',
              color: 'var(--button-primary-text)',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '0.875rem',
            }}
          >
            + New rule
          </button>
        </div>
      </div>

      {isError && (
        <p data-testid="alert-rules-error" style={{ color: 'var(--status-danger-solid)' }}>
          Failed to load rules: {rulesQuery.error?.message ?? 'unknown error'}
        </p>
      )}

      {!isLoading && !isError && rules.length === 0 && (
        <EmptyStateNoRules onCreateRule={onCreate} />
      )}

      {rules.length > 0 && (
        <table data-testid="alert-rules-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={headerStyle}>Name</th>
              <th style={headerStyle}>Metric</th>
              <th style={headerStyle}>Condition</th>
              <th style={headerStyle}>Severity</th>
              <th style={headerStyle}>Status</th>
              <th style={{ ...headerStyle, textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr
                key={rule.id}
                data-testid="alert-rules-row"
                data-rule-id={rule.id}
                style={{ borderBottom: '1px solid var(--surface-hover-bg)' }}
              >
                <td style={cellStyle}>
                  <span style={{ fontWeight: 600 }}>{rule.name}</span>
                  {rule.description && (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                      {rule.description}
                    </div>
                  )}
                </td>
                <td style={{ ...cellStyle, fontFamily: 'ui-monospace, monospace', fontSize: '0.75rem' }}>
                  {rule.metric}
                </td>
                <td style={{ ...cellStyle, fontFamily: 'ui-monospace, monospace', fontSize: '0.75rem' }}>
                  {rule.operator} {rule.threshold}
                </td>
                <td style={cellStyle}>
                  <SeverityBadge severity={rule.severity} />
                </td>
                <td style={cellStyle}>
                  <span
                    data-testid="alert-rules-row-status"
                    style={{
                      fontSize: '0.75rem',
                      color: rule.enabled ? 'var(--status-success-text-strong)' : 'var(--text-muted)',
                    }}
                  >
                    {rule.enabled ? 'enabled' : 'disabled'}
                  </span>
                </td>
                <td style={{ ...cellStyle, textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <button
                    type="button"
                    data-testid="alert-rules-row-edit"
                    onClick={() => onEdit(rule)}
                    style={{ padding: '4px 10px', fontSize: '0.75rem', marginRight: '0.25rem' }}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    data-testid="alert-rules-row-delete"
                    onClick={() => handleDelete(rule)}
                    disabled={pendingDeleteId === rule.id}
                    style={{
                      padding: '4px 10px',
                      fontSize: '0.75rem',
                      color: 'var(--status-danger-text-strong)',
                    }}
                  >
                    {pendingDeleteId === rule.id ? 'Deleting…' : 'Delete'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
