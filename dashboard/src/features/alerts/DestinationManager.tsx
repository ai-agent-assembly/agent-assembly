import { useState } from 'react'
import {
  useCreateDestinationMutation,
  useDeleteDestinationMutation,
  useDestinationsQuery,
  useTestDestinationMutation,
  useUpdateDestinationMutation,
} from './api'
import { useToast } from '../../components/Toast'
import type { Destination, DestinationInput, DestinationKind } from './types'

interface DestinationManagerProps {
  open: boolean
  onClose: () => void
}

const KIND_OPTIONS: readonly DestinationKind[] = ['webhook', 'slack', 'pagerduty', 'opsgenie']

interface DraftForm {
  /** Set when editing an existing row; null when creating. */
  editingId: string | null
  kind: DestinationKind
  name: string
  /** Raw JSON for the connector-specific config. Validated on submit. */
  configJson: string
}

const EMPTY_DRAFT: DraftForm = {
  editingId: null,
  kind: 'webhook',
  name: '',
  configJson: '{\n  "url": "https://hooks.internal/aaasm"\n}',
}

function draftFromDestination(d: Destination): DraftForm {
  return {
    editingId: d.id,
    kind: d.kind,
    name: d.name,
    configJson: JSON.stringify(d.config, null, 2),
  }
}

export function DestinationManager({ open, onClose }: DestinationManagerProps) {
  const { data, isLoading, isError, error } = useDestinationsQuery()
  const createMut = useCreateDestinationMutation()
  const updateMut = useUpdateDestinationMutation()
  const deleteMut = useDeleteDestinationMutation()
  const testMut = useTestDestinationMutation()
  const { toast } = useToast()

  const [draft, setDraft] = useState<DraftForm>(EMPTY_DRAFT)

  if (!open) return null

  const destinations = data ?? []

  const submit = async () => {
    let parsedConfig: unknown
    try {
      parsedConfig = JSON.parse(draft.configJson)
    } catch {
      toast('Config is not valid JSON', 'error')
      return
    }
    const input = {
      kind: draft.kind,
      name: draft.name.trim(),
      enabled: true,
      config: parsedConfig,
    } as DestinationInput
    if (!input.name) {
      toast('Name is required', 'error')
      return
    }
    try {
      if (draft.editingId) {
        await updateMut.mutateAsync({ id: draft.editingId, input })
        toast(`Updated destination "${input.name}"`, 'success')
      } else {
        await createMut.mutateAsync(input)
        toast(`Created destination "${input.name}"`, 'success')
      }
      setDraft(EMPTY_DRAFT)
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to save destination', 'error')
    }
  }

  const remove = async (d: Destination) => {
    try {
      await deleteMut.mutateAsync(d.id)
      toast(`Deleted destination "${d.name}"`, 'success')
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to delete destination', 'error')
    }
  }

  const testFire = async (d: Destination) => {
    try {
      const result = await testMut.mutateAsync({ id: d.id, severity: 'LOW' })
      toast(
        `Test fired → ${result.connectorResponseStatus} (${d.name})`,
        result.connectorResponseStatus < 300 ? 'success' : 'error',
      )
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Test fire failed', 'error')
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="destination-manager-title"
      data-testid="destination-manager"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.4)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        padding: '2rem',
        zIndex: 1000,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        style={{
          width: 'min(720px, 100%)',
          maxHeight: '90vh',
          overflow: 'auto',
          background: 'var(--surface-card)',
          borderRadius: '8px',
          boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2)',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
        }}
      >
        <header
          style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
        >
          <h2 id="destination-manager-title" style={{ margin: 0, fontSize: '1.125rem' }}>
            Destination registry
          </h2>
          <button
            type="button"
            data-testid="destination-manager-close"
            aria-label="Close"
            onClick={onClose}
            style={{
              border: 'none',
              background: 'transparent',
              fontSize: '1.25rem',
              cursor: 'pointer',
              color: 'var(--text-muted)',
            }}
          >
            ✕
          </button>
        </header>

        {isLoading && (
          <p data-testid="destination-manager-loading" style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            Loading destinations…
          </p>
        )}
        {isError && (
          <p data-testid="destination-manager-error" style={{ color: 'var(--status-danger-solid)', fontSize: '0.875rem' }}>
            Failed to load destinations: {error?.message ?? 'unknown error'}
          </p>
        )}

        {!isLoading && !isError && destinations.length === 0 && (
          <p data-testid="destination-manager-empty" style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            No destinations configured yet.
          </p>
        )}

        {destinations.length > 0 && (
          <table
            data-testid="destination-manager-table"
            style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}
          >
            <thead>
              <tr>
                <th style={{ textAlign: 'left', padding: '0.25rem', borderBottom: '1px solid var(--surface-card-border)' }}>
                  Kind
                </th>
                <th style={{ textAlign: 'left', padding: '0.25rem', borderBottom: '1px solid var(--surface-card-border)' }}>
                  Name
                </th>
                <th style={{ textAlign: 'right', padding: '0.25rem', borderBottom: '1px solid var(--surface-card-border)' }}>
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {destinations.map((d) => (
                <tr key={d.id} data-testid={`destination-row-${d.id}`}>
                  <td style={{ padding: '0.35rem 0.25rem', fontWeight: 600, textTransform: 'uppercase' }}>
                    {d.kind}
                  </td>
                  <td style={{ padding: '0.35rem 0.25rem' }}>{d.name}</td>
                  <td style={{ padding: '0.35rem 0.25rem', textAlign: 'right', display: 'flex', gap: '0.25rem', justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      data-testid={`destination-test-${d.id}`}
                      onClick={() => void testFire(d)}
                      disabled={testMut.isPending}
                      style={{ padding: '2px 8px', fontSize: '0.75rem' }}
                    >
                      Test fire
                    </button>
                    <button
                      type="button"
                      data-testid={`destination-edit-${d.id}`}
                      onClick={() => setDraft(draftFromDestination(d))}
                      style={{ padding: '2px 8px', fontSize: '0.75rem' }}
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      data-testid={`destination-delete-${d.id}`}
                      onClick={() => void remove(d)}
                      disabled={deleteMut.isPending}
                      style={{ padding: '2px 8px', fontSize: '0.75rem', color: 'var(--status-danger-text-strong)' }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <section
          data-testid="destination-manager-form"
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '0.5rem',
            border: '1px solid var(--surface-card-border)',
            borderRadius: '6px',
            padding: '0.75rem',
          }}
        >
          <h3 style={{ margin: 0, fontSize: '0.875rem' }}>
            {draft.editingId ? 'Edit destination' : 'New destination'}
          </h3>

          <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.75rem' }}>
            <span>Kind</span>
            <select
              data-testid="destination-form-kind"
              value={draft.kind}
              onChange={(e) =>
                setDraft({ ...draft, kind: e.target.value as DestinationKind })
              }
            >
              {KIND_OPTIONS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
          </label>

          <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.75rem' }}>
            <span>Name</span>
            <input
              data-testid="destination-form-name"
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
          </label>

          <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.75rem' }}>
            <span>Config (JSON)</span>
            <textarea
              data-testid="destination-form-config"
              rows={5}
              value={draft.configJson}
              onChange={(e) => setDraft({ ...draft, configJson: e.target.value })}
              style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
            />
          </label>

          <div style={{ display: 'flex', gap: '0.25rem', justifyContent: 'flex-end' }}>
            {draft.editingId && (
              <button
                type="button"
                data-testid="destination-form-cancel-edit"
                onClick={() => setDraft(EMPTY_DRAFT)}
                style={{ padding: '4px 12px', fontSize: '0.75rem' }}
              >
                Cancel edit
              </button>
            )}
            <button
              type="button"
              data-testid="destination-form-submit"
              onClick={() => void submit()}
              disabled={createMut.isPending || updateMut.isPending}
              style={{
                padding: '4px 12px',
                background: 'var(--button-primary-bg)',
                color: 'var(--text-on-accent)',
                border: 'none',
                borderRadius: '4px',
                fontSize: '0.75rem',
                cursor: 'pointer',
              }}
            >
              {draft.editingId ? 'Save changes' : 'Add destination'}
            </button>
          </div>
        </section>
      </div>
    </div>
  )
}
