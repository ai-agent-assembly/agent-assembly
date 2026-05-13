import { useMemo, useState } from 'react'
import { usePoliciesQuery, type Policy } from '../features/policies/api'
import { EmptyState, ErrorState } from '../components/states'
import { OverlayHost } from '../components/OverlayHost'
import { useOverlay } from '../components/useOverlay'
import './PoliciesPage.css'

type FilterTab = 'all' | 'active' | 'proposed'

const FILTER_TABS: ReadonlyArray<{ id: FilterTab; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'active', label: 'Active' },
  { id: 'proposed', label: 'Proposed' },
]

interface PolicyEditorOverlayProps {
  mode: 'new' | 'edit'
  name?: string
  version?: string
}

function PolicyEditorPlaceholder() {
  const { props, closeOverlay } = useOverlay('policy-editor')
  const overlayProps = props as PolicyEditorOverlayProps
  return (
    <div className="policy-editor-placeholder" data-testid="policy-editor-placeholder">
      <h2 className="policy-editor-placeholder__title">
        {overlayProps.mode === 'edit'
          ? `Edit ${overlayProps.name ?? ''} v${overlayProps.version ?? ''}`
          : 'New policy'}
      </h2>
      <p className="policy-editor-placeholder__desc">
        Structured condition-builder form lands in AAASM-1370 (ST-4).
        For now, this confirms the overlay open/close lifecycle works
        end-to-end.
      </p>
      <button
        type="button"
        className="policy-editor-placeholder__close"
        data-testid="policy-editor-close"
        onClick={closeOverlay}
      >
        Close
      </button>
    </div>
  )
}

function PolicySkeletonRow() {
  return (
    <li>
      <div className="policies-list__skeleton" data-testid="policy-row-skeleton">
        <span className="policies-list__skeleton-bar" style={{ width: '40%' }} />
        <span className="policies-list__skeleton-bar" style={{ width: '8rem' }} />
        <span className="policies-list__skeleton-bar" style={{ width: '5rem' }} />
      </div>
    </li>
  )
}

function PolicyRow({ policy, onEdit }: { policy: Policy; onEdit: () => void }) {
  const proposed = !policy.active
  return (
    <li>
      <button
        type="button"
        className="policies-list__row"
        data-testid="policy-row"
        onClick={onEdit}
      >
        <span className="policies-list__row-name">
          {policy.name}
          {proposed ? (
            <span className="policies-list__chip-draft">draft</span>
          ) : null}
        </span>
        <span className="policies-list__row-meta">
          v{policy.version} · {policy.rule_count} {policy.rule_count === 1 ? 'rule' : 'rules'}
        </span>
        <span
          className={
            policy.active
              ? 'policies-list__status policies-list__status--active'
              : 'policies-list__status policies-list__status--proposed'
          }
          data-testid="policy-row-status"
        >
          {policy.active ? 'active' : 'proposed'}
        </span>
      </button>
    </li>
  )
}

export function PoliciesPage() {
  const { data: policies, isLoading, isError, refetch } = usePoliciesQuery()
  const [filter, setFilter] = useState<FilterTab>('all')
  const { openOverlay } = useOverlay('policy-editor')

  const all = policies ?? []
  const activePolicies = useMemo(() => all.filter((p) => p.active), [all])
  const proposedPolicies = useMemo(() => all.filter((p) => !p.active), [all])

  const filtered =
    filter === 'active' ? activePolicies : filter === 'proposed' ? proposedPolicies : all

  const counts: Record<FilterTab, number> = {
    all: all.length,
    active: activePolicies.length,
    proposed: proposedPolicies.length,
  }

  const handleNew = () => openOverlay({ mode: 'new' })
  const handleEdit = (policy: Policy) =>
    openOverlay({ mode: 'edit', name: policy.name, version: policy.version })

  return (
    <main className="policies-page" data-testid="policies-page">
      <header className="policies-page__head">
        <div className="policies-page__heading">
          <h1 className="policies-page__title">Policies</h1>
          <p className="policies-page__subtitle">
            Visual builder for narrowing rules — open one to edit.
          </p>
        </div>
        <button
          type="button"
          className="policies-page__new-btn"
          data-testid="new-policy-btn"
          onClick={handleNew}
        >
          + new policy
        </button>
      </header>

      <nav className="policies-tabs" role="tablist" aria-label="Filter policies">
        {FILTER_TABS.map((tab) => {
          const active = filter === tab.id
          return (
            <button
              type="button"
              key={tab.id}
              role="tab"
              aria-selected={active}
              data-testid={`policies-tab-${tab.id}`}
              className={
                active
                  ? 'policies-tabs__tab policies-tabs__tab--active'
                  : 'policies-tabs__tab'
              }
              onClick={() => setFilter(tab.id)}
            >
              {tab.label}
              <span
                className={
                  tab.id === 'proposed' && counts.proposed > 0
                    ? 'policies-tabs__count policies-tabs__count--warn'
                    : 'policies-tabs__count'
                }
              >
                {counts[tab.id]}
              </span>
            </button>
          )
        })}
      </nav>

      {isError ? (
        <ErrorState
          title="Failed to load policies"
          description="The gateway returned an unexpected error."
          onRetry={() => void refetch()}
        />
      ) : isLoading ? (
        <ul className="policies-list" data-testid="policies-list">
          <PolicySkeletonRow />
          <PolicySkeletonRow />
          <PolicySkeletonRow />
        </ul>
      ) : filtered.length === 0 ? (
        <EmptyState
          title={
            filter === 'active'
              ? 'No active policies'
              : filter === 'proposed'
                ? 'No proposed policies'
                : 'No policies yet'
          }
          description={
            filter === 'all'
              ? 'Create your first policy to get started.'
              : 'Switch to All to see every policy.'
          }
          action={
            filter === 'all' ? (
              <button
                type="button"
                className="policies-page__new-btn"
                data-testid="new-policy-empty-btn"
                onClick={handleNew}
              >
                + new policy
              </button>
            ) : undefined
          }
        />
      ) : (
        <ul className="policies-list" data-testid="policies-list">
          {filtered.map((policy) => (
            <PolicyRow
              key={`${policy.name}-${policy.version}`}
              policy={policy}
              onEdit={() => handleEdit(policy)}
            />
          ))}
        </ul>
      )}

      <OverlayHost name="policy-editor">
        <PolicyEditorPlaceholder />
      </OverlayHost>
    </main>
  )
}
