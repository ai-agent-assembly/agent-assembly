import { useCallback, useMemo, useRef, useState, type MutableRefObject } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import { usePoliciesQuery, useCreatePolicy, type Policy } from '../features/policies/api'
import { useSandboxSummaryQuery } from '../features/audit/api'
import { extractEnforcementMode } from '../features/policies/policyYamlHelpers'
import { SandboxEnableLiveDialog } from '../features/policies/SandboxEnableLiveDialog'
import { SandboxSummaryCard } from '../components/SandboxSummaryCard'
import { EmptyState, ErrorState } from '../components/states'
import { OverlayHost } from '../components/OverlayHost'
import { useOverlay } from '../components/useOverlay'
import { useToast } from '../components/Toast'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { PolicyEditorOverlay } from '../features/policies/editor/PolicyEditorOverlay'
import { emptyDraft, stubDraftFromIdentity } from '../features/policies/editor/constants'
import { serializeDraft } from '../features/policies/editor/serializeDraft'
import type {
  PolicyDraft,
  PolicyEditorOverlayProps,
} from '../features/policies/editor/types'
import './PoliciesPage.css'

type FilterTab = 'all' | 'active' | 'proposed'

const FILTER_TABS: ReadonlyArray<{ id: FilterTab; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'active', label: 'Active' },
  { id: 'proposed', label: 'Proposed' },
]

interface PolicyEditorOverlayContainerProps {
  dirtyRef: MutableRefObject<boolean>
  onRequestClose: () => void
}

function PolicyEditorOverlayContainer({
  dirtyRef,
  onRequestClose,
}: Readonly<PolicyEditorOverlayContainerProps>) {
  const { props, closeOverlay } = useOverlay('policy-editor')
  const overlayProps = props as unknown as PolicyEditorOverlayProps
  const { toast } = useToast()
  const { mutateAsync, isPending } = useCreatePolicy()

  // Stable initial draft for the lifetime of this overlay open session.
  // Identity matters because useDraft references it for dirty tracking.
  const initialDraft = useMemo(() => {
    if (
      overlayProps.mode === 'edit' &&
      overlayProps.name &&
      overlayProps.version
    ) {
      return stubDraftFromIdentity(overlayProps.name, overlayProps.version)
    }
    return emptyDraft()
  }, [overlayProps.mode, overlayProps.name, overlayProps.version])

  const handleDirtyChange = useCallback(
    (dirty: boolean) => {
      dirtyRef.current = dirty
    },
    [dirtyRef],
  )

  const handleSave = useCallback(
    async (draft: PolicyDraft) => {
      try {
        const policy_yaml = serializeDraft(draft)
        await mutateAsync({ policy_yaml, scope: draft.scope })
        toast('Policy saved', 'success')
        // We just persisted; bypass the dirty guard.
        dirtyRef.current = false
        closeOverlay()
      } catch {
        // Leave the overlay open so the user can fix and retry.
        toast('Failed to save policy', 'error')
      }
    },
    [mutateAsync, toast, closeOverlay, dirtyRef],
  )

  return (
    <PolicyEditorOverlay
      initialDraft={initialDraft}
      onSave={handleSave}
      onClose={onRequestClose}
      onDirtyChange={handleDirtyChange}
      isSaving={isPending}
    />
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

function PolicyRow({ policy, onEdit }: Readonly<{ policy: Policy; onEdit: () => void }>) {
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

function emptyStateTitle(filter: FilterTab): string {
  if (filter === 'active') return 'No active policies'
  if (filter === 'proposed') return 'No proposed policies'
  return 'No policies yet'
}

function emptyStateDescription(filter: FilterTab): string {
  return filter === 'all'
    ? 'Create your first policy to get started.'
    : 'Switch to All to see every policy.'
}

interface PoliciesTabsProps {
  readonly filter: FilterTab
  readonly counts: Record<FilterTab, number>
  readonly onSelect: (tab: FilterTab) => void
}

/**
 * The filter tab strip. Extracted from PoliciesPage so its per-tab
 * active/count-class branching does not count against the page's
 * cognitive complexity (SonarCloud typescript:S3776).
 */
function PoliciesTabs({ filter, counts, onSelect }: PoliciesTabsProps) {
  return (
    <nav className="policies-tabs" role="tablist" aria-label="Filter policies">
      {FILTER_TABS.map((tab) => {
        const active = filter === tab.id
        const warnCount = tab.id === 'proposed' && counts.proposed > 0
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
            onClick={() => onSelect(tab.id)}
          >
            {tab.label}
            <span
              className={
                warnCount
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
  )
}

interface PoliciesSandboxBannerProps {
  readonly summary: ReturnType<typeof useSandboxSummaryQuery>['data']
  readonly onEnableLive: () => void
}

/**
 * The observe-mode sandbox banner. Extracted from PoliciesPage so the
 * nested optional-chaining for counts/top-rule does not count against the
 * page's cognitive complexity (SonarCloud typescript:S3776).
 */
function PoliciesSandboxBanner({ summary, onEnableLive }: PoliciesSandboxBannerProps) {
  const topRule = summary?.top_rule
  return (
    <div className="policies-page__sandbox" data-testid="policies-sandbox-banner">
      <SandboxSummaryCard
        policyName="All policies"
        windowLabel="last 24h"
        counts={{
          wouldBeDenies: summary?.counts.would_be_denies ?? 0,
          wouldBeRedactions: summary?.counts.would_be_redactions ?? 0,
          wouldBePendingApprovals: summary?.counts.would_be_pending_approvals ?? 0,
        }}
        topRule={topRule ? { id: topRule.id, count: topRule.count } : undefined}
        onEnableLiveEnforcement={onEnableLive}
      />
    </div>
  )
}

interface PoliciesContentProps {
  readonly isError: boolean
  readonly isLoading: boolean
  readonly filter: FilterTab
  readonly filtered: readonly Policy[]
  readonly onRetry: () => void
  readonly onNew: () => void
  readonly onEdit: (policy: Policy) => void
}

/**
 * The error / loading / empty / list state machine for the policies view.
 * Extracted from PoliciesPage to keep its cognitive complexity low
 * (SonarCloud typescript:S3776).
 */
function PoliciesContent({
  isError,
  isLoading,
  filter,
  filtered,
  onRetry,
  onNew,
  onEdit,
}: PoliciesContentProps) {
  if (isError) {
    return (
      <ErrorState
        title="Failed to load policies"
        description="The gateway returned an unexpected error."
        onRetry={onRetry}
      />
    )
  }
  if (isLoading) {
    return (
      <ul className="policies-list" data-testid="policies-list">
        <PolicySkeletonRow />
        <PolicySkeletonRow />
        <PolicySkeletonRow />
      </ul>
    )
  }
  if (filtered.length === 0) {
    return (
      <EmptyState
        title={emptyStateTitle(filter)}
        description={emptyStateDescription(filter)}
        action={
          filter === 'all' ? (
            <button
              type="button"
              className="policies-page__new-btn"
              data-testid="new-policy-empty-btn"
              onClick={onNew}
            >
              + new policy
            </button>
          ) : undefined
        }
      />
    )
  }
  return (
    <ul className="policies-list" data-testid="policies-list">
      {filtered.map((policy) => (
        <PolicyRow
          key={`${policy.name}-${policy.version}`}
          policy={policy}
          onEdit={() => onEdit(policy)}
        />
      ))}
    </ul>
  )
}

export function PoliciesPage() {
  const { data: policies, isLoading, isError, refetch } = usePoliciesQuery()
  const { data: sandboxSummary } = useSandboxSummaryQuery({ window: '24h' })
  const [filter, setFilter] = useState<FilterTab>('all')
  const { openOverlay, closeOverlay } = useOverlay('policy-editor')
  const { toast } = useToast()
  const { mutateAsync: createPolicy, isPending: enablingLive } = useCreatePolicy()
  const [enableLiveOpen, setEnableLiveOpen] = useState(false)

  // Observe-mode policies detected by parsing each policy_yaml client-side.
  // The aa-api `PolicyResponse` doesn't expose `enforcement_mode` as a
  // field today, so we read it out of the raw YAML; the helper tolerates
  // empty / malformed bodies by returning null.
  const observePolicies = useMemo(
    () => (policies ?? []).filter((p) => extractEnforcementMode(p.policy_yaml) === 'observe'),
    [policies],
  )
  const showSandboxBanner = observePolicies.length > 0

  const openEnableLiveDialog = useCallback(() => {
    setEnableLiveOpen(true)
  }, [])

  const closeEnableLiveDialog = useCallback(() => {
    setEnableLiveOpen(false)
  }, [])

  // The aa-api endpoint is global today (no per-policy filter), so the
  // banner displays "All policies" — counts are aggregate across every
  // observe-mode policy in the deployment. Per-policy scoping is a
  // separate follow-up (see ticket).
  const confirmEnableLive = useCallback(
    async (policy: Policy, modifiedYaml: string) => {
      try {
        await createPolicy({ policy_yaml: modifiedYaml })
        toast(`Live enforcement enabled for ${policy.name}`, 'success')
        setEnableLiveOpen(false)
      } catch {
        toast(`Failed to enable live enforcement for ${policy.name}`, 'error')
      }
    },
    [createPolicy, toast],
  )

  // Editor publishes its dirty state into this ref so the page can decide
  // whether Esc / backdrop / Cancel should prompt for confirmation.
  const editorDirtyRef = useRef(false)
  const [confirmDiscardOpen, setConfirmDiscardOpen] = useState(false)

  const attemptCloseEditor = useCallback(() => {
    if (editorDirtyRef.current) {
      setConfirmDiscardOpen(true)
    } else {
      closeOverlay()
    }
  }, [closeOverlay])

  const handleDiscardConfirm = useCallback(() => {
    setConfirmDiscardOpen(false)
    editorDirtyRef.current = false
    closeOverlay()
  }, [closeOverlay])

  const all = useMemo(() => policies ?? [], [policies])
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

      {showSandboxBanner ? (
        <PoliciesSandboxBanner
          summary={sandboxSummary}
          onEnableLive={openEnableLiveDialog}
        />
      ) : null}

      <PoliciesTabs filter={filter} counts={counts} onSelect={setFilter} />

      <PoliciesContent
        isError={isError}
        isLoading={isLoading}
        filter={filter}
        filtered={filtered}
        onRetry={() => ignorePromise(refetch())}
        onNew={handleNew}
        onEdit={handleEdit}
      />

      <OverlayHost name="policy-editor" onRequestClose={attemptCloseEditor}>
        <PolicyEditorOverlayContainer
          dirtyRef={editorDirtyRef}
          onRequestClose={attemptCloseEditor}
        />
      </OverlayHost>

      <ConfirmDialog
        open={confirmDiscardOpen}
        title="Discard unsaved changes?"
        body="Closing the editor now will lose your unsaved edits."
        confirmLabel="Discard"
        cancelLabel="Keep editing"
        confirmVariant="danger"
        onConfirm={handleDiscardConfirm}
        onCancel={() => setConfirmDiscardOpen(false)}
      />

      <SandboxEnableLiveDialog
        open={enableLiveOpen}
        observePolicies={observePolicies}
        onCancel={closeEnableLiveDialog}
        onConfirm={confirmEnableLive}
        submitting={enablingLive}
      />
    </main>
  )
}
