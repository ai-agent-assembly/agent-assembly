import { useEffect, useMemo, useState } from 'react'
import { useToast } from '../../../components/Toast'
import { useDraft } from './useDraft'
import { countBySeverity, validate } from './validation'
import { RuleCard } from './RuleCard'
import { ScopeRow } from './ScopeRow'
import { ValidationPanel } from './ValidationPanel'
import type { PolicyDraft } from './types'
import './editor.css'

interface PolicyEditorOverlayProps {
  initialDraft: PolicyDraft
  onSave: (draft: PolicyDraft) => void
  onClose: () => void
  /**
   * Published whenever the draft's dirty flag changes. The page consumes
   * this to decide whether Esc / backdrop / Cancel should prompt a
   * "Discard unsaved changes?" dialog.
   */
  onDirtyChange?: (dirty: boolean) => void
  /**
   * When true, the Save button shows a "Saving…" label and is disabled
   * for the duration of the mutation. Falsy in tests + stub flows.
   */
  isSaving?: boolean
}

/**
 * The editor surface mounted inside <OverlayHost name="policy-editor">.
 * Composes the section components and wires draft state via useDraft.
 *
 * The actual save flow (serialize → POST → optimistic update) lives one
 * level up in the page-side container; this component just calls
 * `onSave(draft)` when Save is clicked and validation is clean.
 */
export function PolicyEditorOverlay({
  initialDraft,
  onSave,
  onClose,
  onDirtyChange,
  isSaving = false,
}: PolicyEditorOverlayProps) {
  const {
    draft,
    isDirty,
    updateMeta,
    updateRule,
    addRule,
    duplicateRule,
    removeRule,
    reset,
  } = useDraft(initialDraft)

  const issues = useMemo(() => validate(draft), [draft])
  const { errors } = countBySeverity(issues)
  const { toast } = useToast()
  const [viewMode, setViewMode] = useState<'form' | 'dsl'>('form')

  // Publish isDirty so the page-side container can wire Esc / backdrop /
  // Cancel through a "Discard unsaved changes?" prompt when needed.
  useEffect(() => {
    onDirtyChange?.(isDirty)
  }, [isDirty, onDirtyChange])

  // On unmount, clear the dirty flag — otherwise a successful save +
  // close leaks "still dirty" into the next time the overlay opens.
  useEffect(() => {
    return () => {
      onDirtyChange?.(false)
    }
  }, [onDirtyChange])

  const handleSave = () => {
    if (errors > 0 || isSaving) return
    onSave(draft)
  }

  const handleSimulate = () => {
    if (errors > 0) {
      toast('Fix validation errors before simulating.', 'error')
      return
    }
    toast('Simulate impact: coming soon.', 'info')
  }

  const handleDslToggle = () => {
    // The DSL/Rego preview view is out of scope for this PR.
    toast('Raw DSL view: coming soon.', 'info')
    setViewMode('form')
  }

  const footerStatus = isDirty
    ? `${draft.rules.length} rule(s) modified · run simulate to preview impact`
    : draft.status === 'proposed'
      ? 'Draft — never deployed'
      : `Active · ${draft.rules.length} rule(s)`

  return (
    <div className="editor" data-testid="policy-editor-overlay">
      <header className="editor__header">
        <div className="editor__title">
          <span>editor</span>
          <div className="editor__chips" data-testid="editor-meta-chips">
            <span className="editor__chip">{draft.id}</span>
            <span className="editor__chip editor__chip--name">
              {draft.name.trim().length > 0 ? draft.name : '(unnamed)'}
            </span>
            <span
              className={
                draft.status === 'active'
                  ? 'editor__chip editor__chip--ok'
                  : 'editor__chip editor__chip--warn'
              }
              data-testid="editor-status-chip"
            >
              {draft.status}
            </span>
            <span className="editor__chip">v{draft.version}</span>
            {isDirty ? (
              <span
                className="editor__chip editor__chip--warn"
                data-testid="editor-dirty-chip"
              >
                draft · unsaved
              </span>
            ) : null}
          </div>
        </div>
        <div className="editor__view-toggle" role="tablist" aria-label="editor view mode">
          <button
            type="button"
            role="tab"
            aria-selected={viewMode === 'form'}
            className={
              viewMode === 'form'
                ? 'editor__view-btn editor__view-btn--active'
                : 'editor__view-btn'
            }
            onClick={() => setViewMode('form')}
            data-testid="editor-view-form"
          >
            form
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={viewMode === 'dsl'}
            className="editor__view-btn"
            onClick={handleDslToggle}
            data-testid="editor-view-dsl"
          >
            DSL
          </button>
        </div>
      </header>

      <div className="editor__body">
        {draft.status === 'proposed' ? (
          <div className="editor__callout" data-testid="editor-draft-callout">
            <p className="editor__callout-title">⚠ draft policy</p>
            <p className="editor__callout-body">
              This policy is not yet deployed. Run simulate to preview impact
              before promoting to active.
            </p>
          </div>
        ) : null}

        <ScopeRow
          scope={draft.scope}
          onScopeChange={(scope) => updateMeta({ scope })}
        />

        {draft.rules.map((rule, idx) => (
          <RuleCard
            key={rule.id}
            index={idx}
            rule={rule}
            onChange={(patch) => updateRule(idx, patch)}
            onDuplicate={() => duplicateRule(idx)}
            onRemove={() => removeRule(idx)}
          />
        ))}

        <button
          type="button"
          className="editor__add-rule"
          data-testid="editor-add-rule"
          onClick={addRule}
        >
          + add rule
        </button>

        <ValidationPanel issues={issues} />
      </div>

      <footer className="editor__footer">
        <span className="editor__footer-status" data-testid="editor-footer-status">
          {footerStatus}
        </span>
        <div className="editor__footer-actions">
          {isDirty ? (
            <button
              type="button"
              className="editor__btn"
              data-testid="editor-revert-btn"
              onClick={reset}
            >
              ↶ revert
            </button>
          ) : null}
          <button
            type="button"
            className="editor__btn"
            data-testid="editor-cancel-btn"
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            type="button"
            className={
              errors > 0 || isSaving
                ? 'editor__btn editor__btn--primary editor__btn--disabled'
                : 'editor__btn editor__btn--primary'
            }
            disabled={errors > 0 || isSaving}
            data-testid="editor-save-btn"
            onClick={handleSave}
          >
            {isSaving ? 'Saving…' : 'Save draft'}
          </button>
          <button
            type="button"
            className="editor__btn"
            data-testid="editor-simulate-btn"
            onClick={handleSimulate}
          >
            ▸ Simulate impact
          </button>
        </div>
      </footer>
    </div>
  )
}
