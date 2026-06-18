import { useState } from 'react'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import type { Policy } from './api'
import { withEnforcementMode } from './policyYamlHelpers'

export interface SandboxEnableLiveDialogProps {
  /** Open / closed state controlled by the parent. */
  readonly open: boolean
  /** Observe-mode policies the operator can flip. Empty array hides the picker. */
  readonly observePolicies: ReadonlyArray<Policy>
  /** Fires when the operator clicks Cancel or dismisses via Esc / backdrop. */
  readonly onCancel: () => void
  /**
   * Fires when the operator confirms. Receives the chosen policy and the
   * modified YAML body (with `enforcement_mode: enforce` swapped in) so
   * the caller can submit it through the existing create_policy mutation.
   */
  readonly onConfirm: (policy: Policy, modifiedYaml: string) => void | Promise<void>
  /** When true, disables the confirm button while the parent's POST is in flight. */
  readonly submitting?: boolean
}

/**
 * Confirmation modal for flipping an observe-mode policy to live
 * enforcement. Renders a `<select>` picker when more than one observe-mode
 * policy exists; falls back to a single-line "this will enforce X" prompt
 * when only one is available.
 *
 * On confirm, swaps `enforcement_mode: enforce` into the chosen policy's
 * YAML (preserving comments and unrelated fields) and hands the result to
 * the parent for submission.
 */
export function SandboxEnableLiveDialog({
  open,
  observePolicies,
  onCancel,
  onConfirm,
  submitting = false,
}: SandboxEnableLiveDialogProps) {
  const [selectedName, setSelectedName] = useState<string>('')

  // Effective selection: explicit user pick wins if it still refers to an
  // observe-mode policy in the current set; otherwise fall back to the
  // first available. Computing this each render avoids a setState-in-effect
  // pattern (which react-hooks/set-state-in-effect prohibits) while still
  // staying correct after policies are added/removed between open cycles.
  const effectiveSelection =
    selectedName && observePolicies.some((p) => p.name === selectedName)
      ? selectedName
      : observePolicies[0]?.name ?? ''

  const handleConfirm = () => {
    const chosen =
      observePolicies.find((p) => p.name === effectiveSelection) ?? observePolicies[0]
    if (!chosen) {
      onCancel()
      return
    }
    const modified = withEnforcementMode(chosen.policy_yaml, 'enforce')
    void onConfirm(chosen, modified)
  }

  let body: React.ReactNode
  if (observePolicies.length === 0) {
    body = <p>No observe-mode policies to enforce.</p>
  } else if (observePolicies.length === 1) {
    body = (
      <p data-testid="sandbox-enable-live-single">
        This will switch <strong>{observePolicies[0].name}</strong> from observe mode to live
        enforcement. Decisions matched by this policy will start blocking immediately.
      </p>
    )
  } else {
    body = (
      <>
        <p>
          Pick the observe-mode policy to switch to live enforcement. Decisions matched by
          it will start blocking immediately.
        </p>
        <label style={{ display: 'block', marginTop: 8, fontSize: 12 }}>
          <span>Policy:&nbsp;</span>
          <select
            data-testid="sandbox-enable-live-picker"
            value={effectiveSelection}
            onChange={(e) => setSelectedName(e.target.value)}
            disabled={submitting}
          >
            {observePolicies.map((p) => (
              <option key={p.name} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
      </>
    )
  }

  return (
    <ConfirmDialog
      open={open}
      title="Enable live enforcement?"
      body={body}
      confirmLabel={submitting ? 'Enabling…' : 'Enable live enforcement'}
      cancelLabel="Cancel"
      confirmVariant="primary"
      onConfirm={handleConfirm}
      onCancel={onCancel}
    />
  )
}
