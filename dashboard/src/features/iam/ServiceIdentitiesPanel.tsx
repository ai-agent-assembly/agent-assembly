import { useState } from 'react'
import { useGenerateApiKeyMutation } from './apiKeys'
import { ApiKeyList } from './ApiKeyList'
import { ConfirmDestroyUnseenKey } from './ConfirmDestroyUnseenKey'
import { GenerateKeyDialog } from './GenerateKeyDialog'
import { IdentityDetailCard } from './IdentityDetailCard'
import { RevealOnceModal } from './RevealOnceModal'
import { useRevealOnceState } from './useRevealOnceState'
import { useToast } from '../../components/Toast'
import type { ApiKey, GenerateApiKeyInput } from './types'
import './ServiceIdentitiesPanel.css'
import './GenerateKeyDialog.css'

export function ServiceIdentitiesPanel() {
  const [generateOpen, setGenerateOpen] = useState(false)
  const [confirmDiscardOpen, setConfirmDiscardOpen] = useState(false)
  /** Selected api-key row drives the IdentityDetailCard on the right (AAASM-1396). */
  const [selected, setSelected] = useState<ApiKey | null>(null)
  const reveal = useRevealOnceState()
  const generate = useGenerateApiKeyMutation()
  const { toast } = useToast()

  function handleGenerate(input: GenerateApiKeyInput) {
    generate.mutate(input, {
      onSuccess: (generated) => {
        setGenerateOpen(false)
        reveal.reveal(generated)
      },
      onError: (err) => {
        toast(err instanceof Error ? err.message : 'Failed to generate key', 'error')
      },
    })
  }

  function attemptCloseReveal() {
    if (reveal.copied) {
      reveal.clear()
    } else {
      setConfirmDiscardOpen(true)
    }
  }

  function keepShowing() {
    setConfirmDiscardOpen(false)
  }

  function discardSecret() {
    setConfirmDiscardOpen(false)
    reveal.clear()
  }

  return (
    <section className="iam-services-panel" data-testid="iam-panel-services">
      <header className="iam-services-panel__header">
        <h2>Service identities</h2>
        <button
          type="button"
          className="iam-services-panel__generate-btn"
          data-testid="generate-key-button"
          onClick={() => setGenerateOpen(true)}
        >
          Generate API key
        </button>
      </header>

      <div className="iam-shown-once-banner" data-testid="api-keys-shown-once-banner">
        <strong>API keys are shown once at creation.</strong> Copy the secret immediately —
        Agent Assembly does not store it in cleartext and cannot show it again.
      </div>

      <div className="iam-services-panel__layout">
        <div className="iam-services-panel__list">
          <ApiKeyList
            selectedKeyId={selected?.id ?? null}
            onSelect={setSelected}
            onRotated={(generated) => reveal.reveal(generated)}
          />
        </div>
        <div className="iam-services-panel__detail">
          {selected ? (
            <IdentityDetailCard
              identity={selected}
              onClose={() => setSelected(null)}
            />
          ) : (
            <div
              className="iam-services-panel__hint"
              data-testid="iam-services-detail-empty"
            >
              Select an API key on the left to inspect its identity profile.
            </div>
          )}
        </div>
      </div>

      <GenerateKeyDialog
        open={generateOpen}
        onClose={() => setGenerateOpen(false)}
        onSubmit={handleGenerate}
        isSubmitting={generate.isPending}
      />

      {reveal.current && (
        <RevealOnceModal
          generated={reveal.current}
          copied={reveal.copied}
          onCopied={reveal.markCopied}
          onClose={reveal.clear}
          onAttemptCloseBeforeCopy={() => setConfirmDiscardOpen(true)}
        />
      )}

      <ConfirmDestroyUnseenKey
        open={confirmDiscardOpen}
        onKeepShowing={keepShowing}
        onDiscardSecret={discardSecret}
      />

      {/* Defensive: if both modals close together, ensure escape-route is clean. */}
      {!reveal.current && confirmDiscardOpen && (
        // Should not be reachable, but ensures the destroy modal cannot orphan.
        <button hidden onClick={attemptCloseReveal} />
      )}
    </section>
  )
}
