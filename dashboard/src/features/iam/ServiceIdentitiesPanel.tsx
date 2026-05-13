import { useState } from 'react'
import { useGenerateApiKeyMutation } from './apiKeys'
import { ApiKeyList } from './ApiKeyList'
import { ConfirmDestroyUnseenKey } from './ConfirmDestroyUnseenKey'
import { GenerateKeyDialog } from './GenerateKeyDialog'
import { RevealOnceModal } from './RevealOnceModal'
import { useRevealOnceState } from './useRevealOnceState'
import { useToast } from '../../components/Toast'
import type { GenerateApiKeyInput } from './types'
import './ServiceIdentitiesPanel.css'
import './GenerateKeyDialog.css'

export function ServiceIdentitiesPanel() {
  const [generateOpen, setGenerateOpen] = useState(false)
  const [confirmDiscardOpen, setConfirmDiscardOpen] = useState(false)
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

      <ApiKeyList />

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
