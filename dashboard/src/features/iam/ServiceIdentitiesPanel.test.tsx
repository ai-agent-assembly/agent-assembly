import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest'
import { ServiceIdentitiesPanel } from './ServiceIdentitiesPanel'
import { ToastProvider } from '../../components/ToastProvider'
import { _apiKeysInternal } from './apiKeys'
import { REVEAL_AUTOCLOSE_MS } from './RevealOnceModal'

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>
          <ServiceIdentitiesPanel />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

let clipboardWriteMock: ReturnType<typeof vi.fn>

function installClipboardMock() {
  clipboardWriteMock = vi.fn().mockResolvedValue(undefined)
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    writable: true,
    value: { writeText: clipboardWriteMock },
  })
}

beforeEach(() => {
  _apiKeysInternal.reset()
  installClipboardMock()
})

afterEach(() => {
  _apiKeysInternal.reset()
})

describe('ServiceIdentitiesPanel — listing', () => {
  it('renders seed API keys with masked prefix and warning banner', async () => {
    renderPanel()
    expect(await screen.findByTestId('api-key-row-key-1')).toBeInTheDocument()
    expect(screen.getByTestId('api-keys-shown-once-banner')).toBeInTheDocument()
    expect(screen.getByText(/aa_live_3f9c•••••/)).toBeInTheDocument()
  })

  it('does not render a revoke button on already-revoked rows', async () => {
    renderPanel()
    await screen.findByTestId('api-key-row-key-3')
    expect(screen.queryByTestId('api-key-revoke-key-3')).not.toBeInTheDocument()
    expect(screen.getByTestId('api-key-revoke-key-1')).toBeInTheDocument()
  })
})

describe('ServiceIdentitiesPanel — generate-and-reveal flow', () => {
  it('reveals the new secret once after submit and never re-shows it after close', async () => {
    _apiKeysInternal.setGenerateOverride(() =>
      Promise.resolve({ id: 'gen-1', prefix: 'aa_live_abcd', secret: 'aa_live_abcd_supersecret123' }),
    )
    const user = userEvent.setup()
    renderPanel()
    await screen.findByTestId('api-key-row-key-1')

    await user.click(screen.getByTestId('generate-key-button'))
    await user.type(screen.getByTestId('generate-key-label-input'), 'fresh-runner')
    await user.click(screen.getByTestId('generate-key-scope-read:members'))
    await user.click(screen.getByTestId('generate-key-submit'))

    const modal = await screen.findByTestId('reveal-once-modal')
    expect(within(modal)).toBeDefined()
    const secret = screen.getByTestId('reveal-once-secret') as HTMLInputElement
    expect(secret.value).toBe('aa_live_abcd_supersecret123')
  })

  it('writes the exact secret to the clipboard and autocloses after 2s', async () => {
    _apiKeysInternal.setGenerateOverride(() =>
      Promise.resolve({ id: 'gen-1', prefix: 'aa_live_abcd', secret: 'aa_live_abcd_supersecret123' }),
    )
    const user = userEvent.setup()
    // userEvent.setup() installs its own clipboard polyfill — reinstall the spy on top.
    installClipboardMock()
    renderPanel()
    await screen.findByTestId('api-key-row-key-1')

    await user.click(screen.getByTestId('generate-key-button'))
    await user.type(screen.getByTestId('generate-key-label-input'), 'fresh-runner')
    await user.click(screen.getByTestId('generate-key-scope-read:members'))
    await user.click(screen.getByTestId('generate-key-submit'))

    await screen.findByTestId('reveal-once-modal')
    await user.click(screen.getByTestId('copy-secret-button'))

    await waitFor(() =>
      expect(clipboardWriteMock).toHaveBeenCalledWith('aa_live_abcd_supersecret123'),
    )
    expect(clipboardWriteMock).toHaveBeenCalledTimes(1)
    await screen.findByTestId('reveal-once-copied')

    await waitFor(
      () => expect(screen.queryByTestId('reveal-once-modal')).not.toBeInTheDocument(),
      { timeout: REVEAL_AUTOCLOSE_MS + 1000 },
    )
  }, 10000)

  it('shows the destroy-unseen confirm when closing before copy and discards on confirm', async () => {
    _apiKeysInternal.setGenerateOverride(() =>
      Promise.resolve({ id: 'gen-1', prefix: 'aa_live_abcd', secret: 'aa_live_abcd_supersecret123' }),
    )
    const user = userEvent.setup()
    installClipboardMock()
    renderPanel()
    await screen.findByTestId('api-key-row-key-1')

    await user.click(screen.getByTestId('generate-key-button'))
    await user.type(screen.getByTestId('generate-key-label-input'), 'short-lived')
    await user.click(screen.getByTestId('generate-key-scope-admin'))
    await user.click(screen.getByTestId('generate-key-submit'))

    await screen.findByTestId('reveal-once-modal')
    await user.click(screen.getByTestId('reveal-once-close'))

    expect(await screen.findByTestId('confirm-destroy-unseen-key')).toBeInTheDocument()
    expect(clipboardWriteMock).not.toHaveBeenCalled()

    await user.click(screen.getByTestId('destroy-unseen-discard'))
    await waitFor(() =>
      expect(screen.queryByTestId('reveal-once-modal')).not.toBeInTheDocument(),
    )
    await waitFor(() =>
      expect(screen.queryByTestId('confirm-destroy-unseen-key')).not.toBeInTheDocument(),
    )
  })

  it('keeps the reveal modal open when the destroy-unseen confirm is cancelled', async () => {
    _apiKeysInternal.setGenerateOverride(() =>
      Promise.resolve({ id: 'gen-1', prefix: 'aa_live_abcd', secret: 'aa_live_abcd_supersecret123' }),
    )
    const user = userEvent.setup()
    renderPanel()
    await screen.findByTestId('api-key-row-key-1')

    await user.click(screen.getByTestId('generate-key-button'))
    await user.type(screen.getByTestId('generate-key-label-input'), 'short-lived')
    await user.click(screen.getByTestId('generate-key-scope-admin'))
    await user.click(screen.getByTestId('generate-key-submit'))

    await screen.findByTestId('reveal-once-modal')
    await user.click(screen.getByTestId('reveal-once-close'))
    await screen.findByTestId('confirm-destroy-unseen-key')
    await user.click(screen.getByTestId('destroy-unseen-keep'))

    await waitFor(() =>
      expect(screen.queryByTestId('confirm-destroy-unseen-key')).not.toBeInTheDocument(),
    )
    expect(screen.getByTestId('reveal-once-modal')).toBeInTheDocument()
  })

  it('blocks generate submit until label + scope are present', async () => {
    const user = userEvent.setup()
    renderPanel()
    await screen.findByTestId('api-key-row-key-1')

    await user.click(screen.getByTestId('generate-key-button'))
    await user.click(screen.getByTestId('generate-key-submit'))
    expect(await screen.findByTestId('generate-key-label-error')).toBeInTheDocument()
    expect(screen.getByTestId('generate-key-scopes-error')).toBeInTheDocument()
  })
})

describe('ServiceIdentitiesPanel — revoke', () => {
  it('confirms before revoking, then toggles the row to revoked', async () => {
    const user = userEvent.setup()
    renderPanel()
    await screen.findByTestId('api-key-row-key-1')

    await user.click(screen.getByTestId('api-key-revoke-key-1'))
    expect(await screen.findByTestId('confirm-revoke-key')).toBeInTheDocument()
    await user.click(screen.getByTestId('confirm-revoke-confirm'))

    await waitFor(() =>
      expect(_apiKeysInternal.snapshot().find((k) => k.id === 'key-1')?.status).toBe('revoked'),
    )
    expect(screen.queryByTestId('api-key-revoke-key-1')).not.toBeInTheDocument()
  })
})

// helper import kept after definitions to avoid hoisting hassles in tests
import { within } from '@testing-library/react'
