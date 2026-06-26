import { act, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { RevealOnceModal, REVEAL_AUTOCLOSE_MS } from './RevealOnceModal'
import { ToastProvider } from '../../components/ToastProvider'
import type { GeneratedApiKey } from './types'

const GENERATED: GeneratedApiKey = {
  id: 'key-1',
  secret: 'aa-secret-xyz',
} as GeneratedApiKey

function renderModal(props: Partial<React.ComponentProps<typeof RevealOnceModal>> = {}) {
  const handlers = {
    onCopied: vi.fn(),
    onClose: vi.fn(),
    onAttemptCloseBeforeCopy: vi.fn(),
  }
  const Wrapper = ({ children }: { children: ReactNode }) => <ToastProvider>{children}</ToastProvider>
  render(
    <RevealOnceModal generated={GENERATED} copied={false} {...handlers} {...props} />,
    { wrapper: Wrapper },
  )
  return handlers
}

describe('RevealOnceModal', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('shows the secret and the pre-copy button labels', () => {
    renderModal()
    expect(screen.getByTestId('reveal-once-secret')).toHaveValue('aa-secret-xyz')
    expect(screen.getByTestId('copy-secret-button')).toHaveTextContent('Copy to clipboard')
    expect(screen.getByTestId('reveal-once-close')).toHaveTextContent('Close without copying')
    expect(screen.queryByTestId('reveal-once-copied')).not.toBeInTheDocument()
  })

  it('copies the secret and reports success', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    const { onCopied } = renderModal()

    await act(async () => {
      fireEvent.click(screen.getByTestId('copy-secret-button'))
    })

    expect(writeText).toHaveBeenCalledWith('aa-secret-xyz')
    expect(onCopied).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('toast')).toHaveAttribute('data-variant', 'success')
  })

  it('surfaces a clipboard failure as an error toast', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('denied'))
    Object.assign(navigator, { clipboard: { writeText } })
    const { onCopied } = renderModal()

    await act(async () => {
      fireEvent.click(screen.getByTestId('copy-secret-button'))
    })

    expect(onCopied).not.toHaveBeenCalled()
    const toast = screen.getByTestId('toast')
    expect(toast).toHaveAttribute('data-variant', 'error')
    expect(toast).toHaveTextContent('denied')
  })

  it('treats a backdrop click before copy as an attempted early close', () => {
    const { onAttemptCloseBeforeCopy, onClose } = renderModal()
    fireEvent.click(screen.getByTestId('reveal-once-modal'))
    expect(onAttemptCloseBeforeCopy).toHaveBeenCalledTimes(1)
    expect(onClose).not.toHaveBeenCalled()
  })

  it('closes immediately on backdrop click once copied', () => {
    const { onClose, onAttemptCloseBeforeCopy } = renderModal({ copied: true })
    fireEvent.click(screen.getByTestId('reveal-once-modal'))
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(onAttemptCloseBeforeCopy).not.toHaveBeenCalled()
  })

  it('does not close when the inner dialog body is clicked', () => {
    const { onClose, onAttemptCloseBeforeCopy } = renderModal()
    fireEvent.click(screen.getByTestId('reveal-once-secret'))
    expect(onClose).not.toHaveBeenCalled()
    expect(onAttemptCloseBeforeCopy).not.toHaveBeenCalled()
  })

  it('activates the backdrop via the Enter key', () => {
    const { onAttemptCloseBeforeCopy } = renderModal()
    fireEvent.keyDown(screen.getByTestId('reveal-once-modal'), { key: 'Enter' })
    expect(onAttemptCloseBeforeCopy).toHaveBeenCalledTimes(1)
  })

  it('ignores backdrop key events that bubble from inner content', () => {
    const { onAttemptCloseBeforeCopy } = renderModal()
    fireEvent.keyDown(screen.getByTestId('reveal-once-secret'), { key: 'Enter' })
    expect(onAttemptCloseBeforeCopy).not.toHaveBeenCalled()
  })

  it('shows the copied affordances and auto-closes after the delay', () => {
    vi.useFakeTimers()
    try {
      const handlers = {
        onCopied: vi.fn(),
        onClose: vi.fn(),
        onAttemptCloseBeforeCopy: vi.fn(),
      }
      render(
        <ToastProvider>
          <RevealOnceModal generated={GENERATED} copied {...handlers} />
        </ToastProvider>,
      )
      expect(screen.getByTestId('reveal-once-copied')).toBeInTheDocument()
      expect(screen.getByTestId('copy-secret-button')).toBeDisabled()
      expect(screen.getByTestId('reveal-once-close')).toHaveTextContent('Close')

      act(() => {
        vi.advanceTimersByTime(REVEAL_AUTOCLOSE_MS)
      })
      expect(handlers.onClose).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })
})
