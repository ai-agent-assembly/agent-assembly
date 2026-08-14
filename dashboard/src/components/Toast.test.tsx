import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useToast } from './Toast'
import { ToastProvider } from './ToastProvider'

function Trigger() {
  const { toast } = useToast()
  return (
    <div>
      <button type="button" onClick={() => toast('saved', 'success')}>
        success
      </button>
      <button type="button" onClick={() => toast('boom', 'error')}>
        error
      </button>
      <button type="button" onClick={() => toast('default-variant')}>
        default
      </button>
    </div>
  )
}

describe('useToast', () => {
  it('throws when used outside a ToastProvider', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    function Orphan() {
      useToast()
      return null
    }
    expect(() => render(<Orphan />)).toThrow('useToast must be used within a ToastProvider')
    spy.mockRestore()
  })

  it('renders a toast with its variant when toast() is called', async () => {
    const user = userEvent.setup()
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    )
    await user.click(screen.getByRole('button', { name: 'success' }))
    const toast = screen.getByTestId('toast')
    expect(toast).toHaveTextContent('saved')
    expect(toast).toHaveAttribute('data-variant', 'success')
  })

  it('defaults to the info variant when none is given', async () => {
    const user = userEvent.setup()
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    )
    await user.click(screen.getByRole('button', { name: 'default' }))
    expect(screen.getByTestId('toast')).toHaveAttribute('data-variant', 'info')
  })

  it('stacks multiple toasts', async () => {
    const user = userEvent.setup()
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    )
    await user.click(screen.getByRole('button', { name: 'success' }))
    await user.click(screen.getByRole('button', { name: 'error' }))
    expect(screen.getAllByTestId('toast')).toHaveLength(2)
  })

  it('auto-dismisses a toast after its TTL elapses', () => {
    vi.useFakeTimers()
    try {
      render(
        <ToastProvider>
          <Trigger />
        </ToastProvider>,
      )
      act(() => {
        screen.getByRole('button', { name: 'success' }).click()
      })
      expect(screen.getByTestId('toast')).toBeInTheDocument()
      act(() => {
        vi.advanceTimersByTime(4000)
      })
      expect(screen.queryByTestId('toast')).not.toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })
})
