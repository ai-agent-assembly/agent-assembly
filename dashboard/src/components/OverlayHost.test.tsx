import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { OverlayProvider } from './OverlayProvider'
import { OverlayHost } from './OverlayHost'
import { useOverlay } from './useOverlay'

function OpenerButton() {
  const { openOverlay } = useOverlay('policy-editor')
  return (
    <button type="button" onClick={() => openOverlay()}>
      open
    </button>
  )
}

interface HarnessProps {
  withMount?: boolean
  onRequestClose?: () => void
  children?: ReactNode
}

function Harness({ withMount = true, onRequestClose, children }: HarnessProps) {
  return (
    <OverlayProvider>
      {withMount ? (
        <div data-overlay="policy-editor" data-testid="overlay-mount-policy-editor" />
      ) : null}
      <OpenerButton />
      <OverlayHost name="policy-editor" onRequestClose={onRequestClose}>
        {children ?? <div data-testid="overlay-content">content</div>}
      </OverlayHost>
    </OverlayProvider>
  )
}

describe('OverlayHost', () => {
  it('does not render its children when the overlay is closed', () => {
    render(<Harness />)
    expect(screen.queryByTestId('overlay-content')).not.toBeInTheDocument()
    expect(screen.queryByTestId('overlay-policy-editor')).not.toBeInTheDocument()
  })

  it('portals children into the matching data-overlay mount when open', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    await user.click(screen.getByRole('button', { name: 'open' }))
    const mount = screen.getByTestId('overlay-mount-policy-editor')
    const content = screen.getByTestId('overlay-content')
    expect(content).toBeInTheDocument()
    expect(mount.contains(content)).toBe(true)
  })

  it('marks the container as role="dialog" aria-modal="true"', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    await user.click(screen.getByRole('button', { name: 'open' }))
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveAttribute('aria-modal', 'true')
  })

  it('Esc dismisses via closeOverlay when no onRequestClose is provided', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    await user.click(screen.getByRole('button', { name: 'open' }))
    expect(screen.getByTestId('overlay-content')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByTestId('overlay-content')).not.toBeInTheDocument()
  })

  it('Esc invokes onRequestClose and leaves the overlay open when provided', async () => {
    const user = userEvent.setup()
    const onRequestClose = vi.fn()
    render(<Harness onRequestClose={onRequestClose} />)
    await user.click(screen.getByRole('button', { name: 'open' }))
    await user.keyboard('{Escape}')
    expect(onRequestClose).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('overlay-content')).toBeInTheDocument()
  })

  it('backdrop click dismisses; content click does not', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    await user.click(screen.getByRole('button', { name: 'open' }))
    await user.click(screen.getByTestId('overlay-content'))
    expect(screen.getByTestId('overlay-content')).toBeInTheDocument()
    await user.click(screen.getByTestId('overlay-policy-editor'))
    expect(screen.queryByTestId('overlay-content')).not.toBeInTheDocument()
  })

  it('backdrop click invokes onRequestClose when provided', async () => {
    const user = userEvent.setup()
    const onRequestClose = vi.fn()
    render(<Harness onRequestClose={onRequestClose} />)
    await user.click(screen.getByRole('button', { name: 'open' }))
    await user.click(screen.getByTestId('overlay-policy-editor'))
    expect(onRequestClose).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('overlay-content')).toBeInTheDocument()
  })

  it('renders nothing when the data-overlay mount point is missing', async () => {
    const user = userEvent.setup()
    render(<Harness withMount={false} />)
    await user.click(screen.getByRole('button', { name: 'open' }))
    expect(screen.queryByTestId('overlay-content')).not.toBeInTheDocument()
    expect(screen.queryByTestId('overlay-policy-editor')).not.toBeInTheDocument()
  })
})
