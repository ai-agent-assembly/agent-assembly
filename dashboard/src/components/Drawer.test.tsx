import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { Drawer } from './Drawer'

describe('Drawer', () => {
  it('renders nothing when open is false', () => {
    render(
      <Drawer open={false} onClose={vi.fn()}>
        body
      </Drawer>,
    )
    expect(screen.queryByTestId('drawer-scrim')).not.toBeInTheDocument()
    expect(screen.queryByTestId('drawer-panel')).not.toBeInTheDocument()
  })

  it('renders the scrim and panel when open is true', () => {
    render(
      <Drawer open onClose={vi.fn()} ariaLabel="Test drawer">
        <p>hello</p>
      </Drawer>,
    )
    expect(screen.getByTestId('drawer-scrim')).toBeInTheDocument()
    const panel = screen.getByTestId('drawer-panel')
    expect(panel).toBeInTheDocument()
    expect(panel).toHaveAttribute('aria-label', 'Test drawer')
    expect(panel).toHaveAttribute('aria-modal', 'true')
    expect(screen.getByText('hello')).toBeInTheDocument()
  })

  it('fires onClose when the scrim is clicked', () => {
    const onClose = vi.fn()
    render(
      <Drawer open onClose={onClose}>
        <p>body</p>
      </Drawer>,
    )
    fireEvent.click(screen.getByTestId('drawer-scrim'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('does not fire onClose when a click bubbles up from inside the panel', () => {
    const onClose = vi.fn()
    render(
      <Drawer open onClose={onClose}>
        <button>inner</button>
      </Drawer>,
    )
    fireEvent.click(screen.getByText('inner'))
    expect(onClose).not.toHaveBeenCalled()
  })

  it('fires onClose when the Escape key is pressed', () => {
    const onClose = vi.fn()
    render(
      <Drawer open onClose={onClose}>
        <p>body</p>
      </Drawer>,
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('ignores non-Escape keys', () => {
    const onClose = vi.fn()
    render(
      <Drawer open onClose={onClose}>
        <p>body</p>
      </Drawer>,
    )
    fireEvent.keyDown(document, { key: 'Enter' })
    fireEvent.keyDown(document, { key: ' ' })
    expect(onClose).not.toHaveBeenCalled()
  })

  it('stops listening for Escape after open flips to false', () => {
    const onClose = vi.fn()
    const { rerender } = render(
      <Drawer open onClose={onClose}>
        <p>body</p>
      </Drawer>,
    )
    rerender(
      <Drawer open={false} onClose={onClose}>
        <p>body</p>
      </Drawer>,
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).not.toHaveBeenCalled()
  })
})
