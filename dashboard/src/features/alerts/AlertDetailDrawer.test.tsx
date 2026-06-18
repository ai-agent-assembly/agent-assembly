import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { AlertDetailDrawer } from './AlertDetailDrawer'

describe('AlertDetailDrawer', () => {
  it('renders nothing when closed', () => {
    const { container } = render(
      <AlertDetailDrawer open={false} onClose={vi.fn()}>
        <div data-testid="child">body</div>
      </AlertDetailDrawer>,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the drawer and children when open', () => {
    render(
      <AlertDetailDrawer open onClose={vi.fn()}>
        <div data-testid="child">body</div>
      </AlertDetailDrawer>,
    )
    expect(screen.getByTestId('alert-detail-drawer')).toBeInTheDocument()
    expect(screen.getByTestId('child')).toBeInTheDocument()
  })

  it('closes via the close button', () => {
    const onClose = vi.fn()
    render(<AlertDetailDrawer open onClose={onClose} />)
    fireEvent.click(screen.getByTestId('alert-detail-drawer-close'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('closes when the scrim is clicked but not the panel body', () => {
    const onClose = vi.fn()
    render(
      <AlertDetailDrawer open onClose={onClose}>
        <div data-testid="child">body</div>
      </AlertDetailDrawer>,
    )
    fireEvent.click(screen.getByTestId('child'))
    expect(onClose).not.toHaveBeenCalled()
    fireEvent.click(screen.getByTestId('alert-detail-drawer'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('closes on Escape only while open', () => {
    const onClose = vi.fn()
    const { rerender } = render(<AlertDetailDrawer open onClose={onClose} />)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)

    // After closing, the keydown listener is removed → no further calls.
    rerender(<AlertDetailDrawer open={false} onClose={onClose} />)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
