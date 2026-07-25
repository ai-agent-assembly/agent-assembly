import { render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CastleMoat } from './CastleMoat'

const observeSpy = vi.fn()
const disconnectSpy = vi.fn()

class MockResizeObserver {
  observe = observeSpy
  unobserve = vi.fn()
  disconnect = disconnectSpy
}

beforeEach(() => {
  observeSpy.mockClear()
  disconnectSpy.mockClear()
  globalThis.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('CastleMoat', () => {
  it('renders a <canvas> with a descriptive aria-label', () => {
    render(<CastleMoat />)
    const canvas = screen.getByTestId('castle-moat')
    expect(canvas.tagName).toBe('CANVAS')
    expect(canvas).toHaveAttribute('role', 'img')
    const label = canvas.getAttribute('aria-label') ?? ''
    expect(label).toMatch(/L1.*L2.*L3/)
  })

  it('subscribes a ResizeObserver to the parent element', () => {
    render(
      <div>
        <CastleMoat />
      </div>,
    )
    expect(observeSpy).toHaveBeenCalledTimes(1)
  })

  it('disconnects the ResizeObserver on unmount', () => {
    const { unmount } = render(
      <div>
        <CastleMoat />
      </div>,
    )
    unmount()
    expect(disconnectSpy).toHaveBeenCalled()
  })

  it('accepts paused / intensity props without crashing', () => {
    const { unmount } = render(
      <div>
        <CastleMoat paused intensity={3} />
      </div>,
    )
    expect(screen.getByTestId('castle-moat')).toBeInTheDocument()
    unmount()
  })

  it('registers and removes a visibilitychange listener around its lifecycle', () => {
    const addSpy = vi.spyOn(document, 'addEventListener')
    const removeSpy = vi.spyOn(document, 'removeEventListener')
    const { unmount } = render(<CastleMoat />)
    expect(
      addSpy.mock.calls.some(([type]) => type === 'visibilitychange'),
    ).toBe(true)
    unmount()
    expect(
      removeSpy.mock.calls.some(([type]) => type === 'visibilitychange'),
    ).toBe(true)
  })
})
