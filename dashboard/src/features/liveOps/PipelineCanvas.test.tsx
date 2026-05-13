import { render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { PipelineCanvas } from './PipelineCanvas'

const observeSpy = vi.fn()
const disconnectSpy = vi.fn()

class MockResizeObserver {
  observe = observeSpy
  unobserve = vi.fn()
  disconnect = disconnectSpy
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_cb: ResizeObserverCallback) {}
}

beforeEach(() => {
  observeSpy.mockClear()
  disconnectSpy.mockClear()
  globalThis.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('PipelineCanvas', () => {
  it('renders a <canvas> with a descriptive aria-label', () => {
    render(<PipelineCanvas />)
    const canvas = screen.getByTestId('pipeline-canvas')
    expect(canvas.tagName).toBe('CANVAS')
    expect(canvas).toHaveAttribute('role', 'img')
    const label = canvas.getAttribute('aria-label') ?? ''
    expect(label).toMatch(/L1.*L2.*L3/)
  })

  it('subscribes a ResizeObserver to the parent element', () => {
    render(
      <div>
        <PipelineCanvas />
      </div>,
    )
    expect(observeSpy).toHaveBeenCalledTimes(1)
  })

  it('disconnects the ResizeObserver on unmount', () => {
    const { unmount } = render(
      <div>
        <PipelineCanvas />
      </div>,
    )
    unmount()
    expect(disconnectSpy).toHaveBeenCalled()
  })

  it('accepts paused / intensity / onCounters props without crashing', () => {
    const onCounters = vi.fn()
    const { unmount } = render(
      <div>
        <PipelineCanvas paused intensity={3} onCounters={onCounters} />
      </div>,
    )
    expect(screen.getByTestId('pipeline-canvas')).toBeInTheDocument()
    unmount()
  })

  it('registers and removes a visibilitychange listener around its lifecycle', () => {
    const addSpy = vi.spyOn(document, 'addEventListener')
    const removeSpy = vi.spyOn(document, 'removeEventListener')
    const { unmount } = render(<PipelineCanvas />)
    expect(
      addSpy.mock.calls.some(([type]) => type === 'visibilitychange'),
    ).toBe(true)
    unmount()
    expect(
      removeSpy.mock.calls.some(([type]) => type === 'visibilitychange'),
    ).toBe(true)
  })
})
