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
})
