import { act, render, screen } from '@testing-library/react'
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

/**
 * jsdom does not implement the Canvas 2D API, so the draw calls themselves
 * cannot be asserted. These tests instead exercise the *simulation* logic by
 * supplying a recording 2D-context stub and stepping the rAF loop manually:
 * the spawn cadence, the per-phase `advance*` helpers, particle removal, and
 * the `emitCounters` readout are all real code paths driven here. The actual
 * pixel output (fillRect/arc/etc.) is genuinely un-unit-testable in jsdom and
 * is left to the visual story / e2e layer.
 */
describe('PipelineCanvas — simulation loop', () => {
  let rafCallbacks: FrameRequestCallback[]
  let getContextSpy: ReturnType<typeof vi.spyOn>

  function makeCtxStub() {
    return {
      setTransform: vi.fn(),
      clearRect: vi.fn(),
      fillRect: vi.fn(),
      strokeRect: vi.fn(),
      fillText: vi.fn(),
      beginPath: vi.fn(),
      arc: vi.fn(),
      fill: vi.fn(),
      stroke: vi.fn(),
      fillStyle: '',
      strokeStyle: '',
      lineWidth: 0,
      globalAlpha: 1,
      font: '',
      textAlign: '',
      textBaseline: '',
    } as unknown as CanvasRenderingContext2D
  }

  // Step the single live rAF callback with a given timestamp. The component
  // re-requests a frame on each call, so we always invoke the latest one.
  function step(ts: number) {
    const cb = rafCallbacks[rafCallbacks.length - 1]
    act(() => {
      cb(ts)
    })
  }

  beforeEach(() => {
    rafCallbacks = []
    globalThis.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver
    getContextSpy = vi
      .spyOn(HTMLCanvasElement.prototype, 'getContext')
      .mockImplementation(() => makeCtxStub() as unknown as null)
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => {
      rafCallbacks.push(cb)
      return rafCallbacks.length
    })
    vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('emits counters to the parent after enough simulated time elapses', () => {
    const onCounters = vi.fn()
    // Force every spawned particle to the "allow" fate (Math.random < 0.55).
    vi.spyOn(Math, 'random').mockReturnValue(0.1)

    render(
      <div>
        <PipelineCanvas onCounters={onCounters} intensity={5} />
      </div>,
    )
    expect(getContextSpy).toHaveBeenCalled()

    // Walk the loop across many frames. Each `step` is one rAF frame; the
    // virtual clock advances by 1ms per frame so dwell holds + spawn cadence
    // both progress and an "allow" particle can traverse all lanes to EXTERNAL.
    for (let ts = 0; ts <= 4000; ts += 1) {
      step(ts)
    }

    expect(onCounters).toHaveBeenCalled()
    const last = onCounters.mock.calls.at(-1)![0]
    expect(last).toEqual(
      expect.objectContaining({
        rpm: expect.any(Number),
        allow: expect.any(Number),
        narrow: expect.any(Number),
        deny: expect.any(Number),
        scrub: expect.any(Number),
        approval: expect.any(Number),
      }),
    )
    // Spawning ran, so the request rate is positive.
    expect(last.rpm).toBeGreaterThan(0)
    // At least one allow particle should have completed the pipeline.
    expect(last.allow).toBeGreaterThan(0)
  })

  it('does not spawn new particles while paused', () => {
    const onCounters = vi.fn()
    vi.spyOn(Math, 'random').mockReturnValue(0.1)

    render(
      <div>
        <PipelineCanvas paused onCounters={onCounters} intensity={5} />
      </div>,
    )
    for (let ts = 0; ts <= 2000; ts += 100) {
      step(ts)
    }
    // Counters still emit, but with zero throughput because nothing spawned.
    expect(onCounters).toHaveBeenCalled()
    const last = onCounters.mock.calls.at(-1)![0]
    expect(last.allow).toBe(0)
    expect(last.rpm).toBe(0)
  })

  it('routes deny + identity-fail + approval + scrub fates without throwing', () => {
    const onCounters = vi.fn()
    // Sequence the fate picks: identity-fail, deny, approval, scrub, then allow.
    const fateValues = [0.99, 0.96, 0.9, 0.8, 0.1]
    let i = 0
    vi.spyOn(Math, 'random').mockImplementation(() => {
      const v = fateValues[i % fateValues.length]
      i += 1
      return v
    })

    expect(() => {
      render(
        <div>
          <PipelineCanvas onCounters={onCounters} intensity={5} />
        </div>,
      )
      for (let ts = 0; ts <= 6000; ts += 80) {
        step(ts)
      }
    }).not.toThrow()
    expect(onCounters).toHaveBeenCalled()
  })

  it('skips the frame body while the document is hidden but keeps the loop armed', () => {
    const onCounters = vi.fn()
    const hiddenSpy = vi
      .spyOn(document, 'hidden', 'get')
      .mockReturnValue(true)

    render(
      <div>
        <PipelineCanvas onCounters={onCounters} intensity={5} />
      </div>,
    )
    for (let ts = 0; ts <= 2000; ts += 100) {
      step(ts)
    }
    // Hidden → early-return before emitCounters, so nothing is reported.
    expect(onCounters).not.toHaveBeenCalled()
    // But the loop keeps re-requesting frames.
    expect(rafCallbacks.length).toBeGreaterThan(1)
    hiddenSpy.mockRestore()
  })
})
