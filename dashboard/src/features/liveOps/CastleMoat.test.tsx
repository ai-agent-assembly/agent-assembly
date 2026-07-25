import { act, render, screen } from '@testing-library/react'
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

/**
 * The ring/arrow draw code runs on a Canvas 2D context that jsdom does not
 * implement, so `getContext('2d')` is stubbed with a spy context and the rAF
 * loop is driven manually. This exercises `drawRings`, `spawn`,
 * `drawTravelling`, and `drawBurst` — the animation internals that are
 * otherwise unreachable under jsdom.
 */
describe('CastleMoat — draw loop', () => {
  let rafCallbacks: FrameRequestCallback[]
  let ctx: Record<string, unknown>

  function makeCtxStub() {
    return {
      setTransform: vi.fn(),
      clearRect: vi.fn(),
      fillRect: vi.fn(),
      fillText: vi.fn(),
      beginPath: vi.fn(),
      moveTo: vi.fn(),
      lineTo: vi.fn(),
      arc: vi.fn(),
      fill: vi.fn(),
      stroke: vi.fn(),
      setLineDash: vi.fn(),
      fillStyle: '',
      strokeStyle: '',
      lineWidth: 0,
      globalAlpha: 1,
      font: '',
      textAlign: '',
      textBaseline: '',
    }
  }

  // Step the latest live rAF callback; the component re-arms a frame each call.
  function step(ts: number) {
    const cb = rafCallbacks.at(-1)
    act(() => {
      cb?.(ts)
    })
  }

  beforeEach(() => {
    rafCallbacks = []
    ctx = makeCtxStub()
    globalThis.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(
      () => ctx as unknown as null,
    )
    vi.spyOn(globalThis, 'requestAnimationFrame').mockImplementation((cb) => {
      rafCallbacks.push(cb)
      return rafCallbacks.length
    })
    vi.spyOn(globalThis, 'cancelAnimationFrame').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('draws the concentric rings on the stubbed 2D context', () => {
    render(
      <div>
        <CastleMoat intensity={5} />
      </div>,
    )
    step(0)
    // Rings are filled + stroked every frame.
    expect(ctx.fill).toHaveBeenCalled()
    expect(ctx.stroke).toHaveBeenCalled()
    expect(ctx.fillText).toHaveBeenCalled()
  })

  it('spawns and animates arrows through travel and burst', () => {
    const { unmount } = render(
      <div>
        <CastleMoat intensity={5} />
      </div>,
    )
    // Each frame advances an arrow's progress by a fixed step, so enough frames
    // must run for a spawned arrow to traverse to its ring (travelling), burst,
    // and finally be spliced out — exercising all three arrow code paths.
    for (let frame = 0; frame <= 200; frame += 1) {
      step(frame * 100)
    }
    // Dashed strokes are only set while arrows travel; a burst re-strokes rings.
    expect(ctx.setLineDash).toHaveBeenCalled()
    expect(ctx.moveTo).toHaveBeenCalled()
    expect(ctx.lineTo).toHaveBeenCalled()
    // Cleanup cancels the pending frame.
    unmount()
  })

  it('keeps drawing rings but spawns no arrows while paused', () => {
    render(
      <div>
        <CastleMoat paused intensity={5} />
      </div>,
    )
    for (let ts = 0; ts <= 6000; ts += 200) {
      step(ts)
    }
    // Rings still render, but no travelling arrow means no line segments.
    expect(ctx.fill).toHaveBeenCalled()
    expect(ctx.moveTo).not.toHaveBeenCalled()
  })
})
