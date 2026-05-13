import { useEffect, useRef } from 'react'
import './PipelineCanvas.css'

/**
 * Pipeline lane geometry — relative coordinates as fractions of the
 * canvas width. Mirrors `laneCols` in `design/v1/hi-fi/live-ops.jsx`
 * so the dashboard backdrop matches the hi-fi exactly. The lane fills
 * (`#fafaf7 / #fbf2dc / #f0e3f7`) sit slightly off the project token
 * palette by design — the hi-fi picked tinted papers that are softer
 * than `--paper-2 / --warn-bg / --scrub-bg`. Border + label colours
 * map to design tokens.
 */
interface Lane {
  id: 'agents' | 'l1' | 'l2' | 'l3' | 'ext'
  label: string
  /** Left edge as a fraction of the canvas width. */
  x: number
  /** Lane width as a fraction of the canvas width. */
  w: number
  fill: string
  gateHint?: string
  gateColor?: string
}

const LANES: readonly Lane[] = [
  { id: 'agents', label: 'AGENTS', x: 0.04, w: 0.1, fill: '#fafaf7' },
  {
    id: 'l1',
    label: 'L1 · IDENTITY',
    x: 0.22,
    w: 0.13,
    fill: '#fafaf7',
    gateHint: 'verify DID',
    gateColor: '#1a1a1a',
  },
  {
    id: 'l2',
    label: 'L2 · CAPABILITY',
    x: 0.43,
    w: 0.13,
    fill: '#fbf2dc',
    gateHint: 'policy enforce',
    gateColor: '#8a5a00',
  },
  {
    id: 'l3',
    label: 'L3 · SCRUB',
    x: 0.64,
    w: 0.13,
    fill: '#f0e3f7',
    gateHint: 'sanitize',
    gateColor: '#5a1a8a',
  },
  { id: 'ext', label: '→ EXTERNAL', x: 0.85, w: 0.1, fill: '#fafaf7' },
]

const LANE_BORDER = '#d8d4c7'
const LANE_LABEL = '#5a5a5a'
const PADDING_Y = 28
const MIN_WIDTH = 400
const MIN_HEIGHT = 300

/**
 * Static pipeline backdrop for the Live Ops page (AAASM-1336). Renders
 * the AGENTS → L1 → L2 → L3 → EXTERNAL lanes with labels and gate
 * hints. Particle animation lands in AAASM-1338.
 */
export function PipelineCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    function draw() {
      if (!canvas || !ctx) return
      const dpr = window.devicePixelRatio || 1
      const parent = canvas.parentElement
      const rect = parent
        ? parent.getBoundingClientRect()
        : canvas.getBoundingClientRect()
      const w = Math.max(rect.width || MIN_WIDTH, MIN_WIDTH)
      const h = Math.max(rect.height || MIN_HEIGHT, MIN_HEIGHT)
      canvas.width = w * dpr
      canvas.height = h * dpr
      canvas.style.width = `${w}px`
      canvas.style.height = `${h}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

      ctx.clearRect(0, 0, w, h)

      // Lane backgrounds + borders
      LANES.forEach((lane) => {
        const x = lane.x * w
        const lw = lane.w * w
        ctx.fillStyle = lane.fill
        ctx.fillRect(x, PADDING_Y, lw, h - PADDING_Y * 2)
        ctx.strokeStyle = LANE_BORDER
        ctx.lineWidth = 1
        ctx.strokeRect(x, PADDING_Y, lw, h - PADDING_Y * 2)
      })

      // Lane labels at the top
      ctx.fillStyle = LANE_LABEL
      ctx.font = '9px "JetBrains Mono", ui-monospace, monospace'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'alphabetic'
      LANES.forEach((lane) => {
        ctx.fillText(lane.label, (lane.x + lane.w / 2) * w, 18)
      })

      // Gate hints inside L1 / L2 / L3
      ctx.font = '10px Inter, system-ui, sans-serif'
      ctx.textBaseline = 'middle'
      LANES.forEach((lane) => {
        if (!lane.gateHint) return
        ctx.fillStyle = lane.gateColor ?? LANE_LABEL
        ctx.fillText(lane.gateHint, (lane.x + lane.w / 2) * w, 50)
      })
    }

    draw()

    // Re-measure after layout settles. Mirrors the hi-fi's two delayed
    // redraws so the canvas catches its real size on first paint.
    const t1 = setTimeout(draw, 50)
    const t2 = setTimeout(draw, 250)

    let observer: ResizeObserver | null = null
    if (typeof ResizeObserver !== 'undefined' && canvas.parentElement) {
      observer = new ResizeObserver(draw)
      observer.observe(canvas.parentElement)
    }

    return () => {
      clearTimeout(t1)
      clearTimeout(t2)
      observer?.disconnect()
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className="pipeline-canvas"
      data-testid="pipeline-canvas"
      role="img"
      aria-label="Live Ops pipeline: agents flow through L1 identity, L2 capability, L3 scrub gates to external systems"
    />
  )
}
