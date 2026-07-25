import { useEffect, useRef } from 'react'
import './CastleMoat.css'

/**
 * Alternate "castle moat" visualization for the Live Ops pipeline
 * (AAASM-5074), mirroring the `CastleMoat` component in
 * `design/v1/hi-fi/live-ops.jsx`. It is a client-side rendering of the SAME
 * simulated traffic the pipeline view animates — not a second data source:
 * requests arrive as arrows from the outer edge and are stopped at the ring
 * (defense layer) that governs them, with the crown jewels at the centre.
 *
 * Like `PipelineCanvas`, colours are stored as CSS custom-property NAMES and
 * resolved to hex at draw time via `getComputedStyle` because the Canvas 2D
 * API cannot read `var(--…)`. The rAF loop early-returns while the document
 * is hidden to keep CPU at zero.
 */
interface Ring {
  /** Radius as a fraction of `min(w, h)`. */
  rFrac: number
  fillVar: string
  label?: string
  /** When true, use the crown accent stroke instead of the default line. */
  crown?: boolean
}

const RINGS: readonly Ring[] = [
  { rFrac: 0.42, fillVar: '--lane-bg-default', label: 'L1 · IDENTITY' },
  { rFrac: 0.32, fillVar: '--paper-3', label: 'L2 · CAPABILITY' },
  { rFrac: 0.22, fillVar: '--lane-bg-scrub', label: 'L3 · SCRUB' },
  { rFrac: 0.12, fillVar: '--lane-bg-warn', crown: true },
]

const RING_BORDER_VAR = '--line'
const CROWN_ACCENT_VAR = '--warn'
const RING_LABEL_VAR = '--ink-3'
const MIN_WIDTH = 400
const MIN_HEIGHT = 400

type Fate = 'allow' | 'narrow' | 'scrub' | 'block' | 'identity-fail'

interface Arrow {
  id: number
  startX: number
  startY: number
  angle: number
  /** Radius at which the arrow stops (the governing ring). */
  stopR: number
  fate: Fate
  progress: number
  burstAge: number
}

function colorVarForFate(fate: Fate): string {
  switch (fate) {
    case 'allow':
      return '--ok'
    case 'narrow':
      return '--warn'
    case 'scrub':
      return '--scrub'
    case 'block':
    case 'identity-fail':
      return '--danger'
  }
}

/** Weighted fate + the ring index it is stopped at, matching the hi-fi. */
function pickArrow(): { fate: Fate; stopRing: number } {
  const r = Math.random()
  if (r < 0.45) return { fate: 'allow', stopRing: 0 }
  if (r < 0.65) return { fate: 'narrow', stopRing: 2 }
  if (r < 0.78) return { fate: 'scrub', stopRing: 2 }
  if (r < 0.9) return { fate: 'block', stopRing: 1 }
  return { fate: 'identity-fail', stopRing: 0 }
}

export interface CastleMoatProps {
  /** When `true`, the rAF loop continues but spawns no new arrows. */
  paused?: boolean
  /** Multiplier on the spawn cadence and arrow speed. */
  intensity?: number
}

export function CastleMoat({
  paused = false,
  intensity = 2,
}: Readonly<CastleMoatProps>) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const pausedRef = useRef(paused)
  const intensityRef = useRef(intensity)

  useEffect(() => {
    pausedRef.current = paused
    intensityRef.current = intensity
  })

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    const rootStyle = getComputedStyle(document.documentElement)
    const css = (varName: string): string =>
      rootStyle.getPropertyValue(varName).trim()

    let sizeW = MIN_WIDTH
    let sizeH = MIN_HEIGHT
    const arrows: Arrow[] = []
    let lastSpawn = 0
    let rafId: number | null = null

    function resize() {
      if (!canvas || !ctx) return
      const dpr = window.devicePixelRatio || 1
      const parent = canvas.parentElement
      const rect = parent
        ? parent.getBoundingClientRect()
        : canvas.getBoundingClientRect()
      sizeW = Math.max(rect.width || MIN_WIDTH, MIN_WIDTH)
      sizeH = Math.max(rect.height || MIN_HEIGHT, MIN_HEIGHT)
      canvas.width = sizeW * dpr
      canvas.height = sizeH * dpr
      canvas.style.width = `${sizeW}px`
      canvas.style.height = `${sizeH}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    function drawRings() {
      if (!ctx) return
      const cx = sizeW / 2
      const cy = sizeH / 2
      const unit = Math.min(sizeW, sizeH)
      ctx.clearRect(0, 0, sizeW, sizeH)

      const border = css(RING_BORDER_VAR)
      const crownAccent = css(CROWN_ACCENT_VAR)
      RINGS.forEach((ring) => {
        ctx.beginPath()
        ctx.arc(cx, cy, ring.rFrac * unit, 0, Math.PI * 2)
        ctx.fillStyle = css(ring.fillVar)
        ctx.fill()
        ctx.strokeStyle = ring.crown ? crownAccent : border
        ctx.lineWidth = ring.crown ? 1.5 : 1
        ctx.stroke()
      })

      ctx.fillStyle = css(RING_LABEL_VAR)
      ctx.font = '9px "JetBrains Mono", ui-monospace, monospace'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'alphabetic'
      RINGS.forEach((ring) => {
        if (!ring.label) return
        ctx.fillText(ring.label, cx, cy - ring.rFrac * unit + 12)
      })

      ctx.fillStyle = crownAccent
      ctx.font = '11px Inter, system-ui, sans-serif'
      ctx.textBaseline = 'middle'
      ctx.fillText('crown jewels', cx, cy - 6)
      ctx.fillStyle = css(RING_LABEL_VAR)
      ctx.font = '8px "JetBrains Mono", ui-monospace, monospace'
      ctx.fillText('customer-pii', cx, cy + 8)
    }

    function spawn(ts: number) {
      const minGap = 1400 / Math.max(intensityRef.current, 0.1)
      if (ts - lastSpawn < minGap) return
      lastSpawn = ts
      const cx = sizeW / 2
      const cy = sizeH / 2
      const unit = Math.min(sizeW, sizeH)
      const angle = Math.random() * Math.PI * 2
      const startR = unit * 0.49
      const { fate, stopRing } = pickArrow()
      arrows.push({
        id: Math.random(),
        startX: cx + Math.cos(angle) * startR,
        startY: cy + Math.sin(angle) * startR,
        angle,
        stopR: RINGS[stopRing].rFrac * unit,
        fate,
        progress: 0,
        burstAge: 0,
      })
    }

    function drawTravelling(a: Arrow): void {
      if (!ctx) return
      const cx = sizeW / 2
      const cy = sizeH / 2
      const startR = Math.min(sizeW, sizeH) * 0.49
      const distance = startR - a.stopR
      a.progress += 0.012 + intensityRef.current * 0.004
      const curR = startR - distance * Math.min(a.progress, 1)
      const x = cx + Math.cos(a.angle) * curR
      const y = cy + Math.sin(a.angle) * curR
      const color = css(colorVarForFate(a.fate))

      ctx.strokeStyle = color
      ctx.lineWidth = 2
      ctx.setLineDash(a.fate === 'allow' ? [] : [4, 2])
      ctx.beginPath()
      ctx.moveTo(a.startX, a.startY)
      ctx.lineTo(x, y)
      ctx.stroke()
      ctx.setLineDash([])

      ctx.fillStyle = color
      ctx.beginPath()
      ctx.arc(x, y, 3, 0, Math.PI * 2)
      ctx.fill()
      ctx.beginPath()
      ctx.arc(a.startX, a.startY, 3, 0, Math.PI * 2)
      ctx.fill()
    }

    function drawBurst(a: Arrow): boolean {
      if (!ctx) return false
      const cx = sizeW / 2
      const cy = sizeH / 2
      a.burstAge += 1
      const x = cx + Math.cos(a.angle) * a.stopR
      const y = cy + Math.sin(a.angle) * a.stopR
      const alpha = Math.max(0, 1 - a.burstAge / 30)
      ctx.globalAlpha = alpha
      ctx.strokeStyle = css(colorVarForFate(a.fate))
      ctx.lineWidth = 1.5
      ctx.beginPath()
      ctx.arc(x, y, 4 + a.burstAge / 2, 0, Math.PI * 2)
      ctx.stroke()
      ctx.beginPath()
      ctx.arc(x, y, 8 + a.burstAge, 0, Math.PI * 2)
      ctx.stroke()
      ctx.globalAlpha = 1
      return a.burstAge < 30
    }

    function frame(ts: number) {
      if (typeof document !== 'undefined' && document.hidden) {
        rafId = requestAnimationFrame(frame)
        return
      }
      if (!ctx) {
        rafId = requestAnimationFrame(frame)
        return
      }

      drawRings()
      if (!pausedRef.current) spawn(ts)

      let i = 0
      while (i < arrows.length) {
        const a = arrows[i]
        let survived: boolean
        if (a.progress < 1) {
          drawTravelling(a)
          survived = true
        } else {
          survived = drawBurst(a)
        }
        if (!survived) {
          arrows.splice(i, 1)
          continue
        }
        i += 1
      }

      rafId = requestAnimationFrame(frame)
    }

    resize()
    drawRings()
    const t1 = setTimeout(() => {
      resize()
      drawRings()
    }, 50)
    const t2 = setTimeout(() => {
      resize()
      drawRings()
    }, 250)

    rafId = requestAnimationFrame(frame)

    let observer: ResizeObserver | null = null
    if (typeof ResizeObserver !== 'undefined' && canvas.parentElement) {
      observer = new ResizeObserver(() => {
        resize()
      })
      observer.observe(canvas.parentElement)
    }

    function onVisibilityChange() {
      if (rafId === null && typeof document !== 'undefined' && !document.hidden) {
        rafId = requestAnimationFrame(frame)
      }
    }
    document.addEventListener('visibilitychange', onVisibilityChange)

    return () => {
      if (rafId !== null) cancelAnimationFrame(rafId)
      clearTimeout(t1)
      clearTimeout(t2)
      observer?.disconnect()
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className="castle-moat"
      data-testid="castle-moat"
      role="img"
      aria-label="Live Ops castle-moat: requests approach the crown jewels from outside and are stopped at the L1 identity, L2 capability, or L3 scrub ring that governs them"
    />
  )
}
