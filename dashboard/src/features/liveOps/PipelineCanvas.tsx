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

// ── Particle simulation ──────────────────────────────────────

type Fate = 'allow' | 'narrow' | 'scrub' | 'approval' | 'deny' | 'identity-fail'
type Phase =
  | 'to-l1'
  | 'in-l1'
  | 'to-l2'
  | 'in-l2'
  | 'to-l3'
  | 'in-l3'
  | 'to-ext'
  | 'stuck-l2'
  | 'blocked'

interface Particle {
  id: number
  y: number
  x: number
  phase: Phase
  fate: Fate
  age: number
  speed: number
  tEnter?: number
  stuckAt?: number
  blockedAt?: 'l1' | 'l2' | 'l3'
  fadeAge?: number
}

interface Counters {
  req: number
  allow: number
  narrow: number
  deny: number
  scrub: number
  approval: number
  t0: number
}

/** Aggregate counters emitted to the parent every ~500 ms. */
export interface PipelineCanvasCounters {
  rpm: number
  allow: number
  narrow: number
  deny: number
  scrub: number
  approval: number
}

export interface PipelineCanvasProps {
  /** When `true`, the rAF loop continues but spawns no new particles. */
  paused?: boolean
  /** Multiplier on the spawn cadence — higher = more particles per sec. */
  intensity?: number
  /** Counter readout emitted every ~500 ms. */
  onCounters?: (c: PipelineCanvasCounters) => void
}

function colorForFate(fate: Fate): string {
  switch (fate) {
    case 'allow':
      return '#1a1a1a'
    case 'narrow':
      return '#8a5a00'
    case 'scrub':
      return '#5a1a8a'
    case 'approval':
      return '#1d3a7a'
    case 'deny':
    case 'identity-fail':
      return '#b8291e'
  }
}

function pickFate(): Fate {
  const r = Math.random()
  if (r < 0.55) return 'allow'
  if (r < 0.75) return 'narrow'
  if (r < 0.85) return 'scrub'
  if (r < 0.95) return 'approval'
  if (r < 0.98) return 'deny'
  return 'identity-fail'
}

/**
 * Pipeline backdrop for the Live Ops page (AAASM-1336) with animated
 * particle flow (AAASM-1338). Particles spawn at the AGENTS lane and
 * flow AGENTS → L1 → L2 → L3 → EXTERNAL; `identity-fail` blocks at
 * L1, `deny` blocks at L2, `approval` collects in the L2 pool.
 *
 * The rAF loop pauses entirely while the document is hidden — the
 * browser already throttles rAF in that state, and the explicit
 * pause keeps the CPU usage at zero per the ticket DoD.
 */
export function PipelineCanvas({
  paused = false,
  intensity = 2,
  onCounters,
}: PipelineCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const pausedRef = useRef(paused)
  const intensityRef = useRef(intensity)
  const onCountersRef = useRef(onCounters)

  // Keep refs in sync so the long-lived rAF closure always sees the latest
  // props without resubscribing.
  useEffect(() => {
    pausedRef.current = paused
    intensityRef.current = intensity
    onCountersRef.current = onCounters
  })

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    let sizeW = MIN_WIDTH
    let sizeH = MIN_HEIGHT
    const particles: Particle[] = []
    const counters: Counters = {
      req: 0,
      allow: 0,
      narrow: 0,
      deny: 0,
      scrub: 0,
      approval: 0,
      t0: Date.now(),
    }
    let lastSpawn = 0
    let lastCounterEmit = 0
    let rafId: number | null = null

    function laneX(id: Lane['id']): number {
      const lane = LANES.find((l) => l.id === id)
      return lane ? lane.x * sizeW : 0
    }
    function laneCenterX(id: Lane['id']): number {
      const lane = LANES.find((l) => l.id === id)
      return lane ? (lane.x + lane.w / 2) * sizeW : 0
    }
    function laneRightX(id: Lane['id']): number {
      const lane = LANES.find((l) => l.id === id)
      return lane ? (lane.x + lane.w) * sizeW : 0
    }

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

    function drawBackdrop() {
      if (!ctx) return
      ctx.clearRect(0, 0, sizeW, sizeH)

      LANES.forEach((lane) => {
        const x = lane.x * sizeW
        const lw = lane.w * sizeW
        ctx.fillStyle = lane.fill
        ctx.fillRect(x, PADDING_Y, lw, sizeH - PADDING_Y * 2)
        ctx.strokeStyle = LANE_BORDER
        ctx.lineWidth = 1
        ctx.strokeRect(x, PADDING_Y, lw, sizeH - PADDING_Y * 2)
      })

      ctx.fillStyle = LANE_LABEL
      ctx.font = '9px "JetBrains Mono", ui-monospace, monospace'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'alphabetic'
      LANES.forEach((lane) => {
        ctx.fillText(lane.label, (lane.x + lane.w / 2) * sizeW, 18)
      })

      ctx.font = '10px Inter, system-ui, sans-serif'
      ctx.textBaseline = 'middle'
      LANES.forEach((lane) => {
        if (!lane.gateHint) return
        ctx.fillStyle = lane.gateColor ?? LANE_LABEL
        ctx.fillText(lane.gateHint, (lane.x + lane.w / 2) * sizeW, 50)
      })
    }

    function spawn(ts: number) {
      const minGap = 1100 / Math.max(intensityRef.current, 0.1)
      if (ts - lastSpawn < minGap) return
      lastSpawn = ts
      particles.push({
        id: Math.random(),
        y: 60 + Math.random() * (sizeH - 110),
        x: laneRightX('agents'),
        phase: 'to-l1',
        fate: pickFate(),
        age: 0,
        speed: 1.2 + Math.random() * 0.6,
      })
      counters.req += 1
    }

    function advance(p: Particle, ts: number): boolean {
      p.age += 1
      switch (p.phase) {
        case 'to-l1':
          p.x += p.speed
          if (p.x >= laneX('l1')) {
            p.x = laneX('l1')
            if (p.fate === 'identity-fail') {
              p.phase = 'blocked'
              p.blockedAt = 'l1'
              counters.deny += 1
            } else {
              p.phase = 'in-l1'
              p.tEnter = ts
            }
          }
          return true
        case 'in-l1':
          if (ts - (p.tEnter ?? ts) > 200) p.phase = 'to-l2'
          return true
        case 'to-l2':
          p.x += p.speed
          if (p.x >= laneX('l2')) {
            p.x = laneX('l2')
            if (p.fate === 'deny') {
              p.phase = 'blocked'
              p.blockedAt = 'l2'
              counters.deny += 1
            } else if (p.fate === 'approval') {
              p.phase = 'stuck-l2'
              p.stuckAt = ts
              counters.approval += 1
            } else {
              p.phase = 'in-l2'
              p.tEnter = ts
              if (p.fate === 'narrow') counters.narrow += 1
            }
          }
          return true
        case 'in-l2':
          if (ts - (p.tEnter ?? ts) > 200) p.phase = 'to-l3'
          return true
        case 'to-l3':
          p.x += p.speed
          if (p.x >= laneX('l3')) {
            p.x = laneX('l3')
            p.phase = 'in-l3'
            p.tEnter = ts
            if (p.fate === 'scrub') counters.scrub += 1
          }
          return true
        case 'in-l3':
          if (ts - (p.tEnter ?? ts) > 200) p.phase = 'to-ext'
          return true
        case 'to-ext':
          p.x += p.speed * 1.4
          if (p.x >= laneRightX('ext')) {
            counters.allow += 1
            return false
          }
          return true
        case 'stuck-l2':
          return ts - (p.stuckAt ?? ts) < 4500
        case 'blocked':
          p.fadeAge = (p.fadeAge ?? 0) + 1
          return (p.fadeAge ?? 0) <= 50
      }
    }

    function drawParticle(p: Particle, ts: number) {
      if (!ctx) return
      const color = colorForFate(p.fate)
      ctx.fillStyle = color
      ctx.globalAlpha =
        p.phase === 'blocked' ? Math.max(0, 1 - (p.fadeAge ?? 0) / 50) : 1

      if (p.phase === 'stuck-l2') {
        const cx = laneCenterX('l2')
        const cy = sizeH * 0.55
        const angle = (p.id * 9.7 + ts * 0.001) % (Math.PI * 2)
        const r = 12 + ((p.id * 13) % 10)
        ctx.beginPath()
        ctx.arc(
          cx + Math.cos(angle) * r,
          cy + Math.sin(angle) * r,
          2.5,
          0,
          Math.PI * 2,
        )
        ctx.fill()
      } else if (p.phase === 'blocked') {
        ctx.beginPath()
        ctx.arc(p.x, p.y, 3 + (p.fadeAge ?? 0) / 6, 0, Math.PI * 2)
        ctx.fill()
        ctx.globalAlpha = Math.max(0, 0.4 - (p.fadeAge ?? 0) / 60)
        ctx.strokeStyle = color
        ctx.lineWidth = 1.2
        ctx.beginPath()
        ctx.arc(p.x, p.y, 6 + (p.fadeAge ?? 0) / 3, 0, Math.PI * 2)
        ctx.stroke()
      } else {
        ctx.beginPath()
        ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2)
        ctx.fill()
        ctx.globalAlpha = 0.25
        ctx.beginPath()
        ctx.arc(p.x - 6, p.y, 1.5, 0, Math.PI * 2)
        ctx.fill()
        ctx.beginPath()
        ctx.arc(p.x - 12, p.y, 1, 0, Math.PI * 2)
        ctx.fill()
      }
      ctx.globalAlpha = 1
    }

    function emitCounters(ts: number) {
      const cb = onCountersRef.current
      if (!cb) return
      if (ts - lastCounterEmit < 500) return
      lastCounterEmit = ts
      const elapsedSec = (Date.now() - counters.t0) / 1000
      cb({
        rpm: Math.round((counters.req / Math.max(elapsedSec, 1)) * 60),
        allow: counters.allow,
        narrow: counters.narrow,
        deny: counters.deny,
        scrub: counters.scrub,
        approval: particles.filter((p) => p.phase === 'stuck-l2').length,
      })
    }

    function frame(ts: number) {
      // Pause when the document is hidden — browsers throttle rAF anyway, but
      // an explicit early-return keeps the CPU at zero (DoD #3).
      if (typeof document !== 'undefined' && document.hidden) {
        rafId = requestAnimationFrame(frame)
        return
      }

      if (!ctx) {
        rafId = requestAnimationFrame(frame)
        return
      }

      drawBackdrop()

      if (!pausedRef.current) {
        spawn(ts)
      }

      let i = 0
      while (i < particles.length) {
        const survived = advance(particles[i], ts)
        if (!survived) {
          particles.splice(i, 1)
          continue
        }
        drawParticle(particles[i], ts)
        i += 1
      }

      emitCounters(ts)

      rafId = requestAnimationFrame(frame)
    }

    resize()
    drawBackdrop()
    const t1 = setTimeout(() => {
      resize()
      drawBackdrop()
    }, 50)
    const t2 = setTimeout(() => {
      resize()
      drawBackdrop()
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
      // Resume by re-arming rAF if it had been cancelled (browser may have
      // suspended it). Cheap enough to re-request unconditionally.
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
      className="pipeline-canvas"
      data-testid="pipeline-canvas"
      role="img"
      aria-label="Live Ops pipeline: agents flow through L1 identity, L2 capability, L3 scrub gates to external systems"
    />
  )
}
