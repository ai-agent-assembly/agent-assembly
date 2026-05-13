import './TrustBar.css'

interface TrustBarProps {
  /** Trust score 0-100. `null` renders an em-dash placeholder. */
  score: number | null
}

function band(score: number): 'ok' | 'warn' | 'danger' {
  if (score >= 80) return 'ok'
  if (score >= 60) return 'warn'
  return 'danger'
}

/**
 * Colour-graded progress bar matching the `TrustBar` helper in
 * `design/v1/fleet.jsx`. Thresholds: ≥80 ok, ≥60 warn, otherwise danger.
 * A `null` score renders an em-dash so unwired analytics columns remain
 * visually inert.
 */
export function TrustBar({ score }: TrustBarProps) {
  if (score === null) {
    return (
      <span className="fleet-trust fleet-trust--empty" data-testid="fleet-trust">
        —
      </span>
    )
  }
  const clamped = Math.max(0, Math.min(100, score))
  const tone = band(clamped)
  return (
    <span className={`fleet-trust fleet-trust--${tone}`} data-testid="fleet-trust">
      <span className="fleet-trust__track">
        <span className="fleet-trust__fill" style={{ width: `${clamped}%` }} />
      </span>
      <span className="fleet-trust__value">{clamped}</span>
    </span>
  )
}
