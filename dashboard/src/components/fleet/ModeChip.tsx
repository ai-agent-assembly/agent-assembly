import './ModeChip.css'
import type { FleetMode } from '../../features/agents/fleetTypes'

interface ModeChipProps {
  mode: FleetMode
}

const GLYPH: Record<FleetMode, string> = {
  enforce: '●',
  shadow: '◐',
  off: '○',
}

/**
 * Enforcement-mode chip matching the `ModeChip` helper in
 * `design/v1/fleet.jsx`. `enforce` uses the OK token, `shadow` uses
 * warn, `off` uses the neutral muted token.
 */
export function ModeChip({ mode }: ModeChipProps) {
  return (
    <span className={`fleet-mode fleet-mode--${mode}`} data-testid="fleet-mode">
      <span aria-hidden="true">{GLYPH[mode]}</span>
      {mode}
    </span>
  )
}
