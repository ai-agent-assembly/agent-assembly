import './StatusChip.css'

export type FleetStatusKind = 'active' | 'idle' | 'suspended' | 'error'

interface StatusChipProps {
  status: string
}

// FleetStatusKind is a closed app union; `classify()` allow-list-guards the
// wire-supplied `status` string against it before this table is ever indexed
// — narrow-union Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const GLYPH: Record<FleetStatusKind, string> = {
  active: '●',
  idle: '○',
  suspended: '■',
  error: '✕',
}

const KNOWN: readonly FleetStatusKind[] = ['active', 'idle', 'suspended', 'error']

function classify(status: string): FleetStatusKind | 'unknown' {
  return (KNOWN as readonly string[]).includes(status) ? (status as FleetStatusKind) : 'unknown'
}

/**
 * Status chip matching the `StatusChip` helper in `design/v1/fleet.jsx`.
 * Renders the hi-fi glyph + label using the design-system colour tokens
 * (palette literals; design tokens land project-wide in AAASM-1048).
 */
export function StatusChip({ status }: Readonly<StatusChipProps>) {
  const kind = classify(status)
  const glyph = kind === 'unknown' ? '○' : GLYPH[kind]
  return (
    <span className={`fleet-status fleet-status--${kind}`} data-testid="fleet-status">
      <span aria-hidden="true">{glyph}</span>
      {status}
    </span>
  )
}
