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

// Synonyms the wire emits for one of the known kinds. The fleet registry and
// `GET /api/v1/fleet/active-sessions` both live behind this chip, and the
// sessions endpoint reports a live session as `running` where the fleet uses
// `active`. Aliasing it here maps the *tone* (active-green glyph) without
// widening the agent `FleetStatusKind` vocabulary — a session that is running
// still reads "running", it just no longer falls into the grey unknown bucket
// (AAASM-5172).
const ALIAS: Readonly<Record<string, FleetStatusKind>> = {
  running: 'active',
}

function classify(status: string): FleetStatusKind | 'unknown' {
  if ((KNOWN as readonly string[]).includes(status)) return status as FleetStatusKind
  return ALIAS[status] ?? 'unknown'
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
