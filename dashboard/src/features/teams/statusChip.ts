/**
 * Agent-status → chip modifier token, keyed by the raw wire `AgentNode.status`
 * (no enum). Shared by the member row in {@link TeamMembersCard} and the orphan
 * row in {@link TeamOrphanDetail}, which carried byte-identical copies of this
 * table (AAASM-5232). Kept in its own module (not a card) so each card file
 * exports only its component (satisfies `react-refresh/only-export-components`).
 *
 * A `Map` rather than an object literal so a status that collides with an
 * inherited `Object.prototype` name (e.g. `"toString"`, `"constructor"`) misses
 * cleanly — `.get()` returns `undefined`, restoring the caller's `?? ''`
 * fallback rather than leaking a prototype member as a class name.
 */
const STATUS_CHIP = new Map<string, string>([
  ['active', 'is-ok'],
  ['suspended', 'is-warn'],
  ['deregistered', ''],
])

/** Chip modifier token for an agent status, or `undefined` for an unknown status. */
export function statusChip(status: string): string | undefined {
  return STATUS_CHIP.get(status)
}
