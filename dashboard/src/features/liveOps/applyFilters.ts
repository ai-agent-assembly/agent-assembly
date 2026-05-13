import type { LiveOperation, LiveOpsFilters } from './types'

/**
 * AND-combine every set filter axis against each operation. `null` /
 * `undefined` on an axis is treated as "no filter on this axis".
 *
 * Pure function — extracted from `LiveOpsPage` so it can be unit-tested
 * without rendering. Wiring lands in AAASM-1332 (feed → ops list).
 */
export function applyFilters(
  ops: ReadonlyArray<LiveOperation>,
  filters: LiveOpsFilters,
): LiveOperation[] {
  return ops.filter((op) => matchesAll(op, filters))
}

function matchesAll(op: LiveOperation, f: LiveOpsFilters): boolean {
  if (isSet(f.agent) && op.agent !== f.agent) return false
  if (isSet(f.team) && op.team !== f.team) return false
  if (isSet(f.opType) && op.opType !== f.opType) return false
  if (isSet(f.status) && op.status !== f.status) return false
  return true
}

function isSet<T>(value: T | null | undefined): value is T {
  return value !== null && value !== undefined && value !== ''
}
