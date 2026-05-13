import type { EffectivePermission, InheritanceKind } from './types'

export function groupBySourceKind(
  permissions: readonly EffectivePermission[],
): Record<InheritanceKind, EffectivePermission[]> {
  const grouped: Record<InheritanceKind, EffectivePermission[]> = {
    team: [],
    role: [],
    policy: [],
  }
  for (const p of permissions) {
    grouped[p.source.kind].push(p)
  }
  return grouped
}
