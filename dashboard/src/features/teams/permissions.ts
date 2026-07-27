import { useCan } from '../../auth/usePermissions'

/**
 * Whether the current caller may manage a team (suspend/resume its members).
 *
 * Team management is an administrative, team-wide mutation. The token exposes
 * no dedicated team-admin scope (`Scope` is `read | write | admin`), so — per
 * AAASM-5253 — we do NOT synthesize one; we route the check through the same
 * verified scope machinery as every other gated control and require the
 * existing `admin` scope. This derives from the token/context (fail-closed:
 * absent or scope-less tokens yield no admin), never from client-writable
 * storage.
 */
export function useCanManageTeam(): boolean {
  return useCan('admin')
}
