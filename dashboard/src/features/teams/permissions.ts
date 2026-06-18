const TEAM_ADMIN_FLAG_KEY = 'aa_team_admin'

export function isTeamAdmin(): boolean {
  if (typeof globalThis === 'undefined') return false
  return globalThis.localStorage.getItem(TEAM_ADMIN_FLAG_KEY) === '1'
}

export function useCanManageTeam(): boolean {
  return isTeamAdmin()
}
