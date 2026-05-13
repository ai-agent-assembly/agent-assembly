import type { Approval } from './api'
import { getUrgency, type Urgency } from './urgency'

export interface ApprovalsFilter {
  agent: string
  team: string
  action: string
  urgency: '' | Urgency
}

export const EMPTY_FILTER: ApprovalsFilter = { agent: '', team: '', action: '', urgency: '' }

export interface ApprovalsFilterOptions {
  agents: string[]
  teams: string[]
  actions: string[]
}

export function deriveOptions(approvals: Approval[]): ApprovalsFilterOptions {
  const agents = new Set<string>()
  const teams = new Set<string>()
  const actions = new Set<string>()
  for (const a of approvals) {
    if (a.agent_id) agents.add(a.agent_id)
    if (a.team_id) teams.add(a.team_id)
    if (a.action) actions.add(a.action)
  }
  return {
    agents: [...agents].sort(),
    teams: [...teams].sort(),
    actions: [...actions].sort(),
  }
}

export function applyFilter(approvals: Approval[], filter: ApprovalsFilter, now: number = Date.now()): Approval[] {
  return approvals.filter((a) => {
    if (filter.agent && a.agent_id !== filter.agent) return false
    if (filter.team && a.team_id !== filter.team) return false
    if (filter.action && a.action !== filter.action) return false
    if (filter.urgency && getUrgency(a.created_at, now) !== filter.urgency) return false
    return true
  })
}
