export type RangeOption = '7d' | '30d' | '90d'

export interface FilterParams {
  range: RangeOption
  agents: string[]
  teams: string[]
}

const VALID_RANGES: RangeOption[] = ['7d', '30d', '90d']
const DEFAULT_RANGE: RangeOption = '7d'

export function encodeFilters(f: FilterParams): URLSearchParams {
  const params = new URLSearchParams()
  params.set('range', f.range)
  if (f.agents.length > 0) params.set('agents', f.agents.join(','))
  if (f.teams.length > 0) params.set('teams', f.teams.join(','))
  return params
}

export function decodeFilters(params: URLSearchParams): FilterParams {
  const rawRange = params.get('range') as RangeOption | null
  const range: RangeOption =
    rawRange && VALID_RANGES.includes(rawRange) ? rawRange : DEFAULT_RANGE

  const agentsRaw = params.get('agents') ?? ''
  const teamsRaw = params.get('teams') ?? ''

  return {
    range,
    agents: agentsRaw ? agentsRaw.split(',').filter(Boolean) : [],
    teams: teamsRaw ? teamsRaw.split(',').filter(Boolean) : [],
  }
}
