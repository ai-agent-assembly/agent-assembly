export type PresetRange = '24h' | '7d' | '30d' | '90d'
export type RangeOption = PresetRange | string  // custom: "YYYY-MM-DD..YYYY-MM-DD"

export interface FilterParams {
  range: RangeOption
  agents: string[]
  teams: string[]
}

export const PRESET_RANGES: PresetRange[] = ['24h', '7d', '30d', '90d']

const CUSTOM_RANGE_RE = /^\d{4}-\d{2}-\d{2}\.\.\d{4}-\d{2}-\d{2}$/
const DEFAULT_RANGE: PresetRange = '7d'

export function isPresetRange(r: string): r is PresetRange {
  return (PRESET_RANGES as string[]).includes(r)
}

export function isCustomRange(r: string): boolean {
  return CUSTOM_RANGE_RE.test(r)
}

export function encodeFilters(f: FilterParams): URLSearchParams {
  const params = new URLSearchParams()
  params.set('range', f.range)
  if (f.agents.length > 0) params.set('agents', f.agents.join(','))
  if (f.teams.length > 0) params.set('teams', f.teams.join(','))
  return params
}

export function decodeFilters(params: URLSearchParams): FilterParams {
  const rawRange = params.get('range') ?? ''
  let range: RangeOption = DEFAULT_RANGE
  if (isPresetRange(rawRange)) {
    range = rawRange
  } else if (isCustomRange(rawRange)) {
    range = rawRange
  }

  const agentsRaw = params.get('agents') ?? ''
  const teamsRaw = params.get('teams') ?? ''

  return {
    range,
    agents: agentsRaw ? agentsRaw.split(',').filter(Boolean) : [],
    teams: teamsRaw ? teamsRaw.split(',').filter(Boolean) : [],
  }
}
