export type GroupBy = 'agent' | 'team' | 'model'

export const GROUP_BY_OPTIONS: { value: GroupBy; label: string }[] = [
  { value: 'agent', label: 'Agent' },
  { value: 'team',  label: 'Team' },
  { value: 'model', label: 'Model' },
]

export const DEFAULT_GROUP_BY: GroupBy = 'agent'

const VALID_GROUP_BY = new Set<string>(['agent', 'team', 'model'])

export function decodeCostBy(params: URLSearchParams): GroupBy {
  const raw = params.get('costBy') ?? ''
  return VALID_GROUP_BY.has(raw) ? (raw as GroupBy) : DEFAULT_GROUP_BY
}
