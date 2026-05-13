import type { Approval } from './api'
import { getUrgency, type Urgency } from './urgency'

export interface ApprovalsFilter {
  agent: string
  team: string
  action: string
  urgency: '' | Urgency
}

export const EMPTY_FILTER: ApprovalsFilter = { agent: '', team: '', action: '', urgency: '' }

export interface ApprovalsFilterBarProps {
  filter: ApprovalsFilter
  onChange: (next: ApprovalsFilter) => void
  options: {
    agents: string[]
    teams: string[]
    actions: string[]
  }
}

const SELECT_STYLE = {
  padding: '0.25rem 0.5rem',
  border: '1px solid var(--line)',
  borderRadius: '0.25rem',
  background: 'var(--paper-2)',
  fontSize: '0.875rem',
} as const

export function ApprovalsFilterBar({ filter, onChange, options }: ApprovalsFilterBarProps) {
  function update<K extends keyof ApprovalsFilter>(key: K, value: ApprovalsFilter[K]) {
    onChange({ ...filter, [key]: value })
  }

  const isActive = filter.agent !== '' || filter.team !== '' || filter.action !== '' || filter.urgency !== ''

  return (
    <div
      data-testid="approvals-filter-bar"
      style={{
        display: 'flex',
        gap: '0.5rem',
        alignItems: 'center',
        marginBottom: '0.75rem',
        fontSize: '0.875rem',
        color: 'var(--ink-3)',
      }}
    >
      <label>
        Agent
        <select
          data-testid="filter-agent"
          value={filter.agent}
          onChange={(e) => update('agent', e.target.value)}
          style={{ ...SELECT_STYLE, marginLeft: '0.25rem' }}
        >
          <option value="">All</option>
          {options.agents.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
      </label>

      <label>
        Team
        <select
          data-testid="filter-team"
          value={filter.team}
          onChange={(e) => update('team', e.target.value)}
          style={{ ...SELECT_STYLE, marginLeft: '0.25rem' }}
        >
          <option value="">All</option>
          {options.teams.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </label>

      <label>
        Action
        <select
          data-testid="filter-action"
          value={filter.action}
          onChange={(e) => update('action', e.target.value)}
          style={{ ...SELECT_STYLE, marginLeft: '0.25rem' }}
        >
          <option value="">All</option>
          {options.actions.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
      </label>

      <label>
        Urgency
        <select
          data-testid="filter-urgency"
          value={filter.urgency}
          onChange={(e) => update('urgency', e.target.value as ApprovalsFilter['urgency'])}
          style={{ ...SELECT_STYLE, marginLeft: '0.25rem' }}
        >
          <option value="">All</option>
          <option value="high">High (&lt; 1h)</option>
          <option value="medium">Medium (&lt; 6h)</option>
          <option value="low">Low (&ge; 6h)</option>
        </select>
      </label>

      {isActive && (
        <button
          data-testid="filter-clear"
          onClick={() => onChange(EMPTY_FILTER)}
          style={{
            padding: '0.25rem 0.5rem',
            border: '1px solid var(--line)',
            borderRadius: '0.25rem',
            background: 'var(--paper-2)',
            color: 'var(--ink-2)',
            cursor: 'pointer',
            fontSize: '0.75rem',
          }}
        >
          Clear filters
        </button>
      )}
    </div>
  )
}

export function deriveOptions(approvals: Approval[]): ApprovalsFilterBarProps['options'] {
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
