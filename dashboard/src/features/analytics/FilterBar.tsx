import { useState, type ChangeEvent } from 'react'
import { PRESET_RANGES, isCustomRange, type FilterParams, type PresetRange } from './urlState'
import type { Agent } from '../agents/api'
import type { TeamSummary } from './useTeamsQuery'

interface FilterBarProps {
  filters: FilterParams
  onFiltersChange: (patch: Partial<FilterParams>) => void
  agents?: Agent[]
  teams?: TeamSummary[]
  isLoadingAgents?: boolean
  isLoadingTeams?: boolean
}

const RANGE_LABELS: Record<string, string> = {
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
  '90d': 'Last 90 days',
}

function parseCustomRange(range: string): [string, string] {
  const [start = '', end = ''] = range.split('..')
  return [start, end]
}

export function FilterBar({
  filters,
  onFiltersChange,
  agents = [],
  teams = [],
  isLoadingAgents = false,
  isLoadingTeams = false,
}: FilterBarProps) {
  const isCurrentlyCustom = isCustomRange(filters.range)
  const [showCustom, setShowCustom] = useState(isCurrentlyCustom)
  const [customStart, setCustomStart] = useState(
    isCurrentlyCustom ? parseCustomRange(filters.range)[0] : '',
  )
  const [customEnd, setCustomEnd] = useState(
    isCurrentlyCustom ? parseCustomRange(filters.range)[1] : '',
  )

  function handleRangeSelect(e: ChangeEvent<HTMLSelectElement>) {
    const value = e.target.value
    if (value === 'custom') {
      setShowCustom(true)
    } else {
      setShowCustom(false)
      onFiltersChange({ range: value as PresetRange })
    }
  }

  function handleCustomStart(e: ChangeEvent<HTMLInputElement>) {
    const start = e.target.value
    setCustomStart(start)
    if (start && customEnd) {
      onFiltersChange({ range: `${start}..${customEnd}` })
    }
  }

  function handleCustomEnd(e: ChangeEvent<HTMLInputElement>) {
    const end = e.target.value
    setCustomEnd(end)
    if (customStart && end) {
      onFiltersChange({ range: `${customStart}..${end}` })
    }
  }

  function handleAgentChange(e: ChangeEvent<HTMLSelectElement>) {
    const selected = Array.from(e.target.selectedOptions).map(o => o.value)
    onFiltersChange({ agents: selected })
  }

  function handleTeamChange(e: ChangeEvent<HTMLSelectElement>) {
    const selected = Array.from(e.target.selectedOptions).map(o => o.value)
    onFiltersChange({ teams: selected })
  }

  const rangeSelectValue = isCurrentlyCustom || showCustom ? 'custom' : filters.range

  return (
    <div
      className="analytics-filter-bar"
      role="search"
      aria-label="Analytics filters"
      data-testid="analytics-filter-bar"
    >
      <div className="analytics-filter-bar__group">
        <label htmlFor="analytics-range" className="analytics-filter-bar__label">
          Time range
        </label>
        <select
          id="analytics-range"
          className="analytics-filter-bar__select"
          value={rangeSelectValue}
          onChange={handleRangeSelect}
          data-testid="filter-range"
        >
          {PRESET_RANGES.map(r => (
            <option key={r} value={r}>
              {RANGE_LABELS[r]}
            </option>
          ))}
          <option value="custom">Custom range</option>
        </select>
        {(isCurrentlyCustom || showCustom) && (
          <div className="analytics-filter-bar__custom-range">
            <input
              type="date"
              aria-label="Range start date"
              className="analytics-filter-bar__date-input"
              value={customStart}
              onChange={handleCustomStart}
            />
            <span aria-hidden>–</span>
            <input
              type="date"
              aria-label="Range end date"
              className="analytics-filter-bar__date-input"
              value={customEnd}
              onChange={handleCustomEnd}
            />
          </div>
        )}
      </div>

      <div className="analytics-filter-bar__group">
        <label htmlFor="analytics-agents" className="analytics-filter-bar__label">
          Agents
        </label>
        <select
          id="analytics-agents"
          multiple
          className="analytics-filter-bar__select analytics-filter-bar__select--multi"
          value={filters.agents}
          onChange={handleAgentChange}
          disabled={isLoadingAgents}
          data-testid="filter-agents"
        >
          {agents.map(a => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </div>

      <div className="analytics-filter-bar__group">
        <label htmlFor="analytics-teams" className="analytics-filter-bar__label">
          Teams
        </label>
        <select
          id="analytics-teams"
          multiple
          className="analytics-filter-bar__select analytics-filter-bar__select--multi"
          value={filters.teams}
          onChange={handleTeamChange}
          disabled={isLoadingTeams}
          data-testid="filter-teams"
        >
          {teams.map(t => (
            <option key={t.team_id} value={t.team_id}>
              {t.team_id}
            </option>
          ))}
        </select>
      </div>
    </div>
  )
}
