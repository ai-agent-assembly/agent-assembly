import { useId } from 'react'
import {
  EMPTY_FILTERS,
  OPERATION_STATUSES,
  type LiveOpsFilters,
  type OperationStatus,
} from './types'
import './FilterBar.css'

export interface FilterOption {
  /** Underlying filter value sent through `onFiltersChange`. */
  id: string
  /** Human label shown in the dropdown. Defaults to `id` when omitted. */
  label?: string
}

interface FilterBarProps {
  filters: LiveOpsFilters
  onFiltersChange: (next: LiveOpsFilters) => void
  agentOptions: ReadonlyArray<FilterOption>
  teamOptions: ReadonlyArray<FilterOption>
  /** Optional verb whitelist; defaults to the hi-fi event-stream verbs. */
  opTypeOptions?: ReadonlyArray<string>
}

const DEFAULT_OP_TYPES = ['read', 'write', 'delete', 'exec'] as const

const STATUS_LABEL: Record<OperationStatus, string> = {
  running: 'Running',
  pending: 'Pending',
  blocked: 'Blocked',
  completing: 'Completing',
  terminated: 'Terminated',
}

/**
 * Four-axis filter UI for the Live Ops event-stream zone. Pure
 * presentation: receives options + filter state via props and calls
 * `onFiltersChange` with the next filter set on every change. Use
 * `applyFilters` from the same module to project the stream through
 * the active filter set; wiring lands in AAASM-1332.
 */
export function FilterBar({
  filters,
  onFiltersChange,
  agentOptions,
  teamOptions,
  opTypeOptions = DEFAULT_OP_TYPES,
}: FilterBarProps) {
  const agentId = useId()
  const teamId = useId()
  const opTypeId = useId()
  const statusId = useId()

  const hasActiveFilter = Boolean(
    filters.agent || filters.team || filters.opType || filters.status,
  )

  const set = <K extends keyof LiveOpsFilters>(key: K, value: LiveOpsFilters[K]) =>
    onFiltersChange({ ...filters, [key]: value })

  return (
    <div className="live-ops-filter-bar" data-testid="live-ops-filter-bar">
      <div className="live-ops-filter-bar__field">
        <label className="live-ops-filter-bar__label" htmlFor={agentId}>
          Agent
        </label>
        <select
          id={agentId}
          className="live-ops-filter-bar__select"
          data-testid="filter-agent"
          value={filters.agent ?? ''}
          onChange={(e) => set('agent', e.target.value || null)}
        >
          <option value="">All</option>
          {agentOptions.map((o) => (
            <option key={o.id} value={o.id}>
              {o.label ?? o.id}
            </option>
          ))}
        </select>
      </div>

      <div className="live-ops-filter-bar__field">
        <label className="live-ops-filter-bar__label" htmlFor={teamId}>
          Team
        </label>
        <select
          id={teamId}
          className="live-ops-filter-bar__select"
          data-testid="filter-team"
          value={filters.team ?? ''}
          onChange={(e) => set('team', e.target.value || null)}
        >
          <option value="">All</option>
          {teamOptions.map((o) => (
            <option key={o.id} value={o.id}>
              {o.label ?? o.id}
            </option>
          ))}
        </select>
      </div>

      <div className="live-ops-filter-bar__field">
        <label className="live-ops-filter-bar__label" htmlFor={opTypeId}>
          Op type
        </label>
        <select
          id={opTypeId}
          className="live-ops-filter-bar__select"
          data-testid="filter-op-type"
          value={filters.opType ?? ''}
          onChange={(e) => set('opType', e.target.value || null)}
        >
          <option value="">All</option>
          {opTypeOptions.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </div>

      <div className="live-ops-filter-bar__field">
        <label className="live-ops-filter-bar__label" htmlFor={statusId}>
          Status
        </label>
        <select
          id={statusId}
          className="live-ops-filter-bar__select"
          data-testid="filter-status"
          value={filters.status ?? ''}
          onChange={(e) =>
            set('status', (e.target.value || null) as OperationStatus | null)
          }
        >
          <option value="">All</option>
          {OPERATION_STATUSES.map((s) => (
            <option key={s} value={s}>
              {STATUS_LABEL[s]}
            </option>
          ))}
        </select>
      </div>

      <button
        type="button"
        className="live-ops-filter-bar__reset"
        data-testid="filter-reset"
        disabled={!hasActiveFilter}
        onClick={() => onFiltersChange(EMPTY_FILTERS)}
      >
        Reset
      </button>
    </div>
  )
}
