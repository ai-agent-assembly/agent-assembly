import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { FilterBar, type FilterOption } from './FilterBar'
import { EMPTY_FILTERS, type LiveOpsFilters } from './types'

const AGENTS: FilterOption[] = [
  { id: 'support-agent' },
  { id: 'deploy-agent' },
]
const TEAMS: FilterOption[] = [{ id: 'support' }, { id: 'devops' }]

function ControlledHarness({
  initial = EMPTY_FILTERS,
  onChange,
}: {
  initial?: LiveOpsFilters
  onChange?: (next: LiveOpsFilters) => void
}) {
  const [filters, setFilters] = useState<LiveOpsFilters>(initial)
  return (
    <FilterBar
      filters={filters}
      onFiltersChange={(next) => {
        setFilters(next)
        onChange?.(next)
      }}
      agentOptions={AGENTS}
      teamOptions={TEAMS}
    />
  )
}

describe('FilterBar', () => {
  it('renders all four filter selects and the reset button', () => {
    render(<ControlledHarness />)
    expect(screen.getByTestId('filter-agent')).toBeInTheDocument()
    expect(screen.getByTestId('filter-team')).toBeInTheDocument()
    expect(screen.getByTestId('filter-op-type')).toBeInTheDocument()
    expect(screen.getByTestId('filter-status')).toBeInTheDocument()
    expect(screen.getByTestId('filter-reset')).toBeDisabled()
  })

  it('emits onFiltersChange with the next agent selection', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<ControlledHarness onChange={onChange} />)
    await user.selectOptions(screen.getByTestId('filter-agent'), 'support-agent')
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ agent: 'support-agent' }),
    )
  })

  it('clears a filter when the user picks "All"', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <ControlledHarness
        initial={{ ...EMPTY_FILTERS, agent: 'support-agent' }}
        onChange={onChange}
      />,
    )
    await user.selectOptions(screen.getByTestId('filter-agent'), '')
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ agent: null }),
    )
  })

  it('enables the reset button when any filter is set, and clears all on click', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <ControlledHarness
        initial={{
          agent: 'support-agent',
          team: 'support',
          opType: 'read',
          status: 'running',
        }}
        onChange={onChange}
      />,
    )
    const reset = screen.getByTestId('filter-reset')
    expect(reset).not.toBeDisabled()
    await user.click(reset)
    expect(onChange).toHaveBeenLastCalledWith(EMPTY_FILTERS)
  })

  it('uses the default verb list when opTypeOptions is omitted', () => {
    render(<ControlledHarness />)
    const opType = screen.getByTestId('filter-op-type')
    const labels = Array.from(opType.querySelectorAll('option')).map((o) => o.value)
    expect(labels).toEqual(['', 'read', 'write', 'delete', 'exec'])
  })
})
