import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ApprovalsFilterBar } from './ApprovalsFilterBar'
import { EMPTY_FILTER, type ApprovalsFilterOptions } from './filter'

const OPTIONS: ApprovalsFilterOptions = {
  agents: ['agent-a', 'agent-b'],
  teams: ['team-x'],
  actions: ['file.write', 'net.request'],
}

function setup(filter = EMPTY_FILTER) {
  const onChange = vi.fn()
  render(<ApprovalsFilterBar filter={filter} onChange={onChange} options={OPTIONS} />)
  return { onChange }
}

describe('ApprovalsFilterBar', () => {
  it('renders the option lists for each select', () => {
    setup()
    expect(screen.getByTestId('approvals-filter-bar')).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'agent-a' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'team-x' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'file.write' })).toBeInTheDocument()
  })

  it('emits an updated filter when the agent select changes', () => {
    const { onChange } = setup()
    fireEvent.change(screen.getByTestId('filter-agent'), { target: { value: 'agent-b' } })
    expect(onChange).toHaveBeenCalledWith({ ...EMPTY_FILTER, agent: 'agent-b' })
  })

  it('emits an updated filter for team, action, and urgency', () => {
    const { onChange } = setup()
    fireEvent.change(screen.getByTestId('filter-team'), { target: { value: 'team-x' } })
    expect(onChange).toHaveBeenCalledWith({ ...EMPTY_FILTER, team: 'team-x' })

    fireEvent.change(screen.getByTestId('filter-action'), { target: { value: 'file.write' } })
    expect(onChange).toHaveBeenCalledWith({ ...EMPTY_FILTER, action: 'file.write' })

    fireEvent.change(screen.getByTestId('filter-urgency'), { target: { value: 'high' } })
    expect(onChange).toHaveBeenCalledWith({ ...EMPTY_FILTER, urgency: 'high' })
  })

  it('hides the clear button when no filter is active', () => {
    setup()
    expect(screen.queryByTestId('filter-clear')).not.toBeInTheDocument()
  })

  it('shows the clear button when a filter is active and resets to empty on click', () => {
    const { onChange } = setup({ ...EMPTY_FILTER, agent: 'agent-a' })
    const clear = screen.getByTestId('filter-clear')
    expect(clear).toBeInTheDocument()
    fireEvent.click(clear)
    expect(onChange).toHaveBeenCalledWith(EMPTY_FILTER)
  })
})
