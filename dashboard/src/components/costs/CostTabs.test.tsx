import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { CostTabs } from './CostTabs'

describe('CostTabs', () => {
  it('renders three tabs with counts on per-agent and per-team only', () => {
    render(<CostTabs value="agents" onChange={vi.fn()} agentCount={4} teamCount={2} />)

    expect(screen.getByTestId('costs-tab-agents')).toHaveTextContent('Per-agent4')
    expect(screen.getByTestId('costs-tab-teams')).toHaveTextContent('Per-team2')
    // Budget tree carries no count (hierarchy, not a flat row set).
    expect(screen.getByTestId('costs-tab-tree')).toHaveTextContent('Budget tree')
    expect(screen.getByTestId('costs-tab-tree').querySelector('.costs-tab__count')).toBeNull()
  })

  it('marks the active tab via aria-selected', () => {
    render(<CostTabs value="teams" onChange={vi.fn()} agentCount={4} teamCount={2} />)
    expect(screen.getByTestId('costs-tab-teams')).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('costs-tab-agents')).toHaveAttribute('aria-selected', 'false')
  })

  it('emits the selected tab on click', async () => {
    const onChange = vi.fn()
    render(<CostTabs value="agents" onChange={onChange} agentCount={4} teamCount={2} />)

    await userEvent.click(screen.getByTestId('costs-tab-tree'))
    expect(onChange).toHaveBeenCalledWith('tree')
  })
})
