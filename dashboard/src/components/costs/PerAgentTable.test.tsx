import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { PerAgentTable } from './PerAgentTable'
import type { PerAgentRow } from '../../features/costs/perAgentRows'

const ROWS: readonly PerAgentRow[] = [
  { agentId: 'agent-top', team: 'team-hot', daily: 160, monthly: 3200, sharePct: 100 },
  { agentId: 'agent-mid', team: 'team-cool', daily: 80, monthly: 1600, sharePct: 50 },
  { agentId: 'agent-idle', team: null, daily: 0, monthly: null, sharePct: 0 },
]

describe('PerAgentTable', () => {
  it('renders agent / team / daily / monthly per row', () => {
    render(<PerAgentTable rows={ROWS} />)

    const top = screen.getByTestId('costs-agent-table').querySelector('[data-agent="agent-top"]')!
    expect(within(top as HTMLElement).getByText('agent-top')).toBeInTheDocument()
    expect(within(top as HTMLElement).getByText('team-hot')).toBeInTheDocument()
    expect(within(top as HTMLElement).getByText('$160.00')).toBeInTheDocument()
    expect(within(top as HTMLElement).getByText('$3200.00')).toBeInTheDocument()
  })

  it('renders a dash for unknown team and untracked monthly spend', () => {
    render(<PerAgentTable rows={ROWS} />)
    const idle = screen.getByTestId('costs-agent-table').querySelector('[data-agent="agent-idle"]') as HTMLElement
    // team dash + monthly dash → two em dashes in the row.
    expect(within(idle).getAllByText('—')).toHaveLength(2)
  })

  it('colours the top spender red and a mid spender amber by share of top', () => {
    render(<PerAgentTable rows={ROWS} />)
    const table = screen.getByTestId('costs-agent-table')
    const top = table.querySelector('[data-agent="agent-top"] .costs-agent-table__amount')!
    const mid = table.querySelector('[data-agent="agent-mid"] .costs-agent-table__amount')!
    expect((top as HTMLElement).dataset.shareBucket).toBe('hot')
    expect((mid as HTMLElement).dataset.shareBucket).toBe('warm')
  })

  it('shows an empty state when there are no rows', () => {
    render(<PerAgentTable rows={[]} />)
    expect(screen.getByTestId('costs-agent-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('costs-agent-table')).not.toBeInTheDocument()
  })
})
