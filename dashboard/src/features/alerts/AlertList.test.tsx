import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AlertList } from './AlertList'
import type { Alert } from './types'

const ROWS: readonly Alert[] = [
  {
    id: 'a-low',
    ruleId: 'r1',
    ruleName: 'low rule',
    severity: 'LOW',
    status: 'RESOLVED',
    agentId: 'aa-z',
    firstFiredAt: '2026-05-13T10:00:00Z',
    resolvedAt: '2026-05-13T11:00:00Z',
    destinationIds: ['d-low'],
  },
  {
    id: 'a-crit',
    ruleId: 'r2',
    ruleName: 'crit rule',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: 'aa-a',
    firstFiredAt: '2026-05-13T09:00:00Z',
    resolvedAt: null,
    destinationIds: ['d-crit'],
  },
  {
    id: 'a-med',
    ruleId: 'r3',
    ruleName: 'med rule',
    severity: 'MEDIUM',
    status: 'SUPPRESSED',
    agentId: 'aa-m',
    firstFiredAt: '2026-05-13T08:30:00Z',
    resolvedAt: null,
    destinationIds: [],
  },
]

describe('AlertList', () => {
  it('renders one data-testid="alert-row" per alert', () => {
    render(<AlertList rows={ROWS} />)
    expect(screen.getAllByTestId('alert-row')).toHaveLength(3)
  })

  it('sorts severity descending by default (CRITICAL first)', () => {
    render(<AlertList rows={ROWS} />)
    const rows = screen.getAllByTestId('alert-row')
    expect(within(rows[0]).getByText('CRITICAL')).toBeInTheDocument()
    expect(within(rows[1]).getByText('MEDIUM')).toBeInTheDocument()
    expect(within(rows[2]).getByText('LOW')).toBeInTheDocument()
  })

  it('flips severity order when the column header is clicked', async () => {
    const user = userEvent.setup()
    render(<AlertList rows={ROWS} />)
    await user.click(screen.getByTestId('alerts-th-severity'))
    const rows = screen.getAllByTestId('alert-row')
    expect(within(rows[0]).getByText('LOW')).toBeInTheDocument()
    expect(within(rows[2]).getByText('CRITICAL')).toBeInTheDocument()
  })

  it('fires onSelect with the alert id when a row is clicked', async () => {
    const user = userEvent.setup()
    const onSelect = vi.fn()
    render(<AlertList rows={ROWS} onSelect={onSelect} />)
    await user.click(screen.getAllByTestId('alert-row')[0])
    expect(onSelect).toHaveBeenCalledWith('a-crit')
  })
})
