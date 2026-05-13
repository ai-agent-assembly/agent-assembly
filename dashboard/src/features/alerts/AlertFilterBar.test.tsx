import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AlertFilterBar, applyClientFilters } from './AlertFilterBar'
import { DEFAULT_ALERT_FILTERS, type Alert, type AlertFilters } from './types'

const ROWS: readonly Alert[] = [
  {
    id: 'a',
    ruleId: 'r',
    ruleName: 'budget burn',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: 'aa-1',
    firstFiredAt: '2026-05-13T09:00:00Z',
    resolvedAt: null,
    destinationIds: [],
  },
  {
    id: 'b',
    ruleId: 'r',
    ruleName: 'low signal',
    severity: 'LOW',
    status: 'RESOLVED',
    agentId: 'aa-2',
    firstFiredAt: '2026-05-13T08:00:00Z',
    resolvedAt: '2026-05-13T08:15:00Z',
    destinationIds: [],
  },
]

describe('applyClientFilters', () => {
  it('returns every row when filters are empty', () => {
    expect(applyClientFilters(ROWS, DEFAULT_ALERT_FILTERS)).toHaveLength(2)
  })

  it('narrows rows when severity is selected', () => {
    const filters: AlertFilters = { ...DEFAULT_ALERT_FILTERS, severities: ['CRITICAL'] }
    expect(applyClientFilters(ROWS, filters)).toEqual([ROWS[0]])
  })

  it('narrows rows when status is selected', () => {
    const filters: AlertFilters = { ...DEFAULT_ALERT_FILTERS, statuses: ['RESOLVED'] }
    expect(applyClientFilters(ROWS, filters)).toEqual([ROWS[1]])
  })

  it('matches agent query case-insensitively', () => {
    const filters: AlertFilters = { ...DEFAULT_ALERT_FILTERS, agentQuery: 'AA-1' }
    expect(applyClientFilters(ROWS, filters)).toEqual([ROWS[0]])
  })
})

describe('AlertFilterBar', () => {
  it('toggles severity when the chip is clicked', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<AlertFilterBar value={DEFAULT_ALERT_FILTERS} onChange={onChange} />)
    await user.click(screen.getByTestId('alerts-filter-severity-CRITICAL'))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ severities: ['CRITICAL'] }),
    )
  })

  it('reveals the custom range inputs when range is "custom"', () => {
    const value: AlertFilters = { ...DEFAULT_ALERT_FILTERS, timeRange: 'custom' }
    render(<AlertFilterBar value={value} onChange={vi.fn()} />)
    expect(screen.getByTestId('alerts-filter-custom-from')).toBeInTheDocument()
    expect(screen.getByTestId('alerts-filter-custom-to')).toBeInTheDocument()
  })
})
