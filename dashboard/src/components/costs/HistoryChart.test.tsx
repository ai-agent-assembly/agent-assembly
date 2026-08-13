import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { HistoryChart } from './HistoryChart'
import type { CostHistory } from '../../features/costs/api'

const POPULATED: CostHistory = {
  days: 7,
  points: [
    { date: '2026-05-05', spend_usd: '38.20' },
    { date: '2026-05-06', spend_usd: '42.10' },
    { date: '2026-05-07', spend_usd: '35.80' },
    { date: '2026-05-08', spend_usd: '44.50' },
    { date: '2026-05-09', spend_usd: '51.20' },
    { date: '2026-05-10', spend_usd: '48.90' },
    { date: '2026-05-11', spend_usd: '47.80' },
  ],
}

describe('HistoryChart', () => {
  it('renders one bar per day with short date labels when populated', () => {
    render(<HistoryChart data={POPULATED} isLoading={false} isError={false} />)
    expect(screen.getByTestId('costs-history-chart')).toBeInTheDocument()
    // Year is stripped to MM-DD; the 7 daily labels render.
    expect(screen.getByText('05-11')).toBeInTheDocument()
    expect(screen.getByText('05-05')).toBeInTheDocument()
    // Seven bars, one per point.
    const bars = document.querySelectorAll('.history-chart__bar')
    expect(bars).toHaveLength(7)
  })

  it('shows the loading state', () => {
    render(<HistoryChart data={undefined} isLoading={true} isError={false} />)
    expect(screen.getByTestId('costs-history-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('costs-history-chart')).not.toBeInTheDocument()
  })

  it('shows the error state', () => {
    render(<HistoryChart data={undefined} isLoading={false} isError={true} />)
    expect(screen.getByTestId('costs-history-error')).toBeInTheDocument()
  })

  it('shows the empty state for an all-zero window', () => {
    const empty: CostHistory = {
      days: 7,
      points: [
        { date: '2026-05-10', spend_usd: '0' },
        { date: '2026-05-11', spend_usd: '0' },
      ],
    }
    render(<HistoryChart data={empty} isLoading={false} isError={false} />)
    expect(screen.getByTestId('costs-history-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('costs-history-chart')).not.toBeInTheDocument()
  })
})
