import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { PerTeamTable } from './PerTeamTable'
import type { TeamListRow } from '../../features/teams/api'

function row(over: Partial<TeamListRow> & { team_id: string }): TeamListRow {
  return {
    agent_count: 2,
    root_agent_count: 1,
    daily_spend_usd: null,
    daily_limit_usd: null,
    monthly_spend_usd: null,
    burn_pct: null,
    ...over,
  }
}

function cell(team: string): HTMLElement {
  return screen.getByTestId('costs-team-table').querySelector(`[data-team="${team}"]`) as HTMLElement
}

describe('PerTeamTable — AAASM-5160 restored columns', () => {
  it('renders the mock’s column set minus the ungated Monthly limit', () => {
    render(<PerTeamTable rows={[row({ team_id: 'team-hot' })]} />)

    const heads = screen.getAllByRole('columnheader').map(h => h.textContent)
    expect(heads).toEqual(['Team', 'Agents', 'Daily spend', 'vs daily limit', 'Monthly spend'])
    // `TeamCostEntry` carries no ceiling of any window; the mock's Monthly
    // limit reads a fixture, and inventing one is worse than omitting it.
    expect(screen.queryByText('Monthly limit')).not.toBeInTheDocument()
  })

  it('renders agent count, daily spend, the burn bar and monthly spend for a measured team', () => {
    render(
      <PerTeamTable
        rows={[
          row({
            team_id: 'team-hot',
            agent_count: 7,
            daily_spend_usd: 190,
            daily_limit_usd: 200,
            monthly_spend_usd: 2900,
            burn_pct: 95,
          }),
        ]}
      />,
    )

    const hot = cell('team-hot')
    expect(within(hot).getByTestId('costs-team-agents')).toHaveTextContent('7')
    expect(within(hot).getByText('$190.00')).toBeInTheDocument()
    expect(within(hot).getByText('$2900.00')).toBeInTheDocument()
    expect(within(hot).getByTestId('team-budget-bar').dataset.thresholdBucket).toBe('danger')
  })

  it('colours the daily figure by its burn bucket, and leaves it uncoloured when unmeasurable', () => {
    render(
      <PerTeamTable
        rows={[
          row({ team_id: 'team-ok', daily_spend_usd: 20, daily_limit_usd: 200 }),
          row({ team_id: 'team-nolimit', daily_spend_usd: 20 }),
        ]}
      />,
    )

    expect(
      (cell('team-ok').querySelector('.costs-team-table__daily') as HTMLElement).dataset
        .thresholdBucket,
    ).toBe('ok')
    // No ceiling ⇒ no band applies; a green figure would claim headroom that
    // was never measured.
    expect(
      (cell('team-nolimit').querySelector('.costs-team-table__daily') as HTMLElement).dataset
        .thresholdBucket,
    ).toBeUndefined()
  })

  it('buckets a configured $0 ceiling as danger rather than as untouched', () => {
    // `bucketForBudget` maps `limit <= 0` to `ok`; a fully-consumed ceiling is
    // not a comfortable one, so the cell resolves that case itself.
    render(<PerTeamTable rows={[row({ team_id: 'team-zero', daily_spend_usd: 5, daily_limit_usd: 0 })]} />)

    expect(
      (cell('team-zero').querySelector('.costs-team-table__daily') as HTMLElement).dataset
        .thresholdBucket,
    ).toBe('danger')
  })

  it('renders an absent monthly figure as an absence, never as $0', () => {
    render(
      <PerTeamTable
        rows={[
          // In the breakdown, no monthly figure → monthly tracking is off.
          row({ team_id: 'team-tracked', daily_spend_usd: 190 }),
          // Absent from the breakdown entirely → nothing was measured.
          row({ team_id: 'team-missing' }),
        ]}
      />,
    )

    const tracked = cell('team-tracked')
    expect(within(tracked).getByTestId('costs-team-no-monthly').dataset.truthState).toBe(
      'unconfigured',
    )
    expect(within(tracked).queryByText('$0.00')).not.toBeInTheDocument()

    const missing = cell('team-missing')
    expect(within(missing).getByTestId('costs-team-no-monthly').dataset.truthState).toBe('unknown')
    expect(within(missing).getByTestId('costs-team-no-daily').dataset.truthState).toBe('unknown')
    expect(within(missing).queryByText('$0.00')).not.toBeInTheDocument()
  })

  it('keeps a genuinely measured $0 spend as $0', () => {
    render(
      <PerTeamTable
        rows={[
          row({ team_id: 'team-idle', daily_spend_usd: 0, daily_limit_usd: 200, monthly_spend_usd: 0 }),
        ]}
      />,
    )

    const idle = cell('team-idle')
    expect(within(idle).getAllByText('$0.00')).toHaveLength(2)
    expect(within(idle).queryByTestId('costs-team-no-monthly')).not.toBeInTheDocument()
  })

  it('renders an empty table body when there are no rows', () => {
    render(<PerTeamTable rows={[]} />)

    expect(screen.getByTestId('costs-team-table')).toBeInTheDocument()
    expect(screen.queryAllByTestId('costs-team-row')).toHaveLength(0)
  })
})
