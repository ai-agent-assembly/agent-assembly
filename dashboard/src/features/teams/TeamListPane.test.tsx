import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { TeamListPane } from './TeamListPane'
import { known } from '../../lib/truthfulness'
import type { TeamListRow } from './api'

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

function renderPane(rows: TeamListRow[]) {
  return render(
    <TeamListPane
      rows={rows}
      selectedId={undefined}
      onSelect={vi.fn()}
      isLoading={false}
      isError={false}
      orphanCount={known(0)}
      isOrphanSelected={false}
      onSelectOrphan={vi.fn()}
    />,
  )
}

describe('TeamListPane', () => {
  it('labels the mini budget bar with $spend / $limit, not a percentage', () => {
    // Dollar figures per design/v1/hi-fi/teams.jsx:35-37; the percentage is the
    // bar colour signal only and must not read as text (AAASM-5172).
    renderPane([
      row({ team_id: 'growth', daily_spend_usd: 150, daily_limit_usd: 200, burn_pct: 75 }),
    ])

    expect(screen.getByText('$150.00 / $200')).toBeInTheDocument()
    expect(screen.queryByText(/% burn/)).not.toBeInTheDocument()
  })

  it('omits the bar entirely when a team has no burn figure', () => {
    renderPane([row({ team_id: 'quiet' })])

    expect(screen.getByText('quiet')).toBeInTheDocument()
    expect(screen.queryByText(/\$/)).not.toBeInTheDocument()
  })
})
