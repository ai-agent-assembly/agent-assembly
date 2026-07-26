import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TeamActivePoliciesCard } from './TeamActivePoliciesCard'
import type { TeamPolicy } from './api'

const GLOBAL_POLICY: TeamPolicy = {
  id: 'global/baseline',
  name: 'baseline',
  scope: 'global',
  version: '1.0.0',
}

const TEAM_POLICY: TeamPolicy = {
  id: 'team:support/support-guard',
  name: 'support-guard',
  scope: 'team:support',
  version: '2.1.0',
}

describe('TeamActivePoliciesCard', () => {
  it('shows a loading state', () => {
    render(<TeamActivePoliciesCard policies={[]} isLoading isError={false} />)
    expect(screen.getByTestId('team-policies-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('team-policies-list')).not.toBeInTheDocument()
  })

  it('shows an error state instead of an empty one when the query failed', () => {
    render(<TeamActivePoliciesCard policies={[]} isLoading={false} isError />)
    expect(screen.getByTestId('team-policies-error')).toHaveTextContent('Failed to load')
    // A failed load must not read as "no policy is in force" — that is a
    // governance claim the UI has no basis for making.
    expect(screen.queryByTestId('team-policies-empty')).not.toBeInTheDocument()
  })

  it('renders an explicit empty state when no policy is in force', () => {
    render(<TeamActivePoliciesCard policies={[]} isLoading={false} isError={false} />)
    expect(screen.getByTestId('team-policies-empty')).toHaveTextContent('No policy is in force')
  })

  it('lists every in-force document with the cascade tier it comes from', () => {
    render(
      <TeamActivePoliciesCard policies={[GLOBAL_POLICY, TEAM_POLICY]} isLoading={false} isError={false} />,
    )
    expect(screen.getByTestId('team-policies-card')).toHaveTextContent('Active policies (2)')
    const rows = screen.getAllByTestId('team-policy-row')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('baseline')
    // The scope chip is what stops a fleet-wide document reading as a
    // team-authored one.
    expect(screen.getAllByTestId('team-policy-scope')[0]).toHaveTextContent('global')
    expect(screen.getAllByTestId('team-policy-scope')[1]).toHaveTextContent('team:support')
  })

  it('folds an absent 24h hit count to an em dash, never to 0', () => {
    render(<TeamActivePoliciesCard policies={[TEAM_POLICY]} isLoading={false} isError={false} />)
    const hits = screen.getByTestId('team-policy-hits')
    expect(hits).toHaveTextContent('—')
    expect(hits).not.toHaveTextContent('0')
  })

  it('renders a real hit count when one is present', () => {
    render(
      <TeamActivePoliciesCard
        policies={[{ ...TEAM_POLICY, hits24h: 142 }]}
        isLoading={false}
        isError={false}
      />,
    )
    expect(screen.getByTestId('team-policy-hits')).toHaveTextContent('142')
  })
})
