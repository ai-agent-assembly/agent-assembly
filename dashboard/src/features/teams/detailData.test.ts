import { describe, expect, it } from 'vitest'
import { selectTeamApprovals, selectTeamBudget } from './detailData'
import type { BudgetTree } from '../costs/api'
import type { Approval } from '../approvals/api'

type TreeNode = NonNullable<BudgetTree['root']>

function tree(children: TreeNode['children']): BudgetTree {
  return {
    root: {
      id: 'org', label: 'org', kind: 'org', depth: 0,
      own_spend_usd: '0', subtree_spend_usd: '0', budget_limit_usd: '100',
      children,
    },
  }
}

describe('selectTeamBudget', () => {
  it('returns null when the tree is absent', () => {
    expect(selectTeamBudget(undefined, 'team-a')).toBeNull()
  })

  it('returns null when no team node matches', () => {
    const t = tree([{ id: 'team-a', label: 'team-a', kind: 'team', depth: 1, own_spend_usd: '0', subtree_spend_usd: '10', budget_limit_usd: '40', children: [] }])
    expect(selectTeamBudget(t, 'team-missing')).toBeNull()
  })

  it('derives spend, limit, burn %, and bucket for a team with a limit', () => {
    const t = tree([{ id: 'team-a', label: 'team-a', kind: 'team', depth: 1, own_spend_usd: '0', subtree_spend_usd: '38', budget_limit_usd: '40', children: [] }])
    const budget = selectTeamBudget(t, 'team-a')
    expect(budget).not.toBeNull()
    expect(budget!.spentUsd).toBe(38)
    expect(budget!.limitUsd).toBe(40)
    expect(budget!.burnPct).toBeCloseTo(95, 5)
    expect(budget!.bucket).toBe('danger')
  })

  it('leaves burn % and bucket null when the team has no configured limit', () => {
    const t = tree([{ id: 'team-a', label: 'team-a', kind: 'team', depth: 1, own_spend_usd: '0', subtree_spend_usd: '12', budget_limit_usd: null, children: [] }])
    const budget = selectTeamBudget(t, 'team-a')
    expect(budget).toEqual({ limitUsd: null, spentUsd: 12, burnPct: null, bucket: null })
  })

  it('ignores non-team siblings sharing the id', () => {
    const t = tree([{ id: 'team-a', label: 'agent-a', kind: 'agent', depth: 1, own_spend_usd: '5', subtree_spend_usd: '5', budget_limit_usd: '10', children: [] }])
    expect(selectTeamBudget(t, 'team-a')).toBeNull()
  })

  it('falls spend back to 0 when the subtree figure is unparseable', () => {
    // A non-numeric wire value must not leak `NaN` into the card; parseDecimal
    // returns null for it and the `?? 0` guard takes over.
    const t = tree([{ id: 'team-a', label: 'team-a', kind: 'team', depth: 1, own_spend_usd: '0', subtree_spend_usd: 'n/a', budget_limit_usd: null, children: [] }])
    expect(selectTeamBudget(t, 'team-a')).toEqual({ limitUsd: null, spentUsd: 0, burnPct: null, bucket: null })
  })

  it('returns null when the root carries no children array', () => {
    // A root delivered without a `children` field must not throw; the `?? []`
    // guard turns the missing collection into "no matching team".
    const t: BudgetTree = { root: { id: 'org', label: 'org', kind: 'org', depth: 0, own_spend_usd: '0', subtree_spend_usd: '0', budget_limit_usd: '100', children: undefined as unknown as TreeNode['children'] } }
    expect(selectTeamBudget(t, 'team-a')).toBeNull()
  })
})

function approval(overrides: Partial<Approval>): Approval {
  return {
    id: 'apr-1', action: 'tool.exec', agent_id: 'a1', reason: 'needs review',
    created_at: '2026-05-13T10:00:00Z', expires_at: '2026-05-13T10:05:00Z',
    status: 'pending', team_id: 'team-a', ...overrides,
  }
}

describe('selectTeamApprovals', () => {
  it('returns an empty array when approvals are absent', () => {
    expect(selectTeamApprovals(undefined, 'team-a')).toEqual([])
  })

  it('keeps only approvals routed to the team', () => {
    const list = [approval({ id: 'a', team_id: 'team-a' }), approval({ id: 'b', team_id: 'team-b' }), approval({ id: 'c', team_id: null })]
    expect(selectTeamApprovals(list, 'team-a').map(a => a.id)).toEqual(['a'])
  })

  it('orders newest first by created_at', () => {
    const list = [
      approval({ id: 'old', created_at: '2026-05-10T00:00:00Z' }),
      approval({ id: 'new', created_at: '2026-05-13T00:00:00Z' }),
      approval({ id: 'mid', created_at: '2026-05-12T00:00:00Z' }),
    ]
    expect(selectTeamApprovals(list, 'team-a').map(a => a.id)).toEqual(['new', 'mid', 'old'])
  })

  it('sorts a missing created_at as the oldest via the empty-string fallback', () => {
    // A wire row without `created_at` must not crash localeCompare; the `?? ''`
    // guard treats it as the empty string, sorting it after every timestamped row.
    // Two undated rows around a dated one exercise the fallback on both the `a`
    // and `b` sides of the comparator.
    const list = [
      approval({ id: 'undated-1', created_at: undefined as unknown as string }),
      approval({ id: 'dated', created_at: '2026-05-12T00:00:00Z' }),
      approval({ id: 'undated-2', created_at: undefined as unknown as string }),
    ]
    expect(selectTeamApprovals(list, 'team-a').map(a => a.id)).toEqual(['dated', 'undated-1', 'undated-2'])
  })
})
