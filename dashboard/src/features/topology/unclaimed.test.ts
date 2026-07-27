import { describe, expect, it } from 'vitest'
import {
  UNCLAIMED_TEAM,
  UNCLAIMED_TEAM_LABEL,
  countUnclaimed,
  isUnclaimedTeam,
  realTeams,
  teamKeyOf,
  teamLabel,
} from './unclaimed'
import { isOrphanAgent } from '../teams/orphans'
import type { components } from '../../api/generated/schema'

type ApiNode = components['schemas']['AgentNode']

function node(over: Partial<ApiNode> = {}): ApiNode {
  return { id: 'a', name: 'agent', depth: 0, status: 'active', mode: 'enforce', flagged: false, trust: null, ...over }
}

describe('teamKeyOf', () => {
  it('keeps a real team id', () => {
    expect(teamKeyOf(node({ team_id: 'support' }))).toBe('support')
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['blank', ''],
  ])('groups a %s team_id under the unclaimed key', (_label, teamId) => {
    expect(teamKeyOf(node({ team_id: teamId }))).toBe(UNCLAIMED_TEAM)
  })

  it('never yields the empty string', () => {
    // The whole defect was `'' `escaping into the view model and being read
    // downstream as a team whose name happened to be blank (AAASM-5184).
    for (const teamId of [null, undefined, '', 'support']) {
      expect(teamKeyOf(node({ team_id: teamId }))).not.toBe('')
    }
  })

  it('agrees with isOrphanAgent for every input', () => {
    // The point of the module: one definition of "unclaimed", shared with the
    // Teams page (AAASM-5157). If these ever disagree, two surfaces are giving
    // the operator different answers about the same agent.
    for (const teamId of [null, undefined, '', 'support', 'ops']) {
      const n = node({ team_id: teamId })
      expect(isUnclaimedTeam(teamKeyOf(n))).toBe(isOrphanAgent(n))
    }
  })
})

describe('teamLabel', () => {
  it('renders the unclaimed group by name, not by its sentinel key', () => {
    expect(teamLabel(UNCLAIMED_TEAM)).toBe(UNCLAIMED_TEAM_LABEL)
    expect(teamLabel(UNCLAIMED_TEAM)).not.toContain('__')
  })

  it('passes a real team id through unchanged', () => {
    expect(teamLabel('support')).toBe('support')
  })
})

describe('realTeams', () => {
  it('excludes the unclaimed group from the team list', () => {
    expect(realTeams(['support', UNCLAIMED_TEAM, 'ops'])).toEqual(['support', 'ops'])
  })

  it('reports no teams when every agent is unclaimed', () => {
    // The header must not claim one team exists because one grouping is drawn.
    expect(realTeams([UNCLAIMED_TEAM])).toHaveLength(0)
  })

  it('leaves a list of only real teams alone', () => {
    expect(realTeams(['support', 'ops'])).toEqual(['support', 'ops'])
  })
})

describe('countUnclaimed', () => {
  it('counts only the nodes in the unclaimed group', () => {
    const nodes = [
      { team: 'support' },
      { team: UNCLAIMED_TEAM },
      { team: UNCLAIMED_TEAM },
      { team: 'ops' },
    ]
    expect(countUnclaimed(nodes)).toBe(2)
  })

  it('is zero when every agent has a team', () => {
    expect(countUnclaimed([{ team: 'support' }, { team: 'ops' }])).toBe(0)
  })
})
