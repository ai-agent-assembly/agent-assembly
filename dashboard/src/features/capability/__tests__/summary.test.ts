import { describe, it, expect } from 'vitest'
import { summarizeMatrix } from '../summary'
import type { CapabilityAgent, CapCell, Resource, Verb } from '../types'

const RESOURCES: Resource[] = [
  { id: 'gmail', name: 'Gmail', group: 'comm', paths: [] },
  { id: 's3', name: 'AWS S3', group: 'files', paths: [] },
]

function cell(patch: Partial<CapCell> = {}): CapCell {
  return { read: 'na', write: 'na', delete: 'na', exec: 'na', ...patch }
}

function makeAgent(patch: Partial<CapabilityAgent> = {}): CapabilityAgent {
  return {
    id: 'a',
    name: 'agent',
    framework: 'LangChain',
    owner: 'team-x',
    trust: 50,
    mode: 'enforce',
    status: 'active',
    lastSeen: '1m ago',
    caps: {},
    ...patch,
  }
}

const VERB: Verb = 'write'

describe('summarizeMatrix', () => {
  it('counts allow / narrow / deny cells for the given verb', () => {
    const agents: CapabilityAgent[] = [
      makeAgent({
        id: 'a',
        caps: { gmail: cell({ write: 'allow' }), s3: cell({ write: 'narrow' }) },
      }),
      makeAgent({
        id: 'b',
        caps: { gmail: cell({ write: 'deny' }), s3: cell({ write: 'allow' }) },
      }),
    ]
    expect(summarizeMatrix(agents, RESOURCES, VERB)).toEqual({
      allow: 2,
      narrow: 1,
      deny: 1,
      flaggedAgents: 0,
    })
  })

  it('only counts the selected verb, ignoring other verbs', () => {
    const agents = [
      makeAgent({
        caps: { gmail: cell({ write: 'allow', read: 'deny' }), s3: cell({ read: 'deny' }) },
      }),
    ]
    const s = summarizeMatrix(agents, RESOURCES, 'write')
    expect(s.allow).toBe(1)
    expect(s.deny).toBe(0)
  })

  it('treats a missing cap cell as n/a (uncounted)', () => {
    const agents = [makeAgent({ caps: { gmail: cell({ write: 'allow' }) } })]
    const s = summarizeMatrix(agents, RESOURCES, VERB)
    expect(s.allow).toBe(1)
    expect(s.narrow + s.deny).toBe(0)
  })

  it('counts flagged agents independently of the verb', () => {
    const agents = [
      makeAgent({ id: 'a', flagged: true }),
      makeAgent({ id: 'b', flagged: false }),
      makeAgent({ id: 'c', flagged: true }),
    ]
    expect(summarizeMatrix(agents, RESOURCES, VERB).flaggedAgents).toBe(2)
  })

  it('returns all zeros for an empty agent set', () => {
    expect(summarizeMatrix([], RESOURCES, VERB)).toEqual({
      allow: 0,
      narrow: 0,
      deny: 0,
      flaggedAgents: 0,
    })
  })
})
