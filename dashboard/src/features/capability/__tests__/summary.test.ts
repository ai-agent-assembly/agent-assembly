import { describe, it, expect } from 'vitest'
import {
  absent,
  isAbsent,
  isKnown,
  known,
  type CascadeEvidence,
  type Certain,
} from '../../../lib/truthfulness'
import { cascadeEvidenceOf, summarizeMatrix } from '../summary'
import type { CapabilityAgent, CapCell, Resource, Verb } from '../types'

const RESOURCES: Resource[] = [
  { id: 'gmail', name: 'Gmail', group: 'comm', paths: [] },
  { id: 's3', name: 'AWS S3', group: 'files', paths: [] },
]

/** A cascade that actually resolved documents, so its verdicts are assertable. */
const LOADED: Certain<CascadeEvidence> = known({ documentCount: 2 })
/** The AAASM-5106 condition: the projection ran, but no policy participated. */
const EMPTY: Certain<CascadeEvidence> = known({ documentCount: 0 })

function cell(patch: Partial<CapCell> = {}): CapCell {
  return { read: 'na', write: 'na', delete: 'na', exec: 'na', ...patch }
}

function makeAgent(patch: Partial<CapabilityAgent> = {}): CapabilityAgent {
  return {
    id: 'a',
    name: 'agent',
    framework: 'LangChain',
    owner: 'team-x',
    mode: 'enforce',
    status: 'active',
    lastSeen: '1m ago',
    caps: {},
    ...patch,
  }
}

const VERB: Verb = 'write'

function count(value: Certain<number>): number | undefined {
  return isKnown(value) ? value.value : undefined
}

function state(value: Certain<number>): string | undefined {
  return isAbsent(value) ? value.state : undefined
}

describe('summarizeMatrix — with a loaded cascade', () => {
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
    const s = summarizeMatrix(agents, RESOURCES, VERB, LOADED)
    expect(count(s.allow)).toBe(2)
    expect(count(s.narrow)).toBe(1)
    expect(count(s.deny)).toBe(1)
  })

  it('only counts the selected verb, ignoring other verbs', () => {
    const agents = [
      makeAgent({
        caps: { gmail: cell({ write: 'allow', read: 'deny' }), s3: cell({ read: 'deny' }) },
      }),
    ]
    const s = summarizeMatrix(agents, RESOURCES, 'write', LOADED)
    expect(count(s.allow)).toBe(1)
    expect(count(s.deny)).toBe(0)
  })

  it('treats a missing cap cell as uncounted', () => {
    const agents = [makeAgent({ caps: { gmail: cell({ write: 'allow' }) } })]
    const s = summarizeMatrix(agents, RESOURCES, VERB, LOADED)
    expect(count(s.allow)).toBe(1)
    expect(count(s.narrow)).toBe(0)
    expect(count(s.deny)).toBe(0)
  })

  it('reports zero counts for an empty agent set as a real measurement', () => {
    // Rules were loaded and there was simply nothing to evaluate against —
    // that zero is honest, unlike the empty-cascade zero below.
    const s = summarizeMatrix([], RESOURCES, VERB, LOADED)
    expect(count(s.allow)).toBe(0)
    expect(count(s.deny)).toBe(0)
  })
})

describe('summarizeMatrix — the AAASM-5106 guard', () => {
  const permissive = [
    makeAgent({ id: 'a', caps: { gmail: cell({ write: 'allow' }), s3: cell({ write: 'allow' }) } }),
  ]

  it('does not report an allow count when no policy document is loaded', () => {
    // Every shipped deployment today: `decide()` falls through to Allow for
    // each cell, so counting them would advertise permissions nothing granted.
    const s = summarizeMatrix(permissive, RESOURCES, VERB, EMPTY)
    expect(isKnown(s.allow)).toBe(false)
    expect(state(s.allow)).toBe('unconfigured')
  })

  it('does not report a reassuring zero denial count either', () => {
    const s = summarizeMatrix(permissive, RESOURCES, VERB, EMPTY)
    expect(state(s.deny)).toBe('unconfigured')
    expect(state(s.narrow)).toBe('unconfigured')
  })

  it('propagates an unavailable matrix to every count', () => {
    const s = summarizeMatrix(permissive, RESOURCES, VERB, absent('unavailable', 'HTTP 500'))
    expect(state(s.allow)).toBe('unavailable')
    expect(state(s.deny)).toBe('unavailable')
    expect(state(s.flaggedAgents)).toBe('unavailable')
  })
})

describe('summarizeMatrix — flagged agents', () => {
  it('counts flagged agents when the backend actually evaluated them', () => {
    const agents = [
      makeAgent({ id: 'a', flagged: true }),
      makeAgent({ id: 'b', flagged: false }),
      makeAgent({ id: 'c', flagged: true }),
    ]
    expect(count(summarizeMatrix(agents, RESOURCES, VERB, LOADED).flaggedAgents)).toBe(2)
  })

  it('reports not-evaluated when no agent carries a flag verdict', () => {
    // The live projection omits `flagged` entirely; "0 flagged agents" would be
    // a clean bill of health nothing produced.
    const agents = [makeAgent({ id: 'a' }), makeAgent({ id: 'b' })]
    const s = summarizeMatrix(agents, RESOURCES, VERB, LOADED)
    expect(isKnown(s.flaggedAgents)).toBe(false)
    expect(state(s.flaggedAgents)).toBe('not-evaluated')
  })

  it('reports a genuine zero once at least one agent was evaluated', () => {
    const agents = [makeAgent({ id: 'a', flagged: false })]
    expect(count(summarizeMatrix(agents, RESOURCES, VERB, LOADED).flaggedAgents)).toBe(0)
  })
})

describe('cascadeEvidenceOf', () => {
  it('counts the resolved policy documents', () => {
    const evidence = cascadeEvidenceOf([{}, {}, {}])
    expect(isKnown(evidence) && evidence.value.documentCount).toBe(3)
  })

  it('records an empty list as zero documents rather than as an absence', () => {
    // Empty is a real answer from the API; it is the *verdict* rules that
    // decide zero documents means nothing was evaluated.
    const evidence = cascadeEvidenceOf([])
    expect(isKnown(evidence) && evidence.value.documentCount).toBe(0)
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
  ])('treats a %s policy list as unavailable', (_label, policies) => {
    const evidence = cascadeEvidenceOf(policies)
    expect(isAbsent(evidence) && evidence.state).toBe('unavailable')
  })
})
