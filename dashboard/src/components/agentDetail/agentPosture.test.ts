import { describe, expect, it } from 'vitest'
import { isAbsent, isKnown, type Certain } from '../../lib/truthfulness'
import type { CapabilityAgent, CapCell, Resource } from '../../features/capability/types'
import { deriveAgentPosture, postureScale, type AgentPosture } from './agentPosture'
import type { ScopedCapabilityMatrix } from './useAgentCapabilityMatrix'

const RESOURCES: Resource[] = [
  { id: 'gmail', name: 'Gmail', group: 'comm', paths: [] },
  { id: 'pg', name: 'Postgres', group: 'data', paths: [] },
]

/** One resolved policy document — enough for the cascade to carry authority. */
const POLICIES = [
  { id: 'P-001', name: 'global default-deny', scope: 'global', status: 'active', affects: [], rules: [] },
] as ScopedCapabilityMatrix['policies']

function cell(patch: Partial<CapCell> = {}): CapCell {
  return { read: 'na', write: 'na', delete: 'na', exec: 'na', ...patch }
}

function makeAgent(caps: Record<string, CapCell>): CapabilityAgent {
  return {
    id: 'abc123',
    name: 'alpha-agent',
    framework: 'langgraph',
    owner: 'alice',
    trust: null,
    mode: 'enforce',
    status: 'active',
    lastSeen: '2m ago',
    caps,
  }
}

function loaded(
  caps: Record<string, CapCell>,
  policies: ScopedCapabilityMatrix['policies'] = POLICIES,
): ScopedCapabilityMatrix {
  return { agent: makeAgent(caps), resources: RESOURCES, policies, sampleCalls: [] }
}

/** A settled, successful TanStack result carrying `data`. */
function success(data: ScopedCapabilityMatrix) {
  return { isPending: false, isError: false, error: null, data }
}

function count(value: Certain<number>): number | undefined {
  return isKnown(value) ? value.value : undefined
}

function state(value: Certain<number>): string | undefined {
  return isAbsent(value) ? value.state : undefined
}

/** Every figure, so a scenario can be asserted against as a whole. */
function shape(posture: AgentPosture) {
  return {
    allow: count(posture.allow) ?? state(posture.allow),
    narrow: count(posture.narrow) ?? state(posture.narrow),
    deny: count(posture.deny) ?? state(posture.deny),
    approval: count(posture.approval) ?? state(posture.approval),
  }
}

describe('deriveAgentPosture — allow and deny come from the matrix', () => {
  it('counts allow and deny cells across every verb', () => {
    const posture = deriveAgentPosture(
      success(
        loaded({
          gmail: cell({ read: 'allow', write: 'deny' }),
          pg: cell({ read: 'allow', write: 'deny', delete: 'deny' }),
        }),
      ),
    )
    expect(count(posture.allow)).toBe(2)
    expect(count(posture.deny)).toBe(3)
  })

  it('excludes na cells rather than letting them disqualify the tally', () => {
    // Every verb of `pg` is `na`; only gmail/read is a real verdict.
    const posture = deriveAgentPosture(success(loaded({ gmail: cell({ read: 'allow' }) })))
    expect(count(posture.allow)).toBe(1)
    expect(count(posture.deny)).toBe(0)
  })

  it('treats a resource column the agent never declared as out of scope', () => {
    // `pg` is absent from caps entirely — that is "not this agent's resource",
    // not "unevaluated", so the panel still reports the cells it does have.
    const posture = deriveAgentPosture(
      success({ ...loaded({ gmail: cell({ write: 'deny' }) }), resources: RESOURCES }),
    )
    expect(count(posture.deny)).toBe(1)
  })

  it('never reproduces sessions minus violations', () => {
    // The agent record behind this fixture had session_count 10 and
    // policy_violations_count 4, which the old panel rendered as Allow 6 /
    // Deny 4. Neither figure may reappear from matrix data.
    const posture = deriveAgentPosture(success(loaded({ gmail: cell({ read: 'allow' }) })))
    expect(count(posture.allow)).toBe(1)
    expect(count(posture.deny)).toBe(0)
  })
})

describe('deriveAgentPosture — narrow and approval are never a number', () => {
  const scenarios: ReadonlyArray<[string, Parameters<typeof deriveAgentPosture>[0]]> = [
    ['a healthy, fully populated matrix', success(loaded({ gmail: cell({ read: 'allow', write: 'deny' }) }))],
    ['an empty policy cascade', success(loaded({ gmail: cell({ read: 'allow' }) }, []))],
    ['an agent missing from the matrix', success({ agent: null, resources: RESOURCES, policies: POLICIES, sampleCalls: [] })],
    ['a failed request', { isPending: false, isError: true, error: new Error('boom') }],
    ['a request still in flight', { isPending: true, isError: false, error: null }],
  ]

  // The regression guard for AAASM-5131: the panel hardcoded `value={0}` for
  // both rows. If a literal — or a tally's structurally-zero `narrow` — ever
  // comes back, these fail on the *type* of the figure, not on its value, so no
  // amount of arithmetic can sneak past them.
  it.each(scenarios)('reports not-supported for narrow and approval given %s', (_name, outcome) => {
    const posture = deriveAgentPosture(outcome)
    expect(isKnown(posture.narrow)).toBe(false)
    expect(isKnown(posture.approval)).toBe(false)
    expect(state(posture.narrow)).toBe('not-supported')
    expect(state(posture.approval)).toBe('not-supported')
  })

  it('explains why, so the dash is legible rather than merely blank', () => {
    const posture = deriveAgentPosture(success(loaded({ gmail: cell({ read: 'allow' }) })))
    expect(isAbsent(posture.narrow) && posture.narrow.detail).toContain('requires_approval_if')
  })

  it('gives the two figures independent identity', () => {
    const posture = deriveAgentPosture(success(loaded({ gmail: cell({ read: 'allow' }) })))
    expect(posture.narrow).not.toBe(posture.approval)
  })
})

describe('deriveAgentPosture — absence of a trustworthy matrix', () => {
  it('reports unavailable when the request failed', () => {
    const posture = deriveAgentPosture({ isPending: false, isError: true, error: new Error('boom') })
    expect(shape(posture)).toEqual({
      allow: 'unavailable',
      narrow: 'not-supported',
      deny: 'unavailable',
      approval: 'not-supported',
    })
  })

  it('carries the thrown message so the operator can act on it', () => {
    const posture = deriveAgentPosture({ isPending: false, isError: true, error: new Error('boom') })
    expect(isAbsent(posture.allow) && posture.allow.detail).toBe('boom')
  })

  it('reports unknown — not unavailable — while the request is in flight', () => {
    const posture = deriveAgentPosture({ isPending: true, isError: false, error: null })
    expect(state(posture.allow)).toBe('unknown')
    expect(state(posture.deny)).toBe('unknown')
  })

  it('reports unknown when a settled response carried no payload', () => {
    const posture = deriveAgentPosture({ isPending: false, isError: false, error: null, data: null })
    expect(state(posture.allow)).toBe('unknown')
  })

  it('reports not-evaluated when the agent has no row in the matrix', () => {
    const posture = deriveAgentPosture(
      success({ agent: null, resources: RESOURCES, policies: POLICIES, sampleCalls: [] }),
    )
    expect(shape(posture)).toEqual({
      allow: 'not-evaluated',
      narrow: 'not-supported',
      deny: 'not-evaluated',
      approval: 'not-supported',
    })
  })

  it('reports unconfigured when no policy document backs the verdicts', () => {
    // AAASM-5106: with an empty cascade `decide()` falls through to Allow for
    // every cell, so counting them would report permissions nothing granted.
    const posture = deriveAgentPosture(
      success(loaded({ gmail: cell({ read: 'allow', write: 'allow' }) }, [])),
    )
    expect(state(posture.allow)).toBe('unconfigured')
    expect(state(posture.deny)).toBe('unconfigured')
  })
})

describe('postureScale', () => {
  it('sums only the figures that were measured', () => {
    const posture = deriveAgentPosture(
      success(loaded({ gmail: cell({ read: 'allow', write: 'deny' }), pg: cell({ read: 'allow' }) })),
    )
    expect(postureScale(posture)).toBe(3)
  })

  it('floors at 1 so a fully absent panel never divides by zero', () => {
    expect(postureScale(deriveAgentPosture({ isPending: true, isError: false, error: null }))).toBe(1)
  })

  it('floors at 1 when every cell is genuinely out of scope', () => {
    expect(postureScale(deriveAgentPosture(success(loaded({ gmail: cell() }))))).toBe(1)
  })
})
