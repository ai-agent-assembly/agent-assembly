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
    deny: count(posture.deny) ?? state(posture.deny),
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

describe('deriveAgentPosture — narrow and approval carry no figure at all', () => {
  // AAASM-5197 (per ADR-0026 Decision 2, Accepted). `AgentPosture` used to carry
  // Narrow and Approval as a permanent `not-supported` absence. They are
  // unreachable by construction — nothing can emit either verdict — so the
  // posture shape no longer models them; the type itself is the guard.
  it('exposes only allow and deny on the posture shape', () => {
    const posture = deriveAgentPosture(success(loaded({ gmail: cell({ read: 'allow', write: 'deny' }) })))
    expect(Object.keys(posture).sort()).toEqual(['allow', 'deny'])
  })

  it('never lets a structurally-zero narrow tally reach the posture', () => {
    // With a loaded cascade `tallyVerdicts` returns a typed `known(0)` for
    // narrow; it must be discarded, not surfaced as a measured `0`.
    const posture = deriveAgentPosture(success(loaded({ gmail: cell({ read: 'allow' }) })))
    expect('narrow' in posture).toBe(false)
    expect('approval' in posture).toBe(false)
  })
})

describe('deriveAgentPosture — absence of a trustworthy matrix', () => {
  it('reports unavailable when the request failed', () => {
    const posture = deriveAgentPosture({ isPending: false, isError: true, error: new Error('boom') })
    expect(shape(posture)).toEqual({
      allow: 'unavailable',
      deny: 'unavailable',
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
      deny: 'not-evaluated',
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

describe('deriveAgentPosture — a body that is not a scoped matrix (AAASM-5380 S6)', () => {
  // The fold is now `certainFromShapedQuery(outcome, decodeScopedMatrix)`. Each
  // body below used to reach the counting path intact — `api/capability.ts`
  // casts the wire — and either threw at render or fabricated a count. Every one
  // must now fold to an explicit `unknown` and, above all, must not throw.

  it('reports unknown for a non-array `resources`, which threw inside the tally generator', () => {
    // `agentCells` does `for (const resource of resources)`; a non-iterable
    // `resources` threw there, at render, outside any queryFn.
    const posture = deriveAgentPosture(
      success({
        agent: makeAgent({ gmail: cell({ read: 'allow' }) }),
        resources: { length: 2 },
        policies: POLICIES,
        sampleCalls: [],
      } as unknown as ScopedCapabilityMatrix),
    )
    expect(shape(posture)).toEqual({ allow: 'unknown', deny: 'unknown' })
  })

  it('reports unknown for a truthy non-array `policies`, which skipped the empty-cascade guard', () => {
    // `cascadeEvidenceOf` reads `.length`; on `{ count: 3 }` that is `undefined`,
    // not `0`, so the empty-cascade guard was skipped and counting proceeded on
    // an unread cascade.
    const posture = deriveAgentPosture(
      success({
        agent: makeAgent({ gmail: cell({ read: 'allow' }) }),
        resources: RESOURCES,
        policies: { count: 3 },
        sampleCalls: [],
      } as unknown as ScopedCapabilityMatrix),
    )
    expect(shape(posture)).toEqual({ allow: 'unknown', deny: 'unknown' })
  })

  it('reports unknown for an agent row with no readable caps, which the index throws on', () => {
    const posture = deriveAgentPosture(
      success({
        agent: { id: 'a1', name: 'alpha' },
        resources: RESOURCES,
        policies: POLICIES,
        sampleCalls: [],
      } as unknown as ScopedCapabilityMatrix),
    )
    expect(shape(posture)).toEqual({ allow: 'unknown', deny: 'unknown' })
  })

  it('reports unknown for a bare `{}` body without throwing', () => {
    const posture = deriveAgentPosture(success({} as unknown as ScopedCapabilityMatrix))
    expect(shape(posture)).toEqual({ allow: 'unknown', deny: 'unknown' })
  })

  it('carries the decoder reason so the operator has somewhere to go', () => {
    const posture = deriveAgentPosture(success({} as unknown as ScopedCapabilityMatrix))
    expect(isAbsent(posture.allow) && posture.allow.detail).toMatch(
      /capability matrix came back in a shape/i,
    )
  })

  it('still counts a null agent as not-evaluated, not unreadable', () => {
    // `agent: null` is a real answer the decoder must let through — the agent has
    // no row — distinct from a body that could not be read.
    const posture = deriveAgentPosture(
      success({ agent: null, resources: RESOURCES, policies: POLICIES, sampleCalls: [] }),
    )
    expect(shape(posture)).toEqual({ allow: 'not-evaluated', deny: 'not-evaluated' })
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
