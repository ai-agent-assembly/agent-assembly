import { describe, expect, it } from 'vitest'
import { buildLayerSteps, deriveVerdict } from './decision'
import type { TraceEvent } from './types'

const BASE: TraceEvent = {
  id: 'e',
  timestamp: '2026-04-23T14:23:01Z',
  type: 'tool_call',
  agent: 'support-agent',
  durationMs: 12,
  payloadPreview: 'query_db',
  payload: {},
}

describe('deriveVerdict', () => {
  it('returns scrubbed when redactedFields is non-empty (strongest signal)', () => {
    // redaction wins even over a policy_violation type.
    expect(deriveVerdict({ ...BASE, type: 'policy_violation', redactedFields: ['user_id'] })).toBe('scrubbed')
  })

  it('ignores an empty redactedFields array', () => {
    expect(deriveVerdict({ ...BASE, type: 'llm_call', redactedFields: [] })).toBe('allowed')
  })

  it('returns denied for a credential_leak', () => {
    expect(deriveVerdict({ ...BASE, type: 'credential_leak' })).toBe('denied')
  })

  it('returns denied for a policy_violation with no approval in the reason', () => {
    expect(deriveVerdict({ ...BASE, type: 'policy_violation', violationReason: 'egress to unknown host' })).toBe('denied')
  })

  it('returns pending for a policy_violation whose reason names an approval', () => {
    expect(
      deriveVerdict({ ...BASE, type: 'policy_violation', violationReason: 'refund > $100 requires human approval' }),
    ).toBe('pending')
  })

  it('returns allowed for a plain llm_call / tool_call', () => {
    expect(deriveVerdict({ ...BASE, type: 'llm_call' })).toBe('allowed')
    expect(deriveVerdict({ ...BASE, type: 'tool_call' })).toBe('allowed')
  })

  it('never emits narrowed from current data', () => {
    // No field distinguishes narrowed; exhaustively check the known shapes.
    const shapes: TraceEvent[] = [
      { ...BASE, type: 'llm_call' },
      { ...BASE, type: 'tool_call' },
      { ...BASE, type: 'policy_violation', violationReason: 'x' },
      { ...BASE, type: 'credential_leak' },
      { ...BASE, redactedFields: ['a'] },
    ]
    expect(shapes.map(deriveVerdict)).not.toContain('narrowed')
  })
})

describe('buildLayerSteps', () => {
  it('always produces L0–L3 in order, with L0/L1 passing', () => {
    const steps = buildLayerSteps(BASE)
    expect(steps.map(s => s.id)).toEqual(['l0', 'l1', 'l2', 'l3'])
    expect(steps[0].status).toBe('pass')
    expect(steps[1].status).toBe('pass')
  })

  it('marks L1 and L2 backend-gated (trust/DID/policy id not in the API)', () => {
    const steps = buildLayerSteps(BASE)
    expect(steps[1].backendGated).toBe(true)
    expect(steps[2].backendGated).toBe(true)
    expect(steps[0].backendGated).toBe(false)
    expect(steps[3].backendGated).toBe(false)
  })

  it('sets L2 fail + L3 unreached when denied', () => {
    const steps = buildLayerSteps({ ...BASE, type: 'credential_leak' })
    expect(steps[2].status).toBe('fail')
    expect(steps[3].status).toBe('unreached')
  })

  it('sets L2 pending + L3 unreached when awaiting approval', () => {
    const steps = buildLayerSteps({ ...BASE, type: 'policy_violation', violationReason: 'needs approval' })
    expect(steps[2].status).toBe('pending')
    expect(steps[3].status).toBe('unreached')
  })

  it('sets L2 pass + L3 scrub with the redacted list when scrubbed', () => {
    const steps = buildLayerSteps({ ...BASE, redactedFields: ['user_id', 'email'] })
    expect(steps[2].status).toBe('pass')
    expect(steps[3].status).toBe('scrub')
    expect(steps[3].detail).toContain('user_id')
    expect(steps[3].detail).toContain('email')
  })

  it('sets L3 skip (pass-through) when allowed with no redaction', () => {
    const steps = buildLayerSteps({ ...BASE, type: 'llm_call' })
    expect(steps[3].status).toBe('skip')
  })

  it('carries the violation reason into the L2 detail', () => {
    const steps = buildLayerSteps({ ...BASE, type: 'policy_violation', violationReason: 'egress blocked' })
    expect(steps[2].detail).toBe('egress blocked')
  })
})
