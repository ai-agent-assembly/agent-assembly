import { describe, expect, it } from 'vitest'
import { absent, isAbsent, isKnown, known } from '../../lib/truthfulness'
import { buildLayerSteps, deriveVerdict } from './decision'
import type { TraceEvent, TraceSeverity } from './types'

const NO_FIELD = 'TraceSpan has no such field'

/**
 * An event in the shape the real endpoint produces: operation and timestamps
 * are known, everything the span schema omits is `not-supported`.
 */
const BASE: TraceEvent = {
  id: 'e',
  timestamp: '2026-04-23T14:23:01Z',
  type: 'ToolCallIntercepted',
  agent: 'support-agent',
  parentSpanId: null,
  durationMs: known(12),
  decision: absent<string>('not-evaluated', 'no decision recorded'),
  payload: absent<unknown>('not-supported', NO_FIELD),
  payloadPreview: absent<string>('not-supported', NO_FIELD),
  severity: absent<TraceSeverity>('not-supported', NO_FIELD),
  redactedFields: absent<readonly string[]>('not-supported', NO_FIELD),
  violationReason: absent<string>('not-supported', NO_FIELD),
}

describe('deriveVerdict', () => {
  it('reads an explicit decision word from the wire', () => {
    expect(deriveVerdict({ ...BASE, decision: known('deny') })).toEqual(known('denied'))
    expect(deriveVerdict({ ...BASE, decision: known('allow') })).toEqual(known('allowed'))
    expect(deriveVerdict({ ...BASE, decision: known('scrub') })).toEqual(known('scrubbed'))
    expect(deriveVerdict({ ...BASE, decision: known('narrow') })).toEqual(known('narrowed'))
  })

  it('is insensitive to case and surrounding whitespace', () => {
    expect(deriveVerdict({ ...BASE, decision: known('  DENIED ') })).toEqual(known('denied'))
  })

  it('refuses to interpret a numeric decision', () => {
    // The audit-reconstruction path stringifies an integer into this field and
    // the schema documents no encoding for it. Guessing that "0" means allowed
    // would invent a contract; getting it backwards would report a denial as a
    // pass, which is the precise harm the vocabulary exists to prevent.
    const verdict = deriveVerdict({ ...BASE, decision: known('0') })
    expect(isAbsent(verdict)).toBe(true)
    expect(isAbsent(verdict) && verdict.state).toBe('not-evaluated')
  })

  it.each([
    ['PolicyViolation', 'denied'],
    ['CredentialLeakBlocked', 'denied'],
    ['MessageBlocked', 'denied'],
    ['ApprovalDenied', 'denied'],
    ['ApprovalGranted', 'allowed'],
    ['ApprovalRequested', 'pending'],
    ['ApprovalRouted', 'pending'],
    ['ApprovalEscalated', 'pending'],
  ] as const)('derives %s from the operation alone', (operation, expected) => {
    expect(deriveVerdict({ ...BASE, type: operation })).toEqual(known(expected))
  })

  it('prefers an explicit decision over the operation', () => {
    expect(deriveVerdict({ ...BASE, type: 'PolicyViolation', decision: known('allow') })).toEqual(
      known('allowed'),
    )
  })

  it.each([
    'ToolCallIntercepted',
    'ToolDispatched',
    'BudgetLimitApproached',
    'SandboxStarted',
    'AgentForceDeregistered',
  ])('reports no verdict for %s rather than defaulting to allowed', (operation) => {
    // The regression AAASM-5109 exposed: the old deriver ended in
    // `return 'allowed'`, so against the real wire — where none of its
    // snake_case tests could ever match — every span was stamped ✓ ALLOWED,
    // including ones that recorded a violation.
    const verdict = deriveVerdict({ ...BASE, type: operation })
    expect(isKnown(verdict)).toBe(false)
    expect(isAbsent(verdict) && verdict.state).toBe('not-evaluated')
  })

  it('never silently reports a violation as allowed', () => {
    const verdict = deriveVerdict({ ...BASE, type: 'PolicyViolation' })
    expect(isKnown(verdict) && verdict.value).toBe('denied')
  })

  it.each(['constructor', 'toString', 'hasOwnProperty', '__proto__'])(
    'does not resolve %s from the prototype as a verdict',
    (poison) => {
      // Both lookup tables are keyed by strings that arrive over the wire. As
      // plain objects, `TABLE['constructor']` returns `Object` — which is
      // `!== undefined` and would have been handed back as the verdict.
      const fromDecision = deriveVerdict({ ...BASE, decision: known(poison) })
      const fromOperation = deriveVerdict({ ...BASE, type: poison })

      expect(isAbsent(fromDecision) && fromDecision.state).toBe('not-evaluated')
      expect(isAbsent(fromOperation) && fromOperation.state).toBe('not-evaluated')
    },
  )
})

describe('buildLayerSteps', () => {
  it('always produces L0–L3 in order, with L0/L1 passing on evidence', () => {
    // L0 passes because a span exists at all; L1 because the envelope named the
    // agent. Neither is an assumption.
    const steps = buildLayerSteps(BASE)
    expect(steps.map(s => s.id)).toEqual(['l0', 'l1', 'l2', 'l3'])
    expect(steps[0].status).toEqual(known('pass'))
    expect(steps[1].status).toEqual(known('pass'))
  })

  it('marks L1 and L2 backend-gated (trust/DID/policy id not in the API)', () => {
    const steps = buildLayerSteps(BASE)
    expect(steps[1].backendGated).toBe(true)
    expect(steps[2].backendGated).toBe(true)
    expect(steps[0].backendGated).toBe(false)
    expect(steps[3].backendGated).toBe(false)
  })

  it('puts the operation, not a fabricated preview, in the L0 detail', () => {
    // The old L0 detail was `${type} — ${payloadPreview}`; with no preview on
    // the wire that interpolated the word "undefined" into the line.
    const [l0] = buildLayerSteps(BASE)
    expect(l0.detail).toEqual(known('ToolCallIntercepted'))
    expect(isKnown(l0.detail) && l0.detail.value).not.toContain('undefined')
  })

  it('names the agent in the L1 detail', () => {
    expect(buildLayerSteps(BASE)[1].detail).toEqual(known('agent support-agent'))
  })

  it('sets L2 fail + L3 unreached when denied', () => {
    const steps = buildLayerSteps({ ...BASE, type: 'CredentialLeakBlocked' })
    expect(steps[2].status).toEqual(known('fail'))
    expect(steps[3].status).toEqual(known('unreached'))
  })

  it('sets L2 pending + L3 unreached when awaiting approval', () => {
    const steps = buildLayerSteps({ ...BASE, type: 'ApprovalRequested' })
    expect(steps[2].status).toEqual(known('pending'))
    expect(steps[3].status).toEqual(known('unreached'))
  })

  it('sets L3 scrub with the redacted list when redaction is reported', () => {
    const steps = buildLayerSteps({
      ...BASE,
      decision: known('scrub'),
      redactedFields: known<readonly string[]>(['user_id', 'email']),
    })
    expect(steps[2].status).toEqual(known('pass'))
    expect(isKnown(steps[3].detail) && steps[3].detail.value).toContain('user_id')
    expect(isKnown(steps[3].detail) && steps[3].detail.value).toContain('email')
  })

  it('leaves L2 absent when no verdict is derivable', () => {
    const steps = buildLayerSteps(BASE)
    expect(isAbsent(steps[2].status) && steps[2].status.state).toBe('not-evaluated')
  })

  it('leaves L3 not-supported rather than claiming a clean pass-through', () => {
    // The old deriver reported `skip` here, which asserts "redaction ran and
    // found nothing to remove". No field on the span supports that claim.
    const steps = buildLayerSteps({ ...BASE, decision: known('allow') })
    expect(isAbsent(steps[3].status) && steps[3].status.state).toBe('not-supported')
    expect(isAbsent(steps[3].detail) && steps[3].detail.state).toBe('not-supported')
  })

  it('leaves the L2 detail absent rather than asserting no violation', () => {
    // "no policy violation recorded" reads as an all-clear; the reason field
    // does not exist on the span, so the absence is reported as such.
    const steps = buildLayerSteps(BASE)
    expect(isAbsent(steps[2].detail) && steps[2].detail.state).toBe('not-supported')
  })

  it('carries a violation reason into the L2 detail when one exists', () => {
    const steps = buildLayerSteps({
      ...BASE,
      type: 'PolicyViolation',
      violationReason: known('egress blocked'),
    })
    expect(steps[2].detail).toEqual(known('egress blocked'))
  })
})
