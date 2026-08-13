import { describe, expect, it } from 'vitest'
import { draftFromPolicy } from './draftFromPolicy'
import type { components } from '../../../api/generated/schema'

type PolicyResponse = components['schemas']['PolicyResponse']

function policy(patch: Partial<PolicyResponse> = {}): PolicyResponse {
  return {
    name: 'p',
    version: '1.0.0',
    rule_count: 1,
    active: false,
    policy_yaml: '',
    ...patch,
  }
}

const EDITOR_YAML = [
  'apiVersion: agent-assembly/v1',
  'kind: Policy',
  'metadata:',
  '  name: research-bot',
  '  scope: team:research',
  '  version: 0.3.0',
  'spec:',
  '  rules:',
  '    - id: R1-gmail-allow',
  '      match:',
  '        actions:',
  '          - gmail:read',
  '          - gmail:write',
  '      effect: allow',
  '      audit: true',
  '    - id: R2-s3-approval',
  '      match:',
  '        actions:',
  '          - s3:write',
  '      effect: require_approval',
  '      approval:',
  '        timeout_seconds: 1800',
  '        approvers:',
  '          - data-platform-lead',
  '      audit: true',
  '    - id: R3-shell-deny',
  '      match:',
  '        actions:',
  '          - shell:exec',
  '      effect: block',
  '      audit: true',
  '',
].join('\n')

describe('draftFromPolicy', () => {
  it('maps identity + status from the PolicyResponse', () => {
    const draft = draftFromPolicy(policy({ name: 'x', version: '2.1.0', active: true, policy_yaml: EDITOR_YAML }))
    expect(draft.id).toBe('pol-x')
    expect(draft.name).toBe('x')
    expect(draft.version).toBe('2.1.0')
    expect(draft.status).toBe('active')
  })

  it('marks a non-active policy as proposed (drives the draft callout)', () => {
    const draft = draftFromPolicy(policy({ active: false, policy_yaml: EDITOR_YAML }))
    expect(draft.status).toBe('proposed')
  })

  it('recovers scope + real rules from editor-schema policy_yaml', () => {
    const draft = draftFromPolicy(policy({ policy_yaml: EDITOR_YAML }))
    expect(draft.scope).toBe('team:research')
    expect(draft.rules).toHaveLength(3)

    const [r1, r2, r3] = draft.rules
    expect(r1.resource).toBe('gmail')
    expect(r1.verb).toEqual(['read', 'write'])
    expect(r1.action).toBe('allow')
    expect(r1.unknown).toBeUndefined()

    expect(r2.resource).toBe('s3')
    expect(r2.verb).toEqual(['write'])
    expect(r2.action).toBe('approval')
    expect(r2.approver).toEqual({ who: 'data-platform-lead', nOfM: '1-of-1', sla: '30m' })

    expect(r3.action).toBe('deny')
  })

  it('does not fabricate rules — an empty snapshot yields unknown placeholders', () => {
    const draft = draftFromPolicy(policy({ rule_count: 3, policy_yaml: '' }))
    expect(draft.scope).toBe('global')
    expect(draft.rules).toHaveLength(3)
    expect(draft.rules.every((r) => r.unknown)).toBe(true)
  })

  it('marks section-based (non editor-schema) policies as unknown, not a stub', () => {
    const sectionYaml = [
      'apiVersion: agent-assembly/v1',
      'metadata:',
      '  name: medium-risk',
      'spec:',
      '  tools:',
      '    file_read:',
      '      allow: true',
      '',
    ].join('\n')
    const draft = draftFromPolicy(policy({ rule_count: 2, policy_yaml: sectionYaml }))
    expect(draft.rules).toHaveLength(2)
    expect(draft.rules.every((r) => r.unknown)).toBe(true)
  })

  it('always yields at least one rule so a real policy never trips "no rules"', () => {
    const draft = draftFromPolicy(policy({ rule_count: 0, policy_yaml: '' }))
    expect(draft.rules).toHaveLength(1)
    expect(draft.rules[0].unknown).toBe(true)
  })

  it('marks an individual rule unknown when its resource is unrecognised', () => {
    const yaml = [
      'spec:',
      '  rules:',
      '    - match:',
      '        actions:',
      '          - mystery:read',
      '      effect: allow',
      '',
    ].join('\n')
    const draft = draftFromPolicy(policy({ policy_yaml: yaml }))
    expect(draft.rules).toHaveLength(1)
    expect(draft.rules[0].unknown).toBe(true)
  })
})
