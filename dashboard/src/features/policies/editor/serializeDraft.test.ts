import YAML from 'yaml'
import { serializeDraft } from './serializeDraft'
import { defaultRule } from './constants'
import type { PolicyDraft, RuleDraft } from './types'

function ruleWith(patch: Partial<RuleDraft> = {}): RuleDraft {
  return { ...defaultRule(), ...patch }
}

function draftWith(patch: Partial<PolicyDraft> = {}): PolicyDraft {
  return {
    id: 'pol-test',
    name: 'audit-restrict-research',
    scope: 'research-bot-04',
    version: '2.3',
    status: 'proposed',
    rules: [ruleWith()],
    ...patch,
  }
}

function parseYaml(yaml: string) {
  return YAML.parse(yaml) as Record<string, unknown>
}

describe('serializeDraft — top-level shape', () => {
  it('emits apiVersion, kind, and metadata from the draft', () => {
    const out = serializeDraft(draftWith())
    const parsed = parseYaml(out)
    expect(parsed.apiVersion).toBe('agent-assembly/v1')
    expect(parsed.kind).toBe('Policy')
    expect(parsed.metadata).toEqual({
      name: 'audit-restrict-research',
      scope: 'research-bot-04',
      version: '2.3',
    })
  })

  it('emits a spec.rules array with one entry per draft rule', () => {
    const out = serializeDraft(draftWith({ rules: [ruleWith(), ruleWith({ resource: 's3' })] }))
    const parsed = parseYaml(out) as { spec: { rules: unknown[] } }
    expect(parsed.spec.rules).toHaveLength(2)
  })

  it('is deterministic for the same input', () => {
    const draft = draftWith()
    expect(serializeDraft(draft)).toBe(serializeDraft(draft))
  })

  it('parses cleanly as YAML', () => {
    expect(() => YAML.parse(serializeDraft(draftWith()))).not.toThrow()
  })
})

describe('serializeDraft — effect mapping', () => {
  it('maps action=allow to effect: allow without an approval block', () => {
    const out = serializeDraft(draftWith({ rules: [ruleWith({ action: 'allow' })] }))
    const rule = (parseYaml(out) as { spec: { rules: { effect: string; approval?: unknown }[] } })
      .spec.rules[0]
    expect(rule.effect).toBe('allow')
    expect(rule.approval).toBeUndefined()
  })

  it('maps action=deny to effect: block', () => {
    const out = serializeDraft(draftWith({ rules: [ruleWith({ action: 'deny' })] }))
    const rule = (parseYaml(out) as { spec: { rules: { effect: string }[] } }).spec.rules[0]
    expect(rule.effect).toBe('block')
  })

  it('maps action=approval to require_approval with an approval block', () => {
    const out = serializeDraft(
      draftWith({
        rules: [
          ruleWith({
            action: 'approval',
            approver: { who: 'security-oncall', nOfM: '1-of-1', sla: '30m' },
          }),
        ],
      }),
    )
    const rule = (
      parseYaml(out) as {
        spec: { rules: { effect: string; approval: { timeout_seconds: number; approvers: string[] } }[] }
      }
    ).spec.rules[0]
    expect(rule.effect).toBe('require_approval')
    expect(rule.approval.timeout_seconds).toBe(1800)
    expect(rule.approval.approvers).toEqual(['security-oncall'])
  })

  it('maps SLA strings to their second equivalents', () => {
    const cases: Array<[
      '5m' | '15m' | '30m' | '1h' | '4h' | '24h',
      number,
    ]> = [
      ['5m', 300],
      ['15m', 900],
      ['30m', 1800],
      ['1h', 3600],
      ['4h', 14400],
      ['24h', 86400],
    ]
    for (const [sla, seconds] of cases) {
      const out = serializeDraft(
        draftWith({
          rules: [
            ruleWith({ action: 'approval', approver: { who: 'agent-owner', nOfM: '1-of-1', sla } }),
          ],
        }),
      )
      const rule = (
        parseYaml(out) as {
          spec: { rules: { approval: { timeout_seconds: number } }[] }
        }
      ).spec.rules[0]
      expect(rule.approval.timeout_seconds).toBe(seconds)
    }
  })

  it('maps narrow and scrub-then-allow to plain allow (lossy by design)', () => {
    const narrow = serializeDraft(draftWith({ rules: [ruleWith({ action: 'narrow' })] }))
    const scrub = serializeDraft(draftWith({ rules: [ruleWith({ action: 'scrub-then-allow' })] }))
    const narrowRule = (parseYaml(narrow) as { spec: { rules: { effect: string }[] } }).spec.rules[0]
    const scrubRule = (parseYaml(scrub) as { spec: { rules: { effect: string }[] } }).spec.rules[0]
    expect(narrowRule.effect).toBe('allow')
    expect(scrubRule.effect).toBe('allow')
  })
})

describe('serializeDraft — actions cross-product', () => {
  it('emits resource:verb pairs for every verb in the rule', () => {
    const out = serializeDraft(
      draftWith({ rules: [ruleWith({ resource: 'gmail', verb: ['read', 'write', 'delete'] })] }),
    )
    const actions = (
      parseYaml(out) as { spec: { rules: { match: { actions: string[] } }[] } }
    ).spec.rules[0].match.actions
    expect(actions).toEqual(['gmail:read', 'gmail:write', 'gmail:delete'])
  })

  it('emits an empty actions list when verb is empty', () => {
    const out = serializeDraft(
      draftWith({ rules: [ruleWith({ verb: [] })] }),
    )
    const actions = (
      parseYaml(out) as { spec: { rules: { match: { actions: string[] } }[] } }
    ).spec.rules[0].match.actions
    expect(actions).toEqual([])
  })
})

describe('serializeDraft — description capture', () => {
  it('records the editor-only fields in description', () => {
    const out = serializeDraft(
      draftWith({
        rules: [
          ruleWith({
            resource: 'gmail',
            verb: ['read'],
            action: 'narrow',
            condition: ['always', 'recipient not in @acme.com'],
            narrowPaths: ['gmail/labels/INBOX/*'],
            exceptions: ['ops@acme.com'],
            timeWindow: 'business hours',
            severity: 'block',
          }),
        ],
      }),
    )
    const desc = (
      parseYaml(out) as { spec: { rules: { description: string }[] } }
    ).spec.rules[0].description
    expect(desc).toContain('when gmail:[read]')
    expect(desc).toContain('if [always AND recipient not in @acme.com]')
    expect(desc).toContain('then narrow')
    expect(desc).toContain('narrow to [gmail/labels/INBOX/*]')
    expect(desc).toContain('except [ops@acme.com]')
    expect(desc).toContain('window: business hours')
    expect(desc).toContain('severity: block')
  })

  it('omits scrub list from description when not scrub-then-allow', () => {
    const out = serializeDraft(
      draftWith({ rules: [ruleWith({ action: 'allow', scrubFields: ['emails'] })] }),
    )
    const desc = (
      parseYaml(out) as { spec: { rules: { description: string }[] } }
    ).spec.rules[0].description
    expect(desc).not.toContain('scrub')
  })
})

describe('serializeDraft — rule id', () => {
  it('uses a stable R{n+1}-{resource}-{action} id', () => {
    const out = serializeDraft(
      draftWith({
        rules: [
          ruleWith({ resource: 's3', action: 'deny' }),
          ruleWith({ resource: 'gmail', action: 'approval' }),
        ],
      }),
    )
    const ids = (parseYaml(out) as { spec: { rules: { id: string }[] } }).spec.rules.map((r) => r.id)
    expect(ids).toEqual(['R1-s3-deny', 'R2-gmail-approval'])
  })
})
