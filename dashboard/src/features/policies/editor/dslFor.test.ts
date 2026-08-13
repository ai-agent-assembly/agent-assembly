import { describe, expect, it } from 'vitest'
import { dslFor } from './dslFor'
import type { PolicyDraft, RuleDraft } from './types'

function rule(patch: Partial<RuleDraft> = {}): RuleDraft {
  return {
    id: 'r1',
    resource: 'gmail',
    verb: ['read'],
    action: 'allow',
    condition: ['always'],
    timeWindow: 'always',
    severity: 'warn',
    ...patch,
  }
}

function draft(patch: Partial<PolicyDraft> = {}): PolicyDraft {
  return {
    id: 'pol-x',
    name: 'Example policy',
    scope: 'research-bot-04',
    version: '1.2.0',
    status: 'active',
    rules: [rule()],
    ...patch,
  }
}

describe('dslFor', () => {
  it('emits the policy header from draft meta', () => {
    const out = dslFor(draft())
    expect(out).toContain('policy "pol-x" {')
    expect(out).toContain('  name    = "Example policy"')
    expect(out).toContain('  scope   = "research-bot-04"')
    expect(out).toContain('  version = "1.2.0"')
    expect(out.trimEnd().endsWith('}')).toBe(true)
  })

  it('renders a rule block with when/if/then clauses', () => {
    const out = dslFor(
      draft({
        rules: [
          rule({
            resource: 's3',
            verb: ['read', 'write'],
            condition: ['host in allowlist', 'business hours only'],
            action: 'allow',
            severity: 'block',
          }),
        ],
      }),
    )
    expect(out).toContain('  rule R1 {')
    expect(out).toContain('    when   resource == "s3" and verb in ["read", "write"]')
    expect(out).toContain('    if     "host in allowlist" and "business hours only"')
    expect(out).toContain('    then   allow')
    expect(out).toContain('      severity block')
  })

  it('falls back to /* none */ verbs and "always" condition when empty', () => {
    const out = dslFor(draft({ rules: [rule({ verb: [], condition: [] })] }))
    expect(out).toContain('verb in [/* none */]')
    expect(out).toContain('    if     "always"')
  })

  it('emits narrow_to lines for a narrow rule', () => {
    const out = dslFor(
      draft({
        rules: [rule({ action: 'narrow', narrowPaths: ['s3://reports/*', 's3://logs/*'] })],
      }),
    )
    expect(out).toContain('    then   narrow')
    expect(out).toContain('      narrow_to "s3://reports/*"')
    expect(out).toContain('      narrow_to "s3://logs/*"')
  })

  it('emits an approver block for an approval rule', () => {
    const out = dslFor(
      draft({
        rules: [
          rule({
            action: 'approval',
            approver: { who: 'security-oncall', nOfM: '2-of-3', sla: '1h' },
          }),
        ],
      }),
    )
    expect(out).toContain('      approver { who="security-oncall" n_of_m="2-of-3" sla="1h" }')
  })

  it('emits scrub, except and window lines when present', () => {
    const out = dslFor(
      draft({
        rules: [
          rule({
            action: 'scrub-then-allow',
            scrubFields: ['emails', 'SSN'],
            exceptions: ['ops@acme.com'],
            timeWindow: 'business hours',
          }),
        ],
      }),
    )
    expect(out).toContain('      scrub ["emails", "SSN"]')
    expect(out).toContain('      except "ops@acme.com"')
    expect(out).toContain('      window "business hours"')
  })

  it('omits the window line when the window is "always"', () => {
    const out = dslFor(draft({ rules: [rule({ timeWindow: 'always' })] }))
    expect(out).not.toContain('window')
  })

  it('separates multiple rule blocks with a blank line', () => {
    const out = dslFor(draft({ rules: [rule({ id: 'a' }), rule({ id: 'b' })] }))
    expect(out).toContain('  rule R1 {')
    expect(out).toContain('  rule R2 {')
  })
})
