import { describe, expect, it } from 'vitest'
import { extractEnforcementMode, withEnforcementMode } from './policyYamlHelpers'

describe('extractEnforcementMode', () => {
  it('returns the top-level mode when set', () => {
    expect(extractEnforcementMode('enforcement_mode: observe\nrules: []\n')).toBe('observe')
    expect(extractEnforcementMode('enforcement_mode: enforce\n')).toBe('enforce')
    expect(extractEnforcementMode('enforcement_mode: disabled\n')).toBe('disabled')
  })

  it('falls through to metadata.enforcement_mode when only the envelope form is set', () => {
    expect(
      extractEnforcementMode('metadata:\n  name: p1\n  enforcement_mode: observe\nrules: []\n'),
    ).toBe('observe')
  })

  it('returns null when the field is absent', () => {
    expect(extractEnforcementMode('rules: []\n')).toBeNull()
    expect(extractEnforcementMode('metadata:\n  name: p1\nrules: []\n')).toBeNull()
  })

  it('returns null for unknown mode strings', () => {
    expect(extractEnforcementMode('enforcement_mode: foobar\n')).toBeNull()
  })

  it('returns null for empty / whitespace input', () => {
    expect(extractEnforcementMode('')).toBeNull()
    expect(extractEnforcementMode('   \n')).toBeNull()
  })

  it('returns null for malformed YAML', () => {
    expect(extractEnforcementMode(': : : not valid')).toBeNull()
  })
})

describe('withEnforcementMode', () => {
  it('inserts enforcement_mode when absent', () => {
    const out = withEnforcementMode('rules: []\n', 'enforce')
    expect(extractEnforcementMode(out)).toBe('enforce')
  })

  it('replaces an existing top-level enforcement_mode', () => {
    const out = withEnforcementMode('enforcement_mode: observe\nrules: []\n', 'enforce')
    expect(extractEnforcementMode(out)).toBe('enforce')
  })

  it('preserves unrelated fields and comments', () => {
    const src = '# important\nname: my-policy\nenforcement_mode: observe\nrules: []\n'
    const out = withEnforcementMode(src, 'enforce')
    expect(out).toContain('# important')
    expect(out).toContain('name: my-policy')
    expect(out).toContain('rules:')
    expect(extractEnforcementMode(out)).toBe('enforce')
  })

  it('returns input unchanged for empty or malformed YAML', () => {
    expect(withEnforcementMode('', 'enforce')).toBe('')
    expect(withEnforcementMode(': : : not valid', 'enforce')).toBe(': : : not valid')
  })
})
