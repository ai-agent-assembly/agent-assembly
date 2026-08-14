import { describe, expect, it } from 'vitest'
import {
  DEFAULT_SCOPE,
  extractEnforcementMode,
  extractScope,
  scopeFromMetadata,
  withEnforcementMode,
} from './policyYamlHelpers'

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

describe('extractScope', () => {
  it('returns metadata.scope when present', () => {
    expect(extractScope('metadata:\n  name: p1\n  scope: team:research\nrules: []\n')).toBe(
      'team:research',
    )
  })

  it('trims surrounding whitespace on the scope value', () => {
    expect(extractScope('metadata:\n  scope: "  agent:bot-04  "\n')).toBe('agent:bot-04')
  })

  it('falls back to the default scope when metadata.scope is absent', () => {
    expect(extractScope('metadata:\n  name: p1\nrules: []\n')).toBe(DEFAULT_SCOPE)
    expect(extractScope('rules: []\n')).toBe(DEFAULT_SCOPE)
  })

  it('falls back to the default scope for a blank scope value', () => {
    expect(extractScope('metadata:\n  scope: "   "\n')).toBe(DEFAULT_SCOPE)
  })

  it('falls back to the default scope for empty / whitespace input', () => {
    expect(extractScope('')).toBe(DEFAULT_SCOPE)
    expect(extractScope('   \n')).toBe(DEFAULT_SCOPE)
  })

  it('falls back to the default scope for malformed YAML', () => {
    expect(extractScope(': : : not valid')).toBe(DEFAULT_SCOPE)
  })
})

describe('scopeFromMetadata', () => {
  it('reads scope from an already-parsed document', () => {
    expect(scopeFromMetadata({ metadata: { scope: 'global' } })).toBe('global')
  })

  it('returns the default for a null / scope-less document', () => {
    expect(scopeFromMetadata(null)).toBe(DEFAULT_SCOPE)
    expect(scopeFromMetadata({ metadata: {} })).toBe(DEFAULT_SCOPE)
    expect(scopeFromMetadata({})).toBe(DEFAULT_SCOPE)
  })
})
