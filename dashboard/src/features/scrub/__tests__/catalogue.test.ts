/**
 * The catalogue join keeps the API as the authority (AAASM-5347).
 *
 * These assert the join's one rule from both sides: nothing local can add a row
 * the gateway did not serve, and nothing missing locally can remove one it did.
 */
import { describe, it, expect } from 'vitest'
import { classSlug, entryName, toCatalogue } from '../catalogue'
import { BUILT_IN_DETECTORS } from '../detectors'
import type { ScrubPatternRow } from '../api'

const row = (kind: string, over: Partial<ScrubPatternRow> = {}): ScrubPatternRow => ({
  kind,
  redaction_label: `[REDACTED:${kind}]`,
  category: 'api_key',
  severity: 'critical',
  builtin: true,
  ...over,
})

describe('toCatalogue', () => {
  it('preserves the scanner’s declaration order as served', () => {
    // Ordering is load-bearing on this surface: Aho-Corasick breaks a
    // same-position collision by lowest pattern index, so re-sorting the served
    // rows would show a precedence the scanner does not have.
    const entries = toCatalogue([row('AnthropicKey'), row('OpenAiKey'), row('AwsAccessKey')])
    expect(entries.map((e) => e.kind)).toEqual(['AnthropicKey', 'OpenAiKey', 'AwsAccessKey'])
  })

  it('takes category, severity and the redaction label from the response', () => {
    const [entry] = toCatalogue([
      row('SsnPattern', { category: 'pii', severity: 'high', redaction_label: '[REDACTED:SsnPattern]' }),
    ])
    expect(entry.category).toBe('pii')
    expect(entry.severity).toBe('high')
    expect(entry.redactionLabel).toBe('[REDACTED:SsnPattern]')
  })

  it('omits a locally-known detector the gateway did not serve', () => {
    // `Custom` is policy-defined, so `/scrub/patterns` never lists it. The local
    // table still carries a row; membership must come from the API regardless.
    expect(BUILT_IN_DETECTORS.some((d) => d.id === 'Custom')).toBe(true)
    const entries = toCatalogue([row('AwsAccessKey')])
    expect(entries.map((e) => e.kind)).not.toContain('Custom')
  })

  it('still renders a served kind the dashboard has never transcribed', () => {
    // Dropping it would hide a shipped detector because the *dashboard* is out
    // of date — an absence of information presented as an absence of detector.
    const [entry] = toCatalogue([row('AKindTheDashboardHasNeverHeardOf')])
    expect(entry.kind).toBe('AKindTheDashboardHasNeverHeardOf')
    expect(entry.local).toBeUndefined()
  })

  it('attaches the local prose and preview regex when the kind is known', () => {
    const [entry] = toCatalogue([row('AwsAccessKey')])
    expect(entry.local?.detection).toMatch(/AKIA/)
    expect(entry.local?.previewRegex).toBeDefined()
  })
})

describe('entryName', () => {
  it('uses the transcribed human name when there is one', () => {
    const [entry] = toCatalogue([row('AwsAccessKey')])
    expect(entryName(entry)).toBe('AWS access key ID')
  })

  it('falls back to the kind verbatim rather than inventing a prettier one', () => {
    const [entry] = toCatalogue([row('SomeNewKind')])
    expect(entryName(entry)).toBe('SomeNewKind')
  })
})

describe('classSlug', () => {
  it('normalises only for the stylesheet, leaving the served value untouched', () => {
    const [entry] = toCatalogue([row('AwsAccessKey', { category: 'cloud_credential' })])
    expect(classSlug(entry.category)).toBe('cloud-credential')
    expect(entry.category).toBe('cloud_credential')
  })
})
