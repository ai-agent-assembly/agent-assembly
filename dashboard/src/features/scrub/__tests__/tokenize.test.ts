import { describe, it, expect } from 'vitest'
import { countMatchesByDetector, tokenize } from '../tokenize'
import { BUILT_IN_DETECTORS, PREVIEWABLE_DETECTORS } from '../detectors'
import type { ScrubDetector } from '../types'

const byId = (id: string): ScrubDetector => {
  const found = BUILT_IN_DETECTORS.find((d) => d.id === id)
  if (!found) throw new Error(`no detector ${id}`)
  return found
}

const AWS = byId('AwsAccessKey')
const EMAIL = byId('EmailAddress')
const ENTROPY = byId('GenericHighEntropy')

describe('tokenize', () => {
  it('returns a single plain token when no detector can be approximated', () => {
    expect(tokenize('hello world', [ENTROPY])).toEqual([{ kind: 'plain', text: 'hello world' }])
  })

  it('returns an empty array for empty input with no usable detector', () => {
    expect(tokenize('', [ENTROPY])).toEqual([])
  })

  it('emits a single match token when the entire input is one hit', () => {
    const tokens = tokenize('AKIAIOSFODNN7EXAMPLE', [AWS])
    expect(tokens).toHaveLength(1)
    expect(tokens[0]).toMatchObject({ kind: 'match', text: 'AKIAIOSFODNN7EXAMPLE' })
    if (tokens[0].kind === 'match') {
      expect(tokens[0].detector.id).toBe('AwsAccessKey')
    }
  })

  it('interleaves plain text and match tokens in order', () => {
    const tokens = tokenize('key=AKIAIOSFODNN7EXAMPLE for jane@acme.com end', [AWS, EMAIL])
    expect(tokens.map((t) => t.kind)).toEqual(['plain', 'match', 'plain', 'match', 'plain'])
    if (tokens[1].kind === 'match') expect(tokens[1].detector.id).toBe('AwsAccessKey')
    if (tokens[3].kind === 'match') expect(tokens[3].detector.id).toBe('EmailAddress')
  })

  it('resolves an sk-ant- token to AnthropicKey, not OpenAiKey', () => {
    // The scanner's AC ordering is load-bearing; the preview alternation has to
    // reproduce that tie-break or it teaches the wrong redaction label.
    const tokens = tokenize('sk-ant-api03-EXAMPLEEXAMPLEEXAMPLE')
    expect(tokens).toHaveLength(1)
    if (tokens[0].kind === 'match') expect(tokens[0].detector.id).toBe('AnthropicKey')
  })

  it('defaults to the previewable slice of the shipped catalogue', () => {
    const tokens = tokenize('ghp_EXAMPLEEXAMPLEEXAMPLEEX')
    expect(tokens).toHaveLength(1)
    if (tokens[0].kind === 'match') expect(tokens[0].detector.id).toBe('GitHubPat')
    expect(PREVIEWABLE_DETECTORS.some((d) => d.id === 'GitHubPat')).toBe(true)
  })

  it('never labels a match with a redaction string the gateway does not emit', () => {
    const tokens = tokenize('AKIAIOSFODNN7EXAMPLE jane@acme.com 123-45-6789')
    const labels = tokens.flatMap((t) => (t.kind === 'match' ? [t.detector.replace] : []))
    expect(labels.length).toBeGreaterThan(0)
    for (const label of labels) {
      expect(label).toMatch(/^\[REDACTED:[A-Za-z]+\]$/)
    }
    expect(labels).not.toContain('[REDACTED:PEM]')
  })

  it('countMatchesByDetector groups by detector id', () => {
    const tokens = tokenize('a@b.com and AKIAIOSFODNN7EXAMPLE and c@d.com', [AWS, EMAIL])
    const counts = countMatchesByDetector(tokens)
    expect(counts.EmailAddress).toBe(2)
    expect(counts.AwsAccessKey).toBe(1)
  })

  it('reports nothing for a detector that matched nothing, rather than zero', () => {
    const counts = countMatchesByDetector(tokenize('nothing here', [AWS, EMAIL]))
    expect(counts).toEqual({})
  })
})
