import { describe, it, expect } from 'vitest'
import { countMatchesByPattern, tokenize } from '../tokenize'
import type { ScrubPattern } from '../types'

const AWS: ScrubPattern = {
  id: 'AWS_KEY',
  name: 'AWS access key ID',
  regex: 'AKIA[0-9A-Z]{16}',
  example: 'AKIAIOSFODNN7EXAMPLE',
  replace: '[REDACTED:AWS_KEY]',
  severity: 'critical',
  hits24h: 0,
  enabled: true,
}

const EMAIL: ScrubPattern = {
  id: 'EMAIL_PII',
  name: 'Email',
  regex: '[a-z0-9._%+-]+@[a-z0-9.-]+',
  example: 'a@b.co',
  replace: '[REDACTED:EMAIL]',
  severity: 'medium',
  hits24h: 0,
  enabled: true,
}

const PHONE_DISABLED: ScrubPattern = {
  ...EMAIL,
  id: 'PHONE',
  name: 'Phone',
  regex: '[0-9]{10}',
  example: '0123456789',
  replace: '[REDACTED:PHONE]',
  severity: 'low',
  enabled: false,
}

describe('tokenize', () => {
  it('returns a single plain token when no patterns are enabled', () => {
    const tokens = tokenize('hello world', [PHONE_DISABLED])
    expect(tokens).toEqual([{ kind: 'plain', text: 'hello world' }])
  })

  it('returns an empty array for empty input with no enabled patterns', () => {
    expect(tokenize('', [PHONE_DISABLED])).toEqual([])
  })

  it('emits a single match token when the entire input is one pattern hit', () => {
    const tokens = tokenize('AKIAABCDEFGHIJKLMNOP', [AWS])
    expect(tokens).toHaveLength(1)
    expect(tokens[0]).toMatchObject({ kind: 'match', text: 'AKIAABCDEFGHIJKLMNOP' })
    if (tokens[0].kind === 'match') {
      expect(tokens[0].pattern.id).toBe('AWS_KEY')
    }
  })

  it('interleaves plain text and match tokens in the correct order', () => {
    const text = 'key=AKIAABCDEFGHIJKLMNOP for jane@acme.com end'
    const tokens = tokenize(text, [AWS, EMAIL])
    const kinds = tokens.map((t) => t.kind)
    expect(kinds).toEqual(['plain', 'match', 'plain', 'match', 'plain'])
    expect(tokens[1]).toMatchObject({ kind: 'match' })
    if (tokens[1].kind === 'match') expect(tokens[1].pattern.id).toBe('AWS_KEY')
    if (tokens[3].kind === 'match') expect(tokens[3].pattern.id).toBe('EMAIL_PII')
  })

  it('skips disabled patterns even when their regex would match', () => {
    const tokens = tokenize('call 0123456789 then', [PHONE_DISABLED])
    expect(tokens).toEqual([{ kind: 'plain', text: 'call 0123456789 then' }])
  })

  it('countMatchesByPattern groups by pattern id', () => {
    const text = 'a@b.com and AKIAAAAAAAAAAAAAAAAA and c@d.com'
    const tokens = tokenize(text, [AWS, EMAIL])
    const counts = countMatchesByPattern(tokens)
    expect(counts.EMAIL_PII).toBe(2)
    expect(counts.AWS_KEY).toBe(1)
  })
})
