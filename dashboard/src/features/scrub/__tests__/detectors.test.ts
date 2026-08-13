/**
 * Guards on the regenerated detector catalogue (AAASM-5156).
 *
 * These assertions are the reason the catalogue can be trusted: they re-derive,
 * from the file, the two properties the previous fixture violated — that every
 * id is a real `CredentialKind::as_str()` value, and that every redaction label
 * is the one `aa-security` emits for it. The dead-detector list is asserted
 * negatively so a future edit cannot quietly re-add a pattern the scanner has
 * never had.
 */
import { describe, it, expect } from 'vitest'
import {
  BUILT_IN_DETECTORS,
  PREVIEWABLE_DETECTORS,
  UNPREVIEWABLE_DETECTORS,
} from '../detectors'
import { redactionLabel } from '../types'

/**
 * `CredentialKind::as_str()` in full, transcribed from
 * `aa-security/src/scanner.rs`. Kept as a literal rather than derived from the
 * catalogue so the test fails if the catalogue drifts, in either direction.
 */
const CREDENTIAL_KINDS = [
  'AnthropicKey',
  'AwsAccessKey',
  'AzureConnectionString',
  'CreditCardLuhn',
  'EcPrivateKey',
  'EmailAddress',
  'GcpServiceAccount',
  'GenericHighEntropy',
  'GitHubAppToken',
  'GitHubOAuthToken',
  'GitHubPat',
  'GitHubRefreshToken',
  'GitHubUserToken',
  'MongodbUrl',
  'MysqlUrl',
  'OpenAiKey',
  'OpensshPrivateKey',
  'PgpPrivateKey',
  'PostgresUrl',
  'PrivateKey',
  'RsaPrivateKey',
  'SlackAppToken',
  'SlackBotToken',
  'SlackOAuthToken',
  'SlackRefreshToken',
  'SlackUserToken',
  'SsnPattern',
  'Custom',
] as const

/** The fixture ids AAASM-5156 found had no detector behind them at all. */
const PHANTOM_IDS = ['AWS_SECRET', 'JWT', 'INTERNAL_URL', 'PHONE'] as const

/** Labels the previous fixture taught that the gateway never writes. */
const PHANTOM_LABELS = [
  '[REDACTED:PEM]',
  '[REDACTED:AWS_KEY]',
  '[REDACTED:CC]',
  '[REDACTED:INT_URL]',
  '[REDACTED:SLACK]',
  '[REDACTED:EMAIL]',
] as const

describe('BUILT_IN_DETECTORS', () => {
  it('covers exactly the shipped CredentialKind set, with no extras', () => {
    expect([...BUILT_IN_DETECTORS.map((d) => d.id)].sort()).toEqual([...CREDENTIAL_KINDS].sort())
  })

  it('names 27 compiled-in detectors plus the one policy-defined kind', () => {
    expect(BUILT_IN_DETECTORS.filter((d) => d.origin === 'built-in')).toHaveLength(27)
    expect(BUILT_IN_DETECTORS.filter((d) => d.origin === 'policy-defined')).toHaveLength(1)
  })

  it('labels every entry exactly as CredentialFinding::new does', () => {
    for (const d of BUILT_IN_DETECTORS) {
      expect(d.replace).toBe(`[REDACTED:${d.id}]`)
      expect(d.replace).toBe(redactionLabel(d.id))
    }
  })

  it('teaches none of the labels the gateway never emits', () => {
    const labels = BUILT_IN_DETECTORS.map((d) => d.replace)
    for (const phantom of PHANTOM_LABELS) {
      expect(labels).not.toContain(phantom)
    }
  })

  it('carries none of the four detectors that never existed', () => {
    const ids = BUILT_IN_DETECTORS.map((d) => d.id)
    for (const phantom of PHANTOM_IDS) {
      expect(ids).not.toContain(phantom)
    }
  })

  it('asserts no enabled state, hit count or severity for any detector', () => {
    for (const d of BUILT_IN_DETECTORS) {
      const record = d as unknown as Record<string, unknown>
      expect(record.enabled).toBeUndefined()
      expect(record.hits24h).toBeUndefined()
      expect(record.severity).toBeUndefined()
    }
  })

  it('keeps sk-ant- ahead of sk-, the ordering the scanner depends on', () => {
    const ids = BUILT_IN_DETECTORS.map((d) => d.id)
    expect(ids.indexOf('AnthropicKey')).toBeLessThan(ids.indexOf('OpenAiKey'))
  })

  it('gives every detector a non-empty prose detection description', () => {
    for (const d of BUILT_IN_DETECTORS) {
      expect(d.detection.length).toBeGreaterThan(0)
    }
  })

  it('compiles every preview approximation into a usable regex', () => {
    for (const d of PREVIEWABLE_DETECTORS) {
      expect(() => new RegExp(d.previewRegex as string)).not.toThrow()
    }
  })

  it('withholds a preview regex only where the browser genuinely cannot approximate', () => {
    expect(UNPREVIEWABLE_DETECTORS.map((d) => d.id).sort()).toEqual([
      'Custom',
      'GenericHighEntropy',
    ])
    expect(PREVIEWABLE_DETECTORS.length + UNPREVIEWABLE_DETECTORS.length).toBe(
      BUILT_IN_DETECTORS.length,
    )
  })

  it('matches its own example with its own preview regex', () => {
    for (const d of PREVIEWABLE_DETECTORS) {
      expect(d.example, `${d.id} needs an example`).toBeDefined()
      expect(
        new RegExp(d.previewRegex as string).test(d.example as string),
        `${d.id} example should match its preview regex`,
      ).toBe(true)
    }
  })
})
