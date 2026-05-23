import { describe, expect, it } from 'vitest'
import {
  extractSandboxInfo,
  isSandboxSummaryEmpty,
  type SandboxSummaryResponse,
} from './api'

function summary(partial: Partial<SandboxSummaryResponse['counts']> = {}): SandboxSummaryResponse {
  return {
    counts: {
      would_be_denies: 0,
      would_be_redactions: 0,
      would_be_pending_approvals: 0,
      ...partial,
    },
    top_rule: null,
    window_secs: 86_400,
    generated_at: '2026-05-23T14:00:00Z',
  }
}

describe('isSandboxSummaryEmpty', () => {
  it('returns true when every would-be count is zero', () => {
    expect(isSandboxSummaryEmpty(summary())).toBe(true)
  })

  it('returns false when any count is non-zero', () => {
    expect(isSandboxSummaryEmpty(summary({ would_be_denies: 1 }))).toBe(false)
    expect(isSandboxSummaryEmpty(summary({ would_be_redactions: 1 }))).toBe(false)
    expect(isSandboxSummaryEmpty(summary({ would_be_pending_approvals: 1 }))).toBe(false)
  })
})

describe('extractSandboxInfo', () => {
  it('returns dryRun=true and the shadow decision when payload carries them', () => {
    const info = extractSandboxInfo('{"dry_run":true,"shadow_decision":"deny"}')
    expect(info.dryRun).toBe(true)
    expect(info.shadowDecision).toBe('deny')
  })

  it('returns dryRun=false when the payload omits dry_run', () => {
    const info = extractSandboxInfo('{"decision":"Allow"}')
    expect(info.dryRun).toBe(false)
    expect(info.shadowDecision).toBeNull()
  })

  it('treats dry_run=false explicitly as live enforcement', () => {
    const info = extractSandboxInfo('{"dry_run":false}')
    expect(info.dryRun).toBe(false)
  })

  it('falls back to dryRun=false for malformed JSON', () => {
    expect(extractSandboxInfo('not-json').dryRun).toBe(false)
  })

  it('treats empty-string shadow_decision as null', () => {
    expect(extractSandboxInfo('{"dry_run":true,"shadow_decision":""}').shadowDecision).toBeNull()
  })
})
