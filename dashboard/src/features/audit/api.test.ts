import { describe, expect, it } from 'vitest'
import { isSandboxSummaryEmpty, type SandboxSummaryResponse } from './api'

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
