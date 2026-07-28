import { describe, it, expect } from 'vitest'
import type { Approval } from './api'
import {
  deriveApprovalsSummary,
  formatAge,
  formatApprovalsSummary,
} from './summary'

const NOW = new Date('2026-05-20T12:00:00Z').getTime()

function approval(createdAt: string): Approval {
  return {
    id: `id-${createdAt}`,
    agent_id: 'agent-1',
    action: 'send_email',
    reason: 'test',
    status: 'pending',
    created_at: createdAt,
    expires_at: '',
  }
}

describe('deriveApprovalsSummary', () => {
  it('counts high-urgency (<1h old) approvals as urgent', () => {
    const summary = deriveApprovalsSummary(
      [
        approval('2026-05-20T11:55:00Z'), // 5m — urgent
        approval('2026-05-20T11:30:00Z'), // 30m — urgent
        approval('2026-05-20T10:00:00Z'), // 2h — not urgent
        approval('2026-05-20T04:00:00Z'), // 8h — not urgent
      ],
      NOW,
    )
    expect(summary.urgentCount).toBe(2)
  })

  it('reports the age of the oldest approval', () => {
    const summary = deriveApprovalsSummary(
      [approval('2026-05-20T11:54:00Z'), approval('2026-05-20T10:00:00Z')],
      NOW,
    )
    expect(summary.oldestAgeMs).toBe(2 * 60 * 60 * 1000)
  })

  it('returns null oldest age for an empty queue', () => {
    const summary = deriveApprovalsSummary([], NOW)
    expect(summary).toEqual({ urgentCount: 0, oldestAgeMs: null })
  })

  it('ignores unparseable created_at when finding the oldest', () => {
    const summary = deriveApprovalsSummary(
      [approval('not-a-date'), approval('2026-05-20T11:54:00Z')],
      NOW,
    )
    expect(summary.oldestAgeMs).toBe(6 * 60 * 1000)
  })
})

describe('formatAge', () => {
  it('formats minutes under an hour', () => {
    expect(formatAge(6 * 60 * 1000)).toBe('6m')
    expect(formatAge(0)).toBe('0m')
  })

  it('formats hours under a day', () => {
    expect(formatAge(2 * 60 * 60 * 1000)).toBe('2h')
  })

  it('formats days at or above 24h', () => {
    expect(formatAge(3 * 24 * 60 * 60 * 1000)).toBe('3d')
  })
})

describe('formatApprovalsSummary', () => {
  it('builds "{n} urgent · oldest {age}" for a known queue', () => {
    const summary = deriveApprovalsSummary(
      [approval('2026-05-20T11:54:00Z'), approval('2026-05-20T11:30:00Z')],
      NOW,
    )
    expect(formatApprovalsSummary(summary)).toBe('2 urgent · oldest 30m')
  })

  it('returns null when there is no oldest age', () => {
    expect(formatApprovalsSummary({ urgentCount: 0, oldestAgeMs: null })).toBeNull()
  })
})
