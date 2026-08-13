import { describe, expect, it } from 'vitest'
import { decodeApprovalCount, decodeApprovalList } from './schema'

/**
 * Unit coverage for the approvals decoders' own branches (AAASM-5380 S1 + S8).
 * Component tests prove the surfaces degrade; this proves the decoders — both
 * the conform and the reason-carrying reject paths.
 */
describe('decodeApprovalList', () => {
  const row = {
    id: 'ap-1',
    agent_id: 'agent-1',
    action: 'tool.call',
    status: 'pending',
    expires_at: '2026-08-05T12:00:00Z',
    created_at: '2026-08-05T11:00:00Z',
  }

  it('conforms a well-formed approvals list', () => {
    const r = decodeApprovalList([row])
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.value).toHaveLength(1)
  })

  it('rejects a row missing a required field, naming it', () => {
    const { expires_at: _e, ...noExpiry } = row
    void _e
    const r = decodeApprovalList([noExpiry])
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain('expires_at')
  })

  it('rejects a non-array body', () => {
    const r = decodeApprovalList({})
    expect(r.ok).toBe(false)
  })
})

describe('decodeApprovalCount (count-only surface)', () => {
  it('conforms count-only rows that omit the fields Overview never reads', () => {
    // A row with just an id (no agent_id/action/status/expires_at) is a
    // perfectly countable approval for the Overview card.
    const r = decodeApprovalCount([{ id: 'ap-1' }, { id: 'ap-2' }])
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.value).toHaveLength(2)
  })

  it('conforms rows carrying created_at (the urgency headline reads it)', () => {
    const r = decodeApprovalCount([{ created_at: '2026-08-05T11:00:00Z' }])
    expect(r.ok).toBe(true)
  })

  it('rejects a non-array body', () => {
    const r = decodeApprovalCount({ items: [] })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toBeTruthy()
  })

  it('rejects non-object rows (not a readable list)', () => {
    const r = decodeApprovalCount(['nope', 42])
    expect(r.ok).toBe(false)
  })

  it('rejects a non-string created_at', () => {
    const r = decodeApprovalCount([{ created_at: 123 }])
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain('created_at')
  })
})
