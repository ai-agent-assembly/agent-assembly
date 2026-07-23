import { describe, expect, it } from 'vitest'
import { buildAuditCsv, buildComplianceReport } from './export'
import type { LogEntry } from './logs'

function entry(partial: Partial<LogEntry> & Pick<LogEntry, 'seq' | 'event_type'>): LogEntry {
  return {
    timestamp: '2026-05-11T14:02:11Z',
    agent_id: 'research-bot-04',
    session_id: 'sess-9a4f',
    payload: '{}',
    ...partial,
  }
}

const ROWS: LogEntry[] = [
  entry({
    seq: 1048,
    event_type: 'PolicyViolation',
    payload: JSON.stringify({
      decision: 'DENY',
      blocked_action: 'gmail/send',
      reason: 'External recipient, needs approval',
    }),
  }),
  entry({
    seq: 1047,
    event_type: 'LLMCall',
    agent_id: 'support-triage',
    payload: JSON.stringify({
      decision: 'ALLOW',
      model: 'claude-3-5-sonnet',
      prompt_tokens: 100,
      completion_tokens: 20,
      latency_ms: 900,
    }),
  }),
]

describe('buildAuditCsv', () => {
  it('emits a header row plus one line per entry', () => {
    const csv = buildAuditCsv(ROWS)
    const lines = csv.split('\r\n')
    expect(lines).toHaveLength(3)
    expect(lines[0]).toBe('seq,timestamp,agent_id,event_type,decision,summary,session_id')
  })

  it('carries the derived decision and summary columns', () => {
    const csv = buildAuditCsv(ROWS)
    expect(csv).toContain('DENY')
    expect(csv).toContain('claude-3-5-sonnet')
  })

  it('quotes cells that contain a comma so columns are not split', () => {
    const csv = buildAuditCsv([ROWS[0]])
    // The violation reason contains a comma and must be quoted.
    expect(csv).toContain('"gmail/send — External recipient, needs approval"')
  })

  it('produces only the header for an empty row set', () => {
    expect(buildAuditCsv([])).toBe('seq,timestamp,agent_id,event_type,decision,summary,session_id')
  })

  it('leaves the decision column empty when the payload carries no verdict', () => {
    const csv = buildAuditCsv([entry({ seq: 5, event_type: 'LLMCall', payload: '{"model":"gpt-4o"}' })])
    const cells = csv.split('\r\n')[1].split(',')
    // Column order: seq,timestamp,agent_id,event_type,decision,summary,session_id
    expect(cells[4]).toBe('')
  })

  it('renders a null wire field as an empty cell rather than "null"', () => {
    // The generated schema types every column as required, but the gateway can
    // still send a null field on a malformed row — the CSV must degrade to an
    // empty cell, not the literal string "null".
    const sparse = [
      {
        seq: 6,
        timestamp: '2026-05-11T14:02:11Z',
        agent_id: 'agent-x',
        event_type: 'LLMCall',
        session_id: null,
        payload: '{}',
      } as unknown as LogEntry,
    ]
    const line = buildAuditCsv(sparse).split('\r\n')[1]
    expect(line.endsWith(',')).toBe(true)
    expect(line).not.toContain('null')
  })
})

describe('buildComplianceReport', () => {
  const ctx = { typeFilter: 'all', agentFilter: 'all', search: '' }
  const now = new Date('2026-05-11T15:00:00Z')

  it('summarizes totals, type counts and decision verdicts', () => {
    const report = buildComplianceReport(ROWS, ctx, now)
    expect(report).toContain('Total events in report: 2')
    expect(report).toContain('- PolicyViolation: 1')
    expect(report).toContain('- DENY: 1')
    expect(report).toContain('- ALLOW: 1')
  })

  it('lists every policy violation in scope', () => {
    const report = buildComplianceReport(ROWS, ctx, now)
    expect(report).toContain('## Policy violations (1)')
    expect(report).toContain('research-bot-04: gmail/send')
  })

  it('reports zero violations honestly when there are none', () => {
    const report = buildComplianceReport([ROWS[1]], ctx, now)
    expect(report).toContain('## Policy violations (0)')
    expect(report).toContain('- None in scope.')
  })

  it('records the active filter scope', () => {
    const report = buildComplianceReport(ROWS, {
      typeFilter: 'PolicyViolation',
      agentFilter: 'research-bot-04',
      search: 'gmail',
    })
    expect(report).toContain('type=PolicyViolation')
    expect(report).toContain('agent=research-bot-04')
    expect(report).toContain('search=gmail')
  })

  it('states there are no verdicts when no row carries a decision', () => {
    const noVerdict = [entry({ seq: 10, event_type: 'LLMCall', payload: '{"model":"gpt-4o"}' })]
    const report = buildComplianceReport(noVerdict, ctx, now)
    expect(report).toContain('## Decision verdicts')
    expect(report).toContain('- (no explicit verdicts)')
  })

  it('reports an empty scope honestly when there are no rows', () => {
    const report = buildComplianceReport([], ctx, now)
    expect(report).toContain('Total events in report: 0')
    expect(report).toContain('Agents covered: (none)')
    expect(report).toContain('## Policy violations (0)')
  })
})
