import { describe, expect, it } from 'vitest'
import { buildAuditCsv, buildComplianceReport, coverageTag } from './export'
import type { AuditCoverage, LogEntry } from './logs'

function entry(partial: Partial<LogEntry> & Pick<LogEntry, 'seq' | 'event_type'>): LogEntry {
  return {
    timestamp: '2026-05-11T14:02:11Z',
    agent_id: '9f2c1a7b4d8e0f3a6b5c4d3e2f1a0b9c',
    session_id: 'sess-9a4f',
    payload: '{}',
    ...partial,
  }
}

/**
 * Rows in the shape the gateway and runtime actually emit: an **integer**
 * `decision`, a `reason` / `policy_rule` pair on the gateway path, a `detail`
 * object on the runtime path.
 */
const ROWS: LogEntry[] = [
  entry({
    seq: 1048,
    event_type: 'PolicyViolation',
    payload: JSON.stringify({
      action_type: 2,
      decision: 2,
      reason: 'External recipient, needs approval',
      policy_rule: 'deny-external-mail',
    }),
  }),
  entry({
    seq: 1047,
    event_type: 'ToolCallIntercepted',
    agent_id: '1122334455667788990011223344556677',
    payload: JSON.stringify({
      action_type: 'TOOL_CALL',
      decision: 1,
      detail: { kind: 'tool_call', tool_name: 'zendesk_search', tool_source: 'mcp', succeeded: true },
    }),
  }),
]

const COMPLETE: AuditCoverage = {
  loaded: 2,
  total: { known: true, value: 2 },
  complete: true,
  capped: false,
  moreAvailable: false,
}

const PARTIAL: AuditCoverage = {
  loaded: 50,
  total: { known: true, value: 4820 },
  complete: false,
  capped: false,
  moreAvailable: true,
}

const UNKNOWN_TOTAL: AuditCoverage = {
  loaded: 50,
  total: { known: false, state: 'unknown' },
  complete: false,
  capped: false,
  moreAvailable: false,
}

describe('coverageTag', () => {
  it('tags a complete window as complete', () => {
    expect(coverageTag(COMPLETE)).toBe('complete:2/2')
  })

  it('tags a short window as partial with both numbers', () => {
    expect(coverageTag(PARTIAL)).toBe('partial:50/4820')
  })

  it('distinguishes a ceiling-capped window', () => {
    expect(coverageTag({ ...PARTIAL, capped: true, moreAvailable: false })).toBe(
      'partial-capped:50/4820',
    )
  })

  it('never invents a total it was not given', () => {
    expect(coverageTag(UNKNOWN_TOTAL)).toBe('partial:50/unknown')
  })
})

describe('buildAuditCsv', () => {
  it('emits a header row plus one line per entry', () => {
    const lines = buildAuditCsv(ROWS, COMPLETE).split('\r\n')
    expect(lines).toHaveLength(3)
    expect(lines[0]).toBe(
      'seq,timestamp,agent_id,event_type,decision,summary,session_id,export_scope',
    )
  })

  // ── AAASM-5117 regression: an integer decision must reach the file ────────
  it('populates the decision column from the integer wire form', () => {
    const csv = buildAuditCsv(ROWS, COMPLETE)
    expect(csv).toContain('DENY')
    expect(csv).toContain('ALLOW')
  })

  it('derives the summary from the real payload shape', () => {
    const csv = buildAuditCsv(ROWS, COMPLETE)
    expect(csv).toContain('zendesk_search (mcp)')
    expect(csv).not.toContain('undefined')
  })

  // ── AAASM-5120 regression: the file cannot claim to be the whole trail ────
  it('stamps every row of a truncated export as partial', () => {
    const lines = buildAuditCsv(ROWS, PARTIAL).split('\r\n').slice(1)
    expect(lines).toHaveLength(2)
    for (const line of lines) {
      expect(line.endsWith(',partial:50/4820')).toBe(true)
    }
  })

  it('never marks a truncated export complete', () => {
    expect(buildAuditCsv(ROWS, PARTIAL)).not.toContain('complete:')
  })

  it('quotes cells that contain a comma so columns are not split', () => {
    const csv = buildAuditCsv([ROWS[0]], COMPLETE)
    expect(csv).toContain('"External recipient, needs approval — deny-external-mail"')
  })

  it('produces only the header for an empty row set', () => {
    expect(buildAuditCsv([], COMPLETE)).toBe(
      'seq,timestamp,agent_id,event_type,decision,summary,session_id,export_scope',
    )
  })

  it('labels a verdict-less row explicitly rather than leaving the cell blank', () => {
    const csv = buildAuditCsv(
      [entry({ seq: 5, event_type: 'SandboxStarted', payload: '{"event_id":"e"}' })],
      COMPLETE,
    )
    const cells = csv.split('\r\n')[1].split(',')
    // Column order: seq,timestamp,agent_id,event_type,decision,summary,session_id,export_scope
    expect(cells[4]).toBe('Not evaluated')
    expect(cells[5]).toBe('Unknown')
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
        event_type: 'ToolCallIntercepted',
        session_id: null,
        payload: '{}',
      } as unknown as LogEntry,
    ]
    const line = buildAuditCsv(sparse, COMPLETE).split('\r\n')[1]
    expect(line).not.toContain('null')
  })
})

describe('buildComplianceReport', () => {
  const ctx = { typeFilter: 'all', agentFilter: 'all', search: '' }
  const now = new Date('2026-05-11T15:00:00Z')

  it('summarizes totals, type counts and decision verdicts', () => {
    const report = buildComplianceReport(ROWS, ctx, COMPLETE, now)
    expect(report).toContain('Entries in this report: 2')
    expect(report).toContain('- PolicyViolation: 1')
    // AAASM-5117: these two lines were empty in every enforce-mode deployment.
    expect(report).toContain('- DENY: 1')
    expect(report).toContain('- ALLOW: 1')
  })

  it('lists every policy violation in scope', () => {
    const report = buildComplianceReport(ROWS, ctx, COMPLETE, now)
    expect(report).toContain('## Policy violations (1)')
    expect(report).toContain('External recipient, needs approval')
    expect(report).not.toContain('undefined')
  })

  // ── AAASM-5120: the report must not read as the complete trail ────────────
  it('titles a truncated report as a partial window', () => {
    const report = buildComplianceReport(ROWS, ctx, PARTIAL, now)
    expect(report.split('\n')[0]).toBe('# Audit Compliance Report — PARTIAL WINDOW')
    expect(report).toContain('does not cover the complete audit trail')
    expect(report).toContain('Partial — 50 of 4820')
  })

  it('states both the loaded count and the filtered total', () => {
    const report = buildComplianceReport(ROWS, ctx, PARTIAL, now)
    expect(report).toContain('Entries loaded from the gateway: 50')
    expect(report).toContain('Entries matching the server-side filter: 4820')
  })

  it('qualifies a zero-violation finding when the window is short', () => {
    const report = buildComplianceReport([ROWS[1]], ctx, PARTIAL, now)
    expect(report).toContain('## Policy violations (0)')
    expect(report).toContain('This does NOT mean there were none in the trail')
  })

  it('states zero violations plainly only when the window is complete', () => {
    const report = buildComplianceReport([ROWS[1]], ctx, COMPLETE, now)
    expect(report).toContain('- None among the entries matching the current filter.')
    expect(report).not.toContain('PARTIAL WINDOW')
  })

  it('refuses to claim completeness when the gateway reported no total', () => {
    const report = buildComplianceReport(ROWS, ctx, UNKNOWN_TOTAL, now)
    expect(report).toContain('PARTIAL WINDOW')
    expect(report).toContain('unknown (the gateway reported no total)')
  })

  it('records the active filter scope', () => {
    const report = buildComplianceReport(
      ROWS,
      { typeFilter: 'policy', agentFilter: 'research-bot-04', search: 'gmail' },
      COMPLETE,
    )
    expect(report).toContain('type=policy')
    expect(report).toContain('agent=research-bot-04')
    expect(report).toContain('search=gmail')
  })

  it('breaks out the entries that carry no verdict instead of dropping them', () => {
    const noVerdict = [entry({ seq: 10, event_type: 'SandboxStarted', payload: '{"event_id":"e"}' })]
    const report = buildComplianceReport(noVerdict, ctx, COMPLETE, now)
    expect(report).toContain('- (no entry in this window carries a policy verdict)')
    expect(report).toContain('### Entries carrying no verdict')
    expect(report).toContain('- Not evaluated: 1')
  })

  it('reports an empty scope honestly when there are no rows', () => {
    const report = buildComplianceReport([], ctx, COMPLETE, now)
    expect(report).toContain('Entries in this report: 0')
    expect(report).toContain('Agents covered (audit id digests): (none)')
    expect(report).toContain('## Policy violations (0)')
  })
})
