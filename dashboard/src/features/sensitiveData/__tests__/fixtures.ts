/**
 * Synthetic bodies for the sensitive-data tests (AAASM-5360).
 *
 * Test-only. Nothing here is imported by app code — the page reads the real
 * endpoints, and this Epic's whole complaint is about surfaces that render
 * constants. These exist so a test can produce a *specific* server answer and
 * assert what the page says about it.
 *
 * No value here resembles a real secret. The findings carry categories,
 * severities and `[REDACTED:…]` labels, which is all the API returns — there is
 * no field on the wire that could carry a raw value, an offset or a length, so
 * there is nothing here to sanitise.
 */
import type {
  QueryScope,
  SensitiveDataCounters,
  SensitiveDataEventSummary,
  SensitiveDataFindingDetail,
  SensitiveDataRates,
} from '../schema'

export const SCOPE: QueryScope = {
  org_id: 'acme',
  tenant_id: 'acme',
  from_ns: 1_760_000_000_000_000_000,
  to_ns: 1_760_604_800_000_000_000,
}

/** Every counter zeroed — the shape an idle window returns. */
export const ZERO_COUNTERS: SensitiveDataCounters = {
  event_count: 0,
  finding_count: 0,
  blocked_event_count: 0,
  blocked_finding_count: 0,
  redacted_event_count: 0,
  redacted_finding_count: 0,
  prevented_event_count: 0,
  prevented_finding_count: 0,
  inspection_incomplete_event_count: 0,
  unmeasured_transmission_event_count: 0,
}

/**
 * ADR 0032 §8's worked example, exactly.
 *
 * One action carrying three findings, two of them rewritten before the action
 * was refused outright. The six figures it produces are the reason this Epic
 * exists: `1` and `3` are both true, of different things, and a card showing
 * either one alone is a defect.
 */
export const WORKED_EXAMPLE_COUNTERS: SensitiveDataCounters = {
  event_count: 1,
  finding_count: 3,
  blocked_event_count: 1,
  blocked_finding_count: 3,
  redacted_event_count: 0,
  redacted_finding_count: 2,
  prevented_event_count: 0,
  prevented_finding_count: 0,
  inspection_incomplete_event_count: 0,
  // The build under test writes `TransmissionEvidence::NotRecorded`
  // unconditionally, so the single event is unmeasured (AAASM-5685).
  unmeasured_transmission_event_count: 1,
}

/** Counters over a busier window where nothing observed the wire at all. */
export const UNMEASURED_COUNTERS: SensitiveDataCounters = {
  event_count: 12,
  finding_count: 37,
  blocked_event_count: 4,
  blocked_finding_count: 11,
  redacted_event_count: 5,
  redacted_finding_count: 18,
  prevented_event_count: 0,
  prevented_finding_count: 0,
  inspection_incomplete_event_count: 0,
  unmeasured_transmission_event_count: 12,
}

/**
 * The same window, but every action carried transmission evidence and none of
 * them prevented anything.
 *
 * This is a *measured* zero: the product looked, and nothing was prevented.
 * It must never render the same way {@link UNMEASURED_COUNTERS} does.
 */
export const MEASURED_ZERO_COUNTERS: SensitiveDataCounters = {
  ...UNMEASURED_COUNTERS,
  unmeasured_transmission_event_count: 0,
}

/** A window with real prevention evidence on some of the actions. */
export const MEASURED_PREVENTION_COUNTERS: SensitiveDataCounters = {
  ...UNMEASURED_COUNTERS,
  prevented_event_count: 3,
  prevented_finding_count: 9,
  unmeasured_transmission_event_count: 0,
}

/** A window whose detection pass did not run to completion on some actions. */
export const LOSSY_INSPECTION_COUNTERS: SensitiveDataCounters = {
  ...UNMEASURED_COUNTERS,
  inspection_incomplete_event_count: 5,
}

/** The rates the API derives for a set of counters, computed the same way. */
export function ratesFor(counters: SensitiveDataCounters): SensitiveDataRates {
  const over = (numerator: number, denominator: number): number | null =>
    denominator === 0 ? null : numerator / denominator
  return {
    block_rate: over(counters.blocked_event_count, counters.event_count),
    redaction_rate: over(counters.redacted_event_count, counters.event_count),
    prevention_rate: over(counters.prevented_event_count, counters.event_count),
    inspection_incomplete_rate: over(
      counters.inspection_incomplete_event_count,
      counters.event_count,
    ),
    unmeasured_transmission_rate: over(
      counters.unmeasured_transmission_event_count,
      counters.event_count,
    ),
    findings_per_event: over(counters.finding_count, counters.event_count),
    blocked_finding_share: over(counters.blocked_finding_count, counters.finding_count),
    redacted_finding_share: over(counters.redacted_finding_count, counters.finding_count),
  }
}

export const EVENT: SensitiveDataEventSummary = {
  event_id: 'evt-0001',
  occurred_at_ns: 1_760_300_000_000_000_000,
  acting_agent_id: 'research-bot-04',
  root_agent_id: 'orchestrator-01',
  parent_agent_id: 'orchestrator-01',
  delegation_depth: 1,
  team_id: 'data-platform',
  session_id: 'sess-9a4f',
  trace_id: 'tr-9a4f-001',
  operation: 'tool_call',
  destination_kind: 'tool',
  destination_id: 'gmail.send',
  trust_zone: 'external',
  direction: 'outbound',
  verdict: 'deny',
  enforcement_point: 'runtime',
  transmission_evidence: 'not_recorded',
  enforcement_mode: 'enforce',
  inspection_failure_path: 'completed',
  prevented_transmission: false,
  policy_document_id: 'pol-014',
  matched_rule_ids: ['rule-pii-egress'],
  inspected_field_paths: ['body.to', 'body.text'],
  finding_count: 3,
  transformed_finding_count: 2,
  reason_codes: ['sensitive_data_detected'],
}

export const FINDINGS: SensitiveDataFindingDetail[] = [
  {
    finding_ordinal: 0,
    category: 'email_address',
    severity: 'low',
    confidence: 'high',
    method: 'regex',
    status: 'confirmed',
    recognizer: 'builtin',
    recognizer_version: '1.4.0',
    field_path: 'body.to',
    redaction_label: '[REDACTED:EmailAddress]',
  },
  {
    finding_ordinal: 1,
    category: 'aws_access_key',
    severity: 'critical',
    confidence: 'high',
    method: 'regex',
    status: 'confirmed',
    recognizer: 'builtin',
    recognizer_version: '1.4.0',
    field_path: 'body.text',
    redaction_label: '[REDACTED:AwsAccessKey]',
  },
  {
    finding_ordinal: 2,
    category: 'email_address',
    severity: 'low',
    confidence: 'medium',
    method: 'regex',
    status: 'suspected',
    recognizer: 'builtin',
    recognizer_version: '1.4.0',
    field_path: 'body.text',
    redaction_label: '[REDACTED:EmailAddress]',
  },
]
