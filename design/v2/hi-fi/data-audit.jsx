/* global React */
/* ============================================================
   Audit log + Active Sessions sample data
   Mirrors GET /api/v1/logs  +  AgentResponse.active_sessions
   ============================================================ */

// ── Audit Log entries  (LogEntry schema) ─────────────────────────────────────
const AUDIT_LOG = [
  {
    seq: 1048, timestamp: '2026-05-11T14:02:11Z', agent_id: 'research-bot-04',  session_id: 'sess-9a4f', trace_id: 'tr-9a4f-001', decision: 'DENY',
    event_type: 'PolicyViolation',
    payload: { policy_rule: 'P-021', blocked_action: 'gmail/send → ext@vendor.com', reason: 'External recipient requires explicit approval' },
  },
  {
    seq: 1047, timestamp: '2026-05-11T14:01:58Z', agent_id: 'research-bot-04',  session_id: 'sess-9a4f', trace_id: 'tr-9a4f-001', decision: 'ALLOW',
    event_type: 'LLMCall',
    payload: { model: 'claude-3-5-sonnet', provider: 'anthropic', prompt_tokens: 2840, completion_tokens: 412, latency_ms: 1840, pii_detected: false, pii_redacted: false },
  },
  {
    seq: 1046, timestamp: '2026-05-11T14:01:33Z', agent_id: 'analytics-runner', session_id: 'sess-8b12', trace_id: 'tr-8b12-004', decision: 'PENDING',
    event_type: 'FileOp',
    payload: { operation: 'read', path: 's3://customer-pii/raw/segment-2026-q2.csv', bytes: 8589934592, source: 'sdk_hook' },
  },
  {
    seq: 1045, timestamp: '2026-05-11T14:01:22Z', agent_id: 'infra-ops-bot',    session_id: 'sess-7c33', trace_id: 'tr-7c33-002', decision: 'ALLOW',
    event_type: 'NetworkCall',
    payload: { host: 'api.github.com', port: 443, protocol: 'https', latency_ms: 284, status_code: 200, succeeded: true },
  },
  {
    seq: 1044, timestamp: '2026-05-11T14:01:09Z', agent_id: 'support-triage',   session_id: 'sess-6d44', trace_id: 'tr-6d44-001', decision: 'ALLOW',
    event_type: 'ToolCall',
    payload: { tool_name: 'zendesk_search', tool_source: 'mcp', latency_ms: 142, succeeded: true, error_message: '' },
  },
  {
    seq: 1043, timestamp: '2026-05-11T14:00:51Z', agent_id: 'research-bot-04',  session_id: 'sess-9a4f', trace_id: 'tr-9a4f-001', decision: 'REDACT',
    event_type: 'LLMCall',
    payload: { model: 'gpt-4o', provider: 'openai', prompt_tokens: 1922, completion_tokens: 308, latency_ms: 2210, pii_detected: true, pii_redacted: true },
  },
  {
    seq: 1042, timestamp: '2026-05-11T14:00:38Z', agent_id: 'finance-bot',      session_id: 'sess-5e55', trace_id: 'tr-5e55-001', decision: 'DENY',
    event_type: 'PolicyViolation',
    payload: { policy_rule: 'P-035', blocked_action: 's3://customer-pii/accounts.csv read', reason: 'PII bucket lockdown — cross-org access denied' },
  },
  {
    seq: 1041, timestamp: '2026-05-11T14:00:14Z', agent_id: 'infra-ops-bot',    session_id: 'sess-7c33', trace_id: 'tr-7c33-002', decision: 'PENDING',
    event_type: 'FileOp',
    payload: { operation: 'write', path: 'github.com/acme/infra/terraform/prod.tf', bytes: 7284, source: 'sdk_hook' },
  },
  {
    seq: 1040, timestamp: '2026-05-11T13:59:58Z', agent_id: 'sales-outreach-v2',session_id: 'sess-4f66', trace_id: 'tr-4f66-003', decision: 'ALLOW',
    event_type: 'LLMCall',
    payload: { model: 'gpt-4o-mini', provider: 'openai', prompt_tokens: 840, completion_tokens: 220, latency_ms: 680, pii_detected: false, pii_redacted: false },
  },
  {
    seq: 1039, timestamp: '2026-05-11T13:59:41Z', agent_id: 'incident-responder',session_id: 'sess-3g77',trace_id: 'tr-3g77-001', decision: 'PENDING',
    event_type: 'PolicyViolation',
    payload: { policy_rule: 'P-042', blocked_action: 'shell:kubectl rollout restart deploy/api', reason: 'Shell exec requires break-glass 2-person approval' },
  },
  {
    seq: 1038, timestamp: '2026-05-11T13:59:22Z', agent_id: 'analytics-runner', session_id: 'sess-8b12', trace_id: 'tr-8b12-003', decision: 'ALLOW',
    event_type: 'ToolCall',
    payload: { tool_name: 'bigquery_query', tool_source: 'function', latency_ms: 3210, succeeded: true, error_message: '' },
  },
  {
    seq: 1037, timestamp: '2026-05-11T13:59:05Z', agent_id: 'docs-summarizer',  session_id: 'sess-2h88', trace_id: 'tr-2h88-001', decision: 'ALLOW',
    event_type: 'NetworkCall',
    payload: { host: 'storage.googleapis.com', port: 443, protocol: 'https', latency_ms: 188, status_code: 200, succeeded: true },
  },
  {
    seq: 1036, timestamp: '2026-05-11T13:58:44Z', agent_id: 'research-bot-04',  session_id: 'sess-9a4e', trace_id: 'tr-9a4e-002', decision: 'APPROVE',
    event_type: 'ApprovalEvent',
    payload: { approval_id: 'AP-9384', approver_id: 'kelly', approved: false, reason: 'External vendor email not in whitelist', wait_time_ms: 142000 },
  },
  {
    seq: 1035, timestamp: '2026-05-11T13:58:20Z', agent_id: 'support-triage',   session_id: 'sess-6d44', trace_id: 'tr-6d44-001', decision: 'PENDING',
    event_type: 'PolicyViolation',
    payload: { policy_rule: 'P-014', blocked_action: 'pg.public.tickets UPDATE 47 rows', reason: 'PII table write requires approval' },
  },
  {
    seq: 1034, timestamp: '2026-05-11T13:57:58Z', agent_id: 'infra-ops-bot',    session_id: 'sess-7c33', trace_id: 'tr-7c33-001', decision: 'ALLOW',
    event_type: 'LLMCall',
    payload: { model: 'claude-3-5-sonnet', provider: 'anthropic', prompt_tokens: 3100, completion_tokens: 580, latency_ms: 2340, pii_detected: false, pii_redacted: false },
  },
  {
    seq: 1033, timestamp: '2026-05-11T13:57:33Z', agent_id: 'analytics-runner', session_id: 'sess-8b12', trace_id: 'tr-8b12-002', decision: 'ALLOW',
    event_type: 'FileOp',
    payload: { operation: 'read', path: 's3://reports/q2-summary.parquet', bytes: 41943040, source: 'sdk_hook' },
  },
  {
    seq: 1032, timestamp: '2026-05-11T13:57:10Z', agent_id: 'sales-outreach-v2',session_id: 'sess-4f66', trace_id: 'tr-4f66-002', decision: 'DENY',
    event_type: 'PolicyViolation',
    payload: { policy_rule: 'P-021', blocked_action: 'gmail/send → prospect@unknown-domain.io', reason: 'Scrub completed — PII removed; external recipient still requires approval' },
  },
  {
    seq: 1031, timestamp: '2026-05-11T13:56:48Z', agent_id: 'research-bot-04',  session_id: 'sess-9a4e', trace_id: 'tr-9a4e-001', decision: 'ALLOW',
    event_type: 'ToolCall',
    payload: { tool_name: 'web_search', tool_source: 'function', latency_ms: 892, succeeded: true, error_message: '' },
  },
  {
    seq: 1030, timestamp: '2026-05-11T13:56:22Z', agent_id: 'incident-responder',session_id: 'sess-3g77',trace_id: 'tr-3g77-001', decision: 'ALLOW',
    event_type: 'NetworkCall',
    payload: { host: 'pagerduty.com', port: 443, protocol: 'https', latency_ms: 312, status_code: 201, succeeded: true },
  },
  {
    seq: 1029, timestamp: '2026-05-11T13:55:55Z', agent_id: 'docs-summarizer',  session_id: 'sess-2h88', trace_id: 'tr-2h88-001', decision: 'ALLOW',
    event_type: 'LLMCall',
    payload: { model: 'claude-3-haiku', provider: 'anthropic', prompt_tokens: 14200, completion_tokens: 840, latency_ms: 4120, pii_detected: false, pii_redacted: false },
  },
];

// ── Active Sessions  (ActiveSessionResponse per agent) ────────────────────────
const ACTIVE_SESSIONS = [
  { agent_id: 'research-bot-04',    session_id: 'sess-9a4f', started_at: '2026-05-11T13:44:00Z', status: 'active', actions_count: 42, current_task: 'Compiling Q2 vendor report' },
  { agent_id: 'research-bot-04',    session_id: 'sess-9a4e', started_at: '2026-05-11T13:38:00Z', status: 'active', actions_count: 18, current_task: 'Web research — market sizing' },
  { agent_id: 'analytics-runner',   session_id: 'sess-8b12', started_at: '2026-05-11T13:50:00Z', status: 'active', actions_count: 27, current_task: 'PII scan — customer segment CSV' },
  { agent_id: 'infra-ops-bot',      session_id: 'sess-7c33', started_at: '2026-05-11T13:55:00Z', status: 'active', actions_count: 11, current_task: 'Terraform plan — prod.tf diff' },
  { agent_id: 'support-triage',     session_id: 'sess-6d44', started_at: '2026-05-11T13:58:00Z', status: 'active', actions_count: 6,  current_task: 'Triaging ticket backlog' },
  { agent_id: 'sales-outreach-v2',  session_id: 'sess-4f66', started_at: '2026-05-11T13:47:00Z', status: 'active', actions_count: 31, current_task: 'Drafting outreach sequence' },
  { agent_id: 'incident-responder', session_id: 'sess-3g77', started_at: '2026-05-11T14:00:00Z', status: 'active', actions_count: 4,  current_task: 'Incident response — api service restart' },
  { agent_id: 'docs-summarizer',    session_id: 'sess-2h88', started_at: '2026-05-11T13:52:00Z', status: 'active', actions_count: 14, current_task: 'Summarising product docs v4.2' },
];

Object.assign(window, { AUDIT_LOG, ACTIVE_SESSIONS });
