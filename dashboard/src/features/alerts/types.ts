// Alert domain types used by the dashboard `/alerts` page.
//
// Mirrors the response shape expected from `GET /api/v1/alerts` (AAASM-9)
// plus the rule/destination concepts the rule builder needs. The Tanstack
// Query hooks defined in AAASM-1075 will narrow these against the
// auto-generated OpenAPI types once the spec is regenerated.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export const SEVERITY_ORDER: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

export type AlertStatus = 'FIRING' | 'RESOLVED' | 'SUPPRESSED'

export interface Alert {
  id: string
  ruleId: string
  ruleName: string
  severity: Severity
  status: AlertStatus
  agentId: string | null
  /** ISO 8601 timestamp when the rule first matched. */
  firstFiredAt: string
  /** ISO 8601 timestamp when the alert returned to a healthy state. */
  resolvedAt: string | null
  /** Destination ids the alert was routed to. */
  destinationIds: readonly string[]
}

export type TimeRangePreset = '24h' | '7d' | '30d' | 'custom'

export interface AlertFilters {
  severities: readonly Severity[]
  statuses: readonly AlertStatus[]
  agentQuery: string
  timeRange: TimeRangePreset
  /** ISO 8601 — required when `timeRange === 'custom'`. */
  customFrom: string | null
  customTo: string | null
}

export const DEFAULT_ALERT_FILTERS: AlertFilters = {
  severities: [],
  statuses: [],
  agentQuery: '',
  timeRange: '24h',
  customFrom: null,
  customTo: null,
}

// ── AlertRule (AAASM-1386 schema) ──────────────────────────────────────────

export type AlertMetric =
  | 'budget_spent_pct'
  | 'anomaly_score'
  | 'approval_pending_age'
  | 'policy_violation_count'

export type AlertOperator = '>' | '>=' | '<' | '='

/** Evaluation window in seconds — fixed allowed values per AAASM-1386 AC. */
export type EvaluationWindowSeconds = 300 | 900 | 3600

export interface AlertRule {
  id: string
  name: string
  description: string
  metric: AlertMetric
  operator: AlertOperator
  threshold: number
  evaluationWindowSeconds: EvaluationWindowSeconds
  severity: Severity
  destinationIds: readonly string[]
  dedupWindowSeconds: number
  suppressionLabels: Readonly<Record<string, string>>
  enabled: boolean
  createdAt: string
  updatedAt: string
}

/** Shape sent to POST /alerts/rules and PUT /alerts/rules/{id}. */
export type AlertRuleInput = Omit<AlertRule, 'id' | 'createdAt' | 'updatedAt'>

// ── Destination (AAASM-1388 schema) ────────────────────────────────────────

export type DestinationKind = 'webhook' | 'slack' | 'pagerduty' | 'opsgenie'

export interface DestinationBase {
  id: string
  kind: DestinationKind
  name: string
  enabled: boolean
  createdAt: string
  updatedAt: string
}

export interface WebhookDestination extends DestinationBase {
  kind: 'webhook'
  config: { url: string; secretHeader?: string | null }
}

export interface SlackDestination extends DestinationBase {
  kind: 'slack'
  config: { webhookUrl: string; channelOverride?: string | null }
}

export interface PagerDutyDestination extends DestinationBase {
  kind: 'pagerduty'
  config: {
    routingKey: string
    severityMap?: Readonly<Partial<Record<Severity, string>>>
  }
}

export interface OpsgenieDestination extends DestinationBase {
  kind: 'opsgenie'
  config: { apiKey: string; teamId?: string | null }
}

export type Destination =
  | WebhookDestination
  | SlackDestination
  | PagerDutyDestination
  | OpsgenieDestination

export type DestinationInput = Omit<Destination, 'id' | 'createdAt' | 'updatedAt'>

export interface DestinationTestResult {
  deliveredAt: string
  connectorResponseStatus: number
  connectorResponseBody: string
}

// ── Silence (AAASM-1387 schema) ────────────────────────────────────────────

export interface Silence {
  silenceId: string
  alertId: string
  startsAt: string
  expiresAt: string
  reason: string | null
  createdBy: string
}

export interface SilenceInput {
  alertId: string
  durationSeconds: number
  reason?: string
}

// ── AlertDetail (AAASM-1385 response) ──────────────────────────────────────

/** One entry in the routing log returned by `GET /alerts/{id}`. */
export interface RoutingLogEntry {
  destinationId: string
  deliveredAt: string
  status: 'ok' | 'failed' | 'retrying'
  errorMessage?: string | null
}

/**
 * Richer payload returned by `GET /api/v1/alerts/{id}` — superset of the
 * `Alert` shape returned by the list endpoint. The drawer reads everything
 * here so the list payload can stay slim.
 */
export interface AlertDetail extends Alert {
  /** Snapshot of the rule that was active when the alert fired. */
  ruleSnapshot: AlertRule
  /** Event payload that triggered the rule. */
  eventPayload: Record<string, unknown>
  routingLog: readonly RoutingLogEntry[]
  /** Active silence if any. */
  silence: Silence | null
  /**
   * Number of times this alert has fired within the current dedup window
   * (including the fire that opened the window). `1` when no deduplication
   * has happened yet.
   */
  dedupOccurrenceCount: number
  /**
   * Timestamp when the active dedup window expires. `null` when the alert
   * is not currently inside a dedup window.
   */
  dedupWindowExpiresAt: string | null
}
