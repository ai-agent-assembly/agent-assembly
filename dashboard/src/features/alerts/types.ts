// Alert domain types used by the dashboard `/alerts` page.
//
// Mirrors the response shape expected from `GET /api/v1/alerts` (AAASM-9)
// plus the rule/destination concepts the rule builder needs. The Tanstack
// Query hooks defined in AAASM-1075 will narrow these against the
// auto-generated OpenAPI types once the spec is regenerated.

/**
 * Severity of an alert *as emitted by the backend* (AAASM-5193).
 *
 * The wire is the single source of truth: `AlertResponse.severity`
 * (`aa-api/src/routes/alerts.rs`) is the `Display` of `AlertSeverity`
 * (`aa-api/src/alerts/mod.rs`), which serialises exactly three values —
 * `critical` / `warning` / `info`. This union is those three, spelled in the
 * dashboard's upper-case convention, so `parseAlert.ts` maps them 1:1 with no
 * lossy remap and no member the backend cannot produce.
 *
 * This is deliberately distinct from {@link RuleSeverity}: an *alert* can only
 * ever carry one of these three, whereas a *rule* is authored with the
 * four-level `RuleSeverity` ladder. Conflating the two (a single four-member
 * `Severity`) left `MEDIUM` unreachable from any real alert payload — the
 * frontend-only state AAASM-5193 removed, following the ADR 0026 D2 precedent
 * of narrowing an enum to what the projection can actually emit.
 */
export type AlertSeverity = 'CRITICAL' | 'WARNING' | 'INFO'

/**
 * Alert severity ordering, most-severe first. Mirrors the backend ladder
 * `Critical > Warning > Info`.
 */
export const ALERT_SEVERITY_ORDER: readonly AlertSeverity[] = ['CRITICAL', 'WARNING', 'INFO'] as const

/**
 * Severity assigned when *authoring an alert rule* (AAASM-5193).
 *
 * Matches the backend `RuleSeverity` enum (`aa-api/src/alerts/rules/types.rs`),
 * whose wire form is the four upper-case levels `CRITICAL` / `HIGH` / `MEDIUM` /
 * `LOW`. All four are genuinely authorable, so — unlike {@link AlertSeverity} —
 * `MEDIUM` is reachable here and stays. The rule engine collapses these onto the
 * three-level {@link AlertSeverity} ladder when it fires an alert.
 */
export type RuleSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export const RULE_SEVERITY_ORDER: readonly RuleSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

export type AlertStatus = 'FIRING' | 'RESOLVED' | 'SUPPRESSED'

export interface Alert {
  id: string
  ruleId: string
  ruleName: string
  severity: AlertSeverity
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
  severities: readonly AlertSeverity[]
  statuses: readonly AlertStatus[]
  agentQuery: string
  /** Free-text search over rule name, agent id, and alert id (AAASM-5146). */
  q: string
  timeRange: TimeRangePreset
  /** ISO 8601 — required when `timeRange === 'custom'`. */
  customFrom: string | null
  customTo: string | null
}

export const DEFAULT_ALERT_FILTERS: AlertFilters = {
  severities: [],
  statuses: [],
  agentQuery: '',
  q: '',
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
  severity: RuleSeverity
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
    severityMap?: Readonly<Partial<Record<RuleSeverity, string>>>
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
