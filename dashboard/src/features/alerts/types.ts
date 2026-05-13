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
