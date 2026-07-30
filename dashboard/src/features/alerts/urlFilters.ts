import {
  DEFAULT_ALERT_FILTERS,
  type AlertFilters,
  type AlertStatus,
  type AlertSeverity,
  type TimeRangePreset,
} from './types'

const SEVERITY_VALUES: ReadonlySet<AlertSeverity> = new Set(['CRITICAL', 'WARNING', 'INFO'])
const STATUS_VALUES: ReadonlySet<AlertStatus> = new Set(['FIRING', 'RESOLVED', 'SUPPRESSED'])
const RANGE_VALUES: ReadonlySet<TimeRangePreset> = new Set(['24h', '7d', '30d', 'custom'])

export function filtersFromSearchParams(sp: URLSearchParams): AlertFilters {
  const severities = sp.getAll('severity').filter((v): v is AlertSeverity =>
    SEVERITY_VALUES.has(v as AlertSeverity),
  )
  const statuses = sp.getAll('status').filter((v): v is AlertStatus =>
    STATUS_VALUES.has(v as AlertStatus),
  )
  const rawRange = sp.get('range') ?? DEFAULT_ALERT_FILTERS.timeRange
  const timeRange: TimeRangePreset = RANGE_VALUES.has(rawRange as TimeRangePreset)
    ? (rawRange as TimeRangePreset)
    : DEFAULT_ALERT_FILTERS.timeRange
  return {
    severities,
    statuses,
    agentQuery: sp.get('agent') ?? '',
    q: sp.get('q') ?? '',
    timeRange,
    customFrom: sp.get('from'),
    customTo: sp.get('to'),
  }
}

export function filtersToSearchParams(filters: AlertFilters): URLSearchParams {
  const sp = new URLSearchParams()
  filters.severities.forEach((s) => sp.append('severity', s))
  filters.statuses.forEach((s) => sp.append('status', s))
  if (filters.agentQuery.trim()) sp.set('agent', filters.agentQuery.trim())
  if (filters.q.trim()) sp.set('q', filters.q.trim())
  if (filters.timeRange !== '24h') sp.set('range', filters.timeRange)
  if (filters.timeRange === 'custom') {
    if (filters.customFrom) sp.set('from', filters.customFrom)
    if (filters.customTo) sp.set('to', filters.customTo)
  }
  return sp
}
