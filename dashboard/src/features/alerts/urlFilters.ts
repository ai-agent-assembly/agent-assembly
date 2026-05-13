import {
  DEFAULT_ALERT_FILTERS,
  type AlertFilters,
  type AlertStatus,
  type Severity,
  type TimeRangePreset,
} from './types'

const SEVERITY_VALUES: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const STATUS_VALUES: readonly AlertStatus[] = ['FIRING', 'RESOLVED', 'SUPPRESSED']
const RANGE_VALUES: readonly TimeRangePreset[] = ['24h', '7d', '30d', 'custom']

export function filtersFromSearchParams(sp: URLSearchParams): AlertFilters {
  const severities = sp.getAll('severity').filter((v): v is Severity =>
    SEVERITY_VALUES.includes(v as Severity),
  )
  const statuses = sp.getAll('status').filter((v): v is AlertStatus =>
    STATUS_VALUES.includes(v as AlertStatus),
  )
  const rawRange = sp.get('range') ?? DEFAULT_ALERT_FILTERS.timeRange
  const timeRange: TimeRangePreset = RANGE_VALUES.includes(rawRange as TimeRangePreset)
    ? (rawRange as TimeRangePreset)
    : DEFAULT_ALERT_FILTERS.timeRange
  return {
    severities,
    statuses,
    agentQuery: sp.get('agent') ?? '',
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
  if (filters.timeRange !== '24h') sp.set('range', filters.timeRange)
  if (filters.timeRange === 'custom') {
    if (filters.customFrom) sp.set('from', filters.customFrom)
    if (filters.customTo) sp.set('to', filters.customTo)
  }
  return sp
}
