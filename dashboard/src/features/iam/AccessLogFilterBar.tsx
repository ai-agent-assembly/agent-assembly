import {
  ACCESS_LOG_EVENT_TYPES,
  type AccessLogEventType,
  type AccessLogFilter,
  type AccessLogTimeRange,
} from './accessLog'
import './AccessLogFilterBar.css'

const EVENT_TYPE_LABELS: Record<AccessLogEventType, string> = {
  login: 'Login',
  logout: 'Logout',
  policy_change: 'Policy change',
  key_rotate: 'Key rotation',
  member_invite: 'Member invite',
  permission_grant: 'Permission grant',
}

const TIME_RANGE_OPTIONS = ['24h', '7d', '30d', 'custom'] as const
type TimeRangeOption = (typeof TIME_RANGE_OPTIONS)[number]

const TIME_RANGE_LABELS: Record<TimeRangeOption, string> = {
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
  custom: 'Custom range',
}

export interface AccessLogFilterBarProps {
  /** Candidate identity values for the identity select — usually the union
   *  of member emails and active service-key labels. */
  identities: readonly string[]
  value: AccessLogFilter
  onChange: (next: AccessLogFilter) => void
}

function readTimeRangeKind(range: AccessLogTimeRange | undefined): TimeRangeOption | '' {
  if (!range) return ''
  return range.kind
}

export function AccessLogFilterBar({
  identities,
  value,
  onChange,
}: AccessLogFilterBarProps) {
  const currentTimeKind = readTimeRangeKind(value.timeRange)
  const isCustom = value.timeRange?.kind === 'custom'

  return (
    <div className="iam-access-log-filter-bar" data-testid="access-log-filter-bar">
      <label className="iam-access-log-filter-bar__field">
        <span className="iam-access-log-filter-bar__label">Identity</span>
        <select
          className="iam-access-log-filter-bar__select"
          data-testid="access-log-filter-identity"
          value={value.identity ?? ''}
          onChange={(e) => {
            const raw = e.target.value
            onChange({ ...value, identity: raw === '' ? null : raw })
          }}
        >
          <option value="">All identities</option>
          {identities.map((id) => (
            <option key={id} value={id}>
              {id}
            </option>
          ))}
        </select>
      </label>

      <label className="iam-access-log-filter-bar__field">
        <span className="iam-access-log-filter-bar__label">Event type</span>
        <select
          className="iam-access-log-filter-bar__select"
          data-testid="access-log-filter-event-type"
          value={value.eventType ?? ''}
          onChange={(e) => {
            const raw = e.target.value
            onChange({
              ...value,
              eventType: raw === '' ? null : (raw as AccessLogEventType),
            })
          }}
        >
          <option value="">All event types</option>
          {ACCESS_LOG_EVENT_TYPES.map((t) => (
            <option key={t} value={t}>
              {EVENT_TYPE_LABELS[t]}
            </option>
          ))}
        </select>
      </label>

      <label className="iam-access-log-filter-bar__field">
        <span className="iam-access-log-filter-bar__label">Time range</span>
        <select
          className="iam-access-log-filter-bar__select"
          data-testid="access-log-filter-time-range"
          value={currentTimeKind}
          onChange={(e) => {
            const raw = e.target.value as TimeRangeOption | ''
            if (raw === '') {
              onChange({ ...value, timeRange: undefined })
              return
            }
            if (raw === 'custom') {
              // Default the custom range to the last 7 days so the inputs
              // open populated rather than empty (empty dates would render
              // the table as "no rows" until the user picks both ends).
              const to = new Date().toISOString().slice(0, 10)
              const from = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
                .toISOString()
                .slice(0, 10)
              onChange({ ...value, timeRange: { kind: 'custom', from, to } })
              return
            }
            onChange({ ...value, timeRange: { kind: raw } })
          }}
        >
          <option value="">Any time</option>
          {TIME_RANGE_OPTIONS.map((opt) => (
            <option key={opt} value={opt}>
              {TIME_RANGE_LABELS[opt]}
            </option>
          ))}
        </select>
      </label>

      {isCustom && value.timeRange?.kind === 'custom' && (
        <>
          <label className="iam-access-log-filter-bar__field">
            <span className="iam-access-log-filter-bar__label">From</span>
            <input
              type="date"
              className="iam-access-log-filter-bar__date"
              data-testid="access-log-filter-custom-from"
              // <input type="date"> emits YYYY-MM-DD; we keep that as the
              // stored representation in the filter and the data layer
              // does an ISO string comparison.
              value={value.timeRange.from.slice(0, 10)}
              onChange={(e) => {
                if (value.timeRange?.kind !== 'custom') return
                onChange({
                  ...value,
                  timeRange: { ...value.timeRange, from: e.target.value },
                })
              }}
            />
          </label>
          <label className="iam-access-log-filter-bar__field">
            <span className="iam-access-log-filter-bar__label">To</span>
            <input
              type="date"
              className="iam-access-log-filter-bar__date"
              data-testid="access-log-filter-custom-to"
              value={value.timeRange.to.slice(0, 10)}
              onChange={(e) => {
                if (value.timeRange?.kind !== 'custom') return
                onChange({
                  ...value,
                  timeRange: { ...value.timeRange, to: e.target.value },
                })
              }}
            />
          </label>
        </>
      )}
    </div>
  )
}
