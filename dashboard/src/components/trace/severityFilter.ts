import type { TraceSeverity } from '../../features/trace/types'

export type SeverityKey = TraceSeverity | 'neutral'

export const SEVERITY_KEYS: readonly SeverityKey[] = ['critical', 'warning', 'info', 'neutral'] as const

export type SeverityFilter = Readonly<Record<SeverityKey, boolean>>

export const ALL_ON: SeverityFilter = {
  critical: true,
  warning: true,
  info: true,
  neutral: true,
}
