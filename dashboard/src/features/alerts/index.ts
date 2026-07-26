// Alerts feature — see AAASM-118.
// Barrel for the feature's public surface. Re-export named specifiers (not a
// bare `export {}`) so the module advertises a real API; consumers may import
// from here or from the individual modules directly.
export { AlertList } from './AlertList'
export { AlertFilterBar } from './AlertFilterBar'
export { AlertStatsStrip } from './AlertStatsStrip'
export { coversWholeFleet, statsScopeNote } from './alertsCoverage'
export { AlertCardFeed } from './AlertCardFeed'
export {
  AlertCategoryFilter,
  type CategoryCounts,
  type CategoryFilterValue,
} from './AlertCategoryFilter'
export {
  deriveCategory,
  indexRulesById,
  categoryCounts,
  ALERT_CATEGORIES,
  CATEGORY_META,
  type AlertCategory,
} from './alertCategory'
export { AlertsTabs, type AlertsTab } from './AlertsTabs'
export { AlertDetailDrawer } from './AlertDetailDrawer'
export { AlertDetailContent } from './AlertDetailContent'
export { AlertRuleForm } from './AlertRuleForm'
export { AlertRulesTable } from './AlertRulesTable'
export { DestinationManager } from './DestinationManager'
export { ResolveAction } from './ResolveAction'
export { SilenceAction } from './SilenceAction'
export { applyClientFilters, resolveTimeWindow, type TimeWindow } from './alertFilters'
export {
  criticalFiringBadge,
  criticalFiringCount,
  isOpenIncident,
} from './alertBadge'
export {
  useAlertsQuery,
  useAlertsPageQuery,
  useAlertRulesQuery,
  useResolveAlertMutation,
  type AlertsPageResult,
  type ResolveAlertInput,
} from './api'
export { useAlertsStream } from './useAlertsStream'
export type { Alert, AlertFilters, AlertRule } from './types'
