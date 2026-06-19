// Alerts feature — see AAASM-118.
// Barrel for the feature's public surface. Re-export named specifiers (not a
// bare `export {}`) so the module advertises a real API; consumers may import
// from here or from the individual modules directly.
export { AlertList } from './AlertList'
export { AlertFilterBar } from './AlertFilterBar'
export { AlertsTabs, type AlertsTab } from './AlertsTabs'
export { AlertDetailDrawer } from './AlertDetailDrawer'
export { AlertDetailContent } from './AlertDetailContent'
export { AlertRuleForm } from './AlertRuleForm'
export { AlertRulesTable } from './AlertRulesTable'
export { DestinationManager } from './DestinationManager'
export { useAlertsQuery, useAlertRulesQuery } from './api'
export { useAlertsStream } from './useAlertsStream'
export type { Alert, AlertFilters, AlertRule } from './types'
