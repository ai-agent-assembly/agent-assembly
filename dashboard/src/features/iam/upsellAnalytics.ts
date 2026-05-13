import { IAM_UPSELL_EVENT } from './copy'

/**
 * OSS-friendly analytics shim. The community dashboard has no
 * `useAnalytics()` hook, so the upsell click is announced as a
 * console.info entry tagged with the event name. When the dashboard
 * gains a real analytics transport (Segment, PostHog, in-house), this
 * function becomes the single swap point.
 *
 * Returns the event name so callers (and tests) can assert on it.
 */
export function fireUpsellClicked(source: string = 'custom-roles-panel'): string {
  console.info(`[analytics] ${IAM_UPSELL_EVENT}`, { source })
  return IAM_UPSELL_EVENT
}
