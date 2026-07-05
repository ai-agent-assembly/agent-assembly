/**
 * Feature flag: whether the `/api/v1/analytics/*` data endpoints exist.
 *
 * The seven analytics hooks (`kpis`, `cost-breakdown`, `action-volume`,
 * `tool-usage`, `approvals`, `policy-effectiveness`, `fleet-health`) target
 * endpoints that were gated behind this flag (AAASM-4138). They now ship in
 * `aa-api` and are declared in `openapi/v1.yaml` (AAASM-4141), so the panels can
 * render real data instead of a "not yet available" placeholder.
 *
 * Typed as `boolean` on purpose so both branches stay reachable to the type
 * checker.
 */
export const ANALYTICS_BACKEND_AVAILABLE: boolean = true
