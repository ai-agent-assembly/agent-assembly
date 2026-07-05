/**
 * Feature flag: whether the `/api/v1/analytics/*` data endpoints exist.
 *
 * The seven analytics hooks (`kpis`, `cost-breakdown`, `action-volume`,
 * `tool-usage`, `approvals`, `policy-effectiveness`, `fleet-health`) target
 * endpoints that are not yet implemented in `aa-api` nor declared in
 * `openapi/v1.yaml` (AAASM-4138). Until they land, the panels that depend on
 * them are gated behind this flag so they render a clear "not yet available"
 * state instead of a raw fetch/HTTP error.
 *
 * Flip to `true` once the backend endpoints ship (tracked separately). Typed as
 * `boolean` on purpose so both branches stay reachable to the type checker.
 */
export const ANALYTICS_BACKEND_AVAILABLE: boolean = false
