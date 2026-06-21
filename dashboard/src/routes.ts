/**
 * Canonical 12-route navigation for the governance dashboard.
 *
 * Mirrors the `ROUTES` const defined in `design/v1/hi-fi/shell.jsx`.
 * The AppShell nav renders entries grouped by `group`; `App.tsx` wires
 * each `path` to either an implemented page or `<ComingSoon />`.
 */

export type RouteGroup = 'monitor' | 'control' | 'manage'

export interface CanonicalRoute {
  /** Stable id, matches hi-fi `ROUTES[].id`. Used in test-id and key. */
  id: string
  /** Two-digit sequence number shown in the nav prefix. */
  num: string
  /** Human label shown in the nav. */
  label: string
  /** Section header the entry sits under in the nav. */
  group: RouteGroup
  /** Route path. */
  path: string
  /**
   * Optional glyph rendered alongside the numbered prefix (AAASM-1373).
   * Only the routes with established iconography ship one today; routes
   * without an icon fall back to the bare `num` + `label` layout so no
   * visual regression hits the other entries.
   */
  icon?: string
}

export const CANONICAL_ROUTES: readonly CanonicalRoute[] = [
  { id: 'overview',   num: '01', label: 'Overview',         group: 'monitor', path: '/overview' },
  { id: 'fleet',      num: '02', label: 'Fleet',            group: 'monitor', path: '/agents' },
  { id: 'topology',   num: '03', label: 'Topology',         group: 'monitor', path: '/topology' },
  { id: 'live',       num: '04', label: 'Live Ops',         group: 'monitor', path: '/live' },
  { id: 'alerts',     num: '05', label: 'Alerts',           group: 'monitor', path: '/alerts', icon: '🔔' },
  { id: 'audit',      num: '06', label: 'Audit Log',        group: 'monitor', path: '/audit' },
  { id: 'capability', num: '07', label: 'Capability',       group: 'control', path: '/capability' },
  { id: 'policy',     num: '08', label: 'Policy',           group: 'control', path: '/policies' },
  { id: 'scrub',      num: '09', label: 'Secret Scrubbing', group: 'control', path: '/scrub' },
  { id: 'costs',      num: '10', label: 'Cost & Budget',    group: 'manage',  path: '/costs' },
  { id: 'teams',      num: '11', label: 'Agent Groups',     group: 'manage',  path: '/teams' },
  { id: 'identity',   num: '12', label: 'Members & Access', group: 'manage',  path: '/identity' },
] as const

export const ROUTE_GROUPS: readonly RouteGroup[] = ['monitor', 'control', 'manage'] as const
