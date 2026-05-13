/**
 * Centralised copy + tracking constants for the locked custom-roles
 * panel. Keeping these in one module makes it cheap to A/B the upsell
 * message or swap the docs link without touching component code.
 */

export const IAM_CUSTOM_ROLES_COPY = {
  title: 'Custom roles',
  description:
    'Define your own permission sets and assign them to users, service identities, and agents.',
  lockedBody:
    'Custom role creation is available in Agent Assembly Cloud. The community dashboard ships with the six built-in roles below — pick one to scope an identity.',
  upgradeCta: 'Learn about Custom Roles',
  upgradeUrl: 'https://docs.agent-assembly.dev/cloud/custom-roles',
} as const

export const BUILTIN_ROLE_CATALOGUE = [
  { id: 'admin', label: 'admin', description: 'Full control over the assembly runtime.' },
  { id: 'operator', label: 'operator', description: 'Approve / reject pending actions, manage policies.' },
  { id: 'viewer', label: 'viewer', description: 'Read-only access to dashboards and audit log.' },
  { id: 'agent.admin', label: 'agent.admin', description: 'Manage agent identity, scopes, and tokens.' },
  { id: 'agent.operator', label: 'agent.operator', description: 'Invoke tools the agent is authorised for.' },
  { id: 'agent.readonly', label: 'agent.readonly', description: 'Inspect agent state, no action authority.' },
] as const

/** Tracking event fired when the upsell CTA is clicked. */
export const IAM_UPSELL_EVENT = 'iam.custom_roles.upsell_clicked' as const
