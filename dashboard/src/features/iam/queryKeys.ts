export const iamQueryKeys = {
  all: ['iam'] as const,
  members: () => [...iamQueryKeys.all, 'members'] as const,
  membersPage: (page: number, pageSize: number) =>
    [...iamQueryKeys.members(), { page, pageSize }] as const,
  apiKeys: () => [...iamQueryKeys.all, 'api-keys'] as const,
  // AAASM-5046 — role→capability grants from GET /api/v1/iam/roles.
  roles: () => [...iamQueryKeys.all, 'roles'] as const,
  agents: () => [...iamQueryKeys.all, 'agents'] as const,
  agentPermissions: (agentId: string) =>
    [...iamQueryKeys.agents(), agentId, 'permissions'] as const,
  /**
   * Key used while no agent is selected. The permissions query is disabled in
   * that state, but it still needs a key that cannot collide with a real
   * agent's cache entry.
   */
  agentPermissionsIdle: () => [...iamQueryKeys.agents(), 'permissions', 'idle'] as const,
  // AAASM-5111 removed `accessLog`: no endpoint reports identity-attributed
  // access events, so there is no query to key.
} as const
