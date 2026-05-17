export const iamQueryKeys = {
  all: ['iam'] as const,
  members: () => [...iamQueryKeys.all, 'members'] as const,
  membersPage: (page: number, pageSize: number) =>
    [...iamQueryKeys.members(), { page, pageSize }] as const,
  apiKeys: () => [...iamQueryKeys.all, 'api-keys'] as const,
  agents: () => [...iamQueryKeys.all, 'agents'] as const,
  agentPermissions: (agentId: string) =>
    [...iamQueryKeys.agents(), agentId, 'permissions'] as const,
  // AAASM-1398 — Access Log tab query keys. Carrying the filter object
  // in the key so React Query can cache one entry per filter shape.
  accessLog: (filter: object) =>
    [...iamQueryKeys.all, 'access-log', filter] as const,
} as const
