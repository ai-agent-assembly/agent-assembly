export const iamQueryKeys = {
  all: ['iam'] as const,
  members: () => [...iamQueryKeys.all, 'members'] as const,
  membersPage: (page: number, pageSize: number) =>
    [...iamQueryKeys.members(), { page, pageSize }] as const,
  apiKeys: () => [...iamQueryKeys.all, 'api-keys'] as const,
  agents: () => [...iamQueryKeys.all, 'agents'] as const,
  agentPermissions: (agentId: string) =>
    [...iamQueryKeys.agents(), agentId, 'permissions'] as const,
} as const
