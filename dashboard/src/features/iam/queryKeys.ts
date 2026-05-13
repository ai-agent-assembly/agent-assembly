export const iamQueryKeys = {
  all: ['iam'] as const,
  members: () => [...iamQueryKeys.all, 'members'] as const,
  membersPage: (page: number, pageSize: number) =>
    [...iamQueryKeys.members(), { page, pageSize }] as const,
} as const
