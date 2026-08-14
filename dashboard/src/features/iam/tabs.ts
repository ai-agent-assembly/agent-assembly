export const IAM_TAB_KEYS = ['members', 'services', 'roles', 'access-log'] as const

export type IamTabKey = (typeof IAM_TAB_KEYS)[number]

export const IAM_DEFAULT_TAB: IamTabKey = 'members'

// IamTabKey is a closed local union; `parseIamTab` validates the `?tab=` query
// param against `IAM_TAB_KEYS` before this table is ever indexed — narrow-
// union Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
export const IAM_TAB_LABELS: Record<IamTabKey, string> = {
  'members': 'Members',
  'services': 'Service Identities',
  'roles': 'Roles & Permissions',
  'access-log': 'Access Log',
}

export function parseIamTab(params: URLSearchParams): IamTabKey {
  const raw = params.get('tab')
  return isIamTabKey(raw) ? raw : IAM_DEFAULT_TAB
}

function isIamTabKey(value: string | null): value is IamTabKey {
  return value !== null && (IAM_TAB_KEYS as readonly string[]).includes(value)
}
