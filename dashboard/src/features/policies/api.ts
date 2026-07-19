import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ignorePromise } from '../../lib/ignorePromise'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type Policy = components['schemas']['PolicyResponse']
export type CreatePolicyRequest = components['schemas']['CreatePolicyRequest']

export function usePoliciesQuery() {
  return useQuery({
    queryKey: ['policies'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/policies', {})
      if (error) throw new Error('Failed to fetch policies')
      // AAASM-4892: /policies returns a paginated { items, total } object.
      return data?.items ?? []
    },
  })
}

export function useActivePolicyQuery() {
  return useQuery({
    queryKey: ['policies', 'active'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/policies/active', {})
      if (error) throw new Error('Failed to fetch active policy')
      return data
    },
  })
}

interface OptimisticContext {
  previous: Policy[] | undefined
}

/**
 * Extract a policy name from the YAML body so the optimistic placeholder
 * can show something useful in the list. Falls back to "(new policy)" if
 * the YAML is empty or doesn't have a metadata.name line.
 */
function nameFromYaml(yaml: string): string {
  // Linear, backtracking-free parse (no regex): scan each line for a top-level
  // `name:` key and return its value. Replaces a `/m` regex that SonarCloud
  // flagged for super-linear runtime (S8786). Behaviour is identical to the
  // old pattern: leading whitespace is skipped, an optional pair of wrapping
  // double-quotes is stripped, and the value is trimmed.
  for (const line of yaml.split('\n')) {
    const trimmed = line.trimStart()
    if (!trimmed.startsWith('name:')) continue
    let value = trimmed.slice('name:'.length).trim()
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
      value = value.slice(1, -1)
    }
    value = value.trim()
    if (value) return value
  }
  return '(new policy)'
}

export function useCreatePolicy() {
  const queryClient = useQueryClient()
  return useMutation<Policy | undefined, Error, CreatePolicyRequest, OptimisticContext>({
    mutationFn: async (body) => {
      const { data, error } = await api.POST('/api/v1/policies', { body })
      if (error) throw new Error('Failed to apply policy')
      return data
    },

    // Optimistic update: pop the new policy into the list immediately so
    // the editor overlay can close without a flash of stale data. On error
    // we restore the snapshot taken before the mutation fired.
    onMutate: async (body) => {
      await queryClient.cancelQueries({ queryKey: ['policies'] })
      const previous = queryClient.getQueryData<Policy[]>(['policies'])
      const optimistic: Policy = {
        name: nameFromYaml(body.policy_yaml),
        version: 'pending',
        rule_count: 0,
        active: false,
        policy_yaml: body.policy_yaml,
      }
      queryClient.setQueryData<Policy[]>(['policies'], (prev) => [
        ...(prev ?? []),
        optimistic,
      ])
      return { previous }
    },

    onError: (_err, _vars, context) => {
      if (context && 'previous' in context) {
        queryClient.setQueryData(['policies'], context.previous)
      }
    },

    // Always re-fetch from the server so the optimistic placeholder is
    // replaced by the real `PolicyResponse` (with the server-assigned
    // version, rule_count, and active flag).
    onSettled: () => {
      ignorePromise(queryClient.invalidateQueries({ queryKey: ['policies'] }))
    },
  })
}
