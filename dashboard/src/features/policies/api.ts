import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ignorePromise } from '../../lib/ignorePromise'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type Policy = components['schemas']['PolicyResponse']
export type CreatePolicyRequest = components['schemas']['CreatePolicyRequest']
export type SimulatePolicyRequest = components['schemas']['SimulatePolicyRequest']
export type SimulatePolicyResponse = components['schemas']['SimulatePolicyResponse']

export interface PoliciesQueryOptions {
  /**
   * Skip the request entirely.
   *
   * `GET /api/v1/policies` requires cross-tenant **admin** scope by design
   * (AAASM-3995(a) — a policy version spans every tenant's cascade, so a plain
   * read caller must not be able to dump it). A caller without that scope has
   * no question to ask, and asking anyway costs a guaranteed 403 per session
   * plus a stream of authorisation failures from legitimate users in the audit
   * log (AAASM-5186).
   */
  readonly enabled?: boolean

  /**
   * Include older (inactive) policy versions in the response (AAASM-5143).
   *
   * Maps to `GET /api/v1/policies?include_archived` (`openapi/v1.yaml`). Off by
   * default: the endpoint returns only the currently in-force version unless
   * this is set, so the archived history is fetched on demand — when the
   * page-header `history` toggle asks for it — rather than on every load.
   */
  readonly includeArchived?: boolean
}

/**
 * Prefix shared by every policies-list query variant. `cancelQueries` /
 * `invalidateQueries` match it by prefix, so they cover both the default
 * (active-only) view and the `includeArchived` history view (AAASM-5143).
 */
const POLICIES_QUERY_KEY = ['policies'] as const

/** Exact cache key for the default (active-only) policies-list view. */
const POLICIES_DEFAULT_QUERY_KEY = [...POLICIES_QUERY_KEY, { includeArchived: false }] as const

export function usePoliciesQuery({
  enabled = true,
  includeArchived = false,
}: PoliciesQueryOptions = {}) {
  return useQuery({
    // includeArchived is part of the key so flipping the history toggle
    // refetches (and caches the two result sets independently) rather than
    // reusing the active-only page for the archived view.
    queryKey: [...POLICIES_QUERY_KEY, { includeArchived }],
    enabled,
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/policies', {
        // Only send the param in history mode. The endpoint already defaults to
        // active-only, so omitting it when false keeps the default request URL
        // exactly `/api/v1/policies` (no query string) — the URL every existing
        // caller, nav badge and route mock already targets. Sending
        // `include_archived=false` would silently change that URL and slip past
        // consumers matching the bare path (AAASM-5143).
        params: { query: includeArchived ? { include_archived: true } : {} },
      })
      if (error) throw new Error('Failed to fetch policies')
      // AAASM-4892: /policies returns a paginated { items, total } object.
      // AAASM-5186: a 200 whose body carries no `items` is a malformed
      // response, not an empty policy set — `?? []` here turned it into a
      // confident "nothing is inactive" that no consumer could tell apart from
      // a real empty list. Throwing keeps the fetch boundary's contract (a
      // hook reports absence by failing, never by substituting a default) so
      // `certainFromQuery` can render it as the absence it is.
      if (!data?.items) throw new Error('Policies response carried no items')
      return data.items
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
      await queryClient.cancelQueries({ queryKey: POLICIES_QUERY_KEY })
      // Exact key: getQueryData/setQueryData match exactly, so the optimistic
      // placeholder lands in the default (active-only) view — the one visible
      // when a policy is created (history is off by default).
      const previous = queryClient.getQueryData<Policy[]>(POLICIES_DEFAULT_QUERY_KEY)
      const optimistic: Policy = {
        name: nameFromYaml(body.policy_yaml),
        version: 'pending',
        rule_count: 0,
        active: false,
        policy_yaml: body.policy_yaml,
      }
      queryClient.setQueryData<Policy[]>(POLICIES_DEFAULT_QUERY_KEY, (prev) => [
        ...(prev ?? []),
        optimistic,
      ])
      return { previous }
    },

    onError: (_err, _vars, context) => {
      if (context && 'previous' in context) {
        queryClient.setQueryData(POLICIES_DEFAULT_QUERY_KEY, context.previous)
      }
    },

    // Always re-fetch from the server so the optimistic placeholder is
    // replaced by the real `PolicyResponse` (with the server-assigned
    // version, rule_count, and active flag).
    onSettled: () => {
      ignorePromise(queryClient.invalidateQueries({ queryKey: POLICIES_QUERY_KEY }))
    },
  })
}

/**
 * Dry-run a hypothetical `(agent, tool, target)` request against the active
 * policy (AAASM-5037). Read-only what-if: the endpoint mutates no state, so
 * this mutation touches no query cache — the caller renders the returned
 * verdict directly.
 */
export function useSimulatePolicy() {
  return useMutation<SimulatePolicyResponse, Error, SimulatePolicyRequest>({
    mutationFn: async (body) => {
      const { data, error } = await api.POST('/api/v1/policies/simulate', { body })
      if (error || !data) throw new Error('Failed to simulate policy')
      return data
    },
  })
}
