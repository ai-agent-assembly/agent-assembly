import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type CostHistory = components['schemas']['CostHistoryResponse']
export type CostHistoryPoint = components['schemas']['CostHistoryPoint']
export type BudgetTree = components['schemas']['BudgetTreeResponse']
export type BudgetTreeNode = components['schemas']['BudgetTreeNode']

/**
 * Trailing daily spend series for the Costs page history chart. `days` is part
 * of the query key so changing the window refetches rather than serving a stale
 * series. Defaults to the 7-day window the page renders.
 */
export function useCostHistoryQuery(days = 7) {
  return useQuery<CostHistory>({
    queryKey: ['costs', 'history', days],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/costs/history', {
        params: { query: { days } },
      })
      if (error) throw new Error('Failed to fetch cost history')
      if (!data) throw new Error('Cost history response was empty')
      return data
    },
  })
}

/**
 * Org → team → agent budget-inheritance tree for the Costs page. Read-only; the
 * `root` is `null` when the caller can see no tenant, which the component
 * renders as an empty state.
 */
export function useBudgetTreeQuery() {
  return useQuery<BudgetTree>({
    queryKey: ['costs', 'budget-tree'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/costs/budget-tree', {})
      if (error) throw new Error('Failed to fetch budget tree')
      if (!data) throw new Error('Budget tree response was empty')
      return data
    },
  })
}
