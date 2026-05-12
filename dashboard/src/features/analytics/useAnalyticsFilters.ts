import { useSearchParams } from 'react-router-dom'
import { useDebouncedCallback } from 'use-debounce'
import { decodeFilters, encodeFilters } from './urlState'
import type { FilterParams } from './urlState'

export function useAnalyticsFilters() {
  const [searchParams, setSearchParams] = useSearchParams()
  const filters = decodeFilters(searchParams)

  const setFilters = useDebouncedCallback((patch: Partial<FilterParams>) => {
    setSearchParams(encodeFilters({ ...filters, ...patch }), { replace: true })
  }, 300)

  return { filters, setFilters }
}
