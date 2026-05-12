import { renderHook } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAnalyticsFilters } from './useAnalyticsFilters'

function makeWrapper(search = '') {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <MemoryRouter initialEntries={[`/analytics${search}`]}>{children}</MemoryRouter>
    )
  }
}

describe('useAnalyticsFilters', () => {
  it('returns default 7d range when no URL params', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper(),
    })
    expect(result.current.filters.range).toBe('7d')
  })

  it('decodes range from URL search params', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper('?range=30d'),
    })
    expect(result.current.filters.range).toBe('30d')
  })

  it('decodes agents from URL search params', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper('?agents=a1,a2'),
    })
    expect(result.current.filters.agents).toEqual(['a1', 'a2'])
  })

  it('decodes teams from URL search params', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper('?teams=t1,t2'),
    })
    expect(result.current.filters.teams).toEqual(['t1', 't2'])
  })

  it('returns empty agents and teams when params absent', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper(),
    })
    expect(result.current.filters.agents).toEqual([])
    expect(result.current.filters.teams).toEqual([])
  })
})
