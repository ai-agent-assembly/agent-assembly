import { renderHook, act } from '@testing-library/react'
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

describe('useAnalyticsFilters — URL decode (restores filters on page load)', () => {
  it('returns default 7d range when no URL params', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper(),
    })
    expect(result.current.filters.range).toBe('7d')
  })

  it('restores range filter from URL on page load', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper('?range=30d'),
    })
    expect(result.current.filters.range).toBe('30d')
  })

  it('restores 24h range from URL on page load', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper('?range=24h'),
    })
    expect(result.current.filters.range).toBe('24h')
  })

  it('restores custom date range from URL on page load', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper('?range=2024-01-01..2024-01-07'),
    })
    expect(result.current.filters.range).toBe('2024-01-01..2024-01-07')
  })

  it('restores agents filter from URL on page load', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper('?agents=a1,a2'),
    })
    expect(result.current.filters.agents).toEqual(['a1', 'a2'])
  })

  it('restores teams filter from URL on page load', () => {
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

describe('useAnalyticsFilters — URL write (changing filters updates URL)', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('changing range updates decoded filters after debounce fires', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper('?range=7d'),
    })
    expect(result.current.filters.range).toBe('7d')
    act(() => {
      result.current.setFilters({ range: '90d' })
      vi.advanceTimersByTime(300)
    })
    expect(result.current.filters.range).toBe('90d')
  })

  it('changing agents updates decoded filters after debounce fires', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper(),
    })
    expect(result.current.filters.agents).toEqual([])
    act(() => {
      result.current.setFilters({ agents: ['a1', 'a2'] })
      vi.advanceTimersByTime(300)
    })
    expect(result.current.filters.agents).toEqual(['a1', 'a2'])
  })

  it('changing teams updates decoded filters after debounce fires', () => {
    const { result } = renderHook(() => useAnalyticsFilters(), {
      wrapper: makeWrapper(),
    })
    act(() => {
      result.current.setFilters({ teams: ['team-alpha'] })
      vi.advanceTimersByTime(300)
    })
    expect(result.current.filters.teams).toEqual(['team-alpha'])
  })
})
