import { describe, expect, it } from 'vitest'
import { filtersFromSearchParams, filtersToSearchParams } from './urlFilters'
import { DEFAULT_ALERT_FILTERS, type AlertFilters } from './types'

describe('urlFilters', () => {
  it('round-trips a complex filter through search params', () => {
    const filters: AlertFilters = {
      severities: ['CRITICAL', 'HIGH'],
      statuses: ['FIRING'],
      agentQuery: 'aa-001',
      timeRange: 'custom',
      customFrom: '2026-05-13T00:00',
      customTo: '2026-05-13T23:59',
    }
    const sp = filtersToSearchParams(filters)
    expect(filtersFromSearchParams(sp)).toEqual(filters)
  })

  it('returns defaults from an empty search-params object', () => {
    expect(filtersFromSearchParams(new URLSearchParams())).toEqual(DEFAULT_ALERT_FILTERS)
  })

  it('omits the default 24h range from the search params', () => {
    const sp = filtersToSearchParams(DEFAULT_ALERT_FILTERS)
    expect(sp.has('range')).toBe(false)
  })

  it('ignores unknown severity values from the URL', () => {
    const sp = new URLSearchParams('severity=CRITICAL&severity=BOGUS')
    expect(filtersFromSearchParams(sp).severities).toEqual(['CRITICAL'])
  })
})
