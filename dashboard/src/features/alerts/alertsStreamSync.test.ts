import { QueryClient } from '@tanstack/react-query'
import { describe, expect, it } from 'vitest'
import { applyFire, applyResolve, applySilence } from './alertsStreamSync'
import { ALERTS_LIST_KEY, alertDetailKey } from './endpoints'
import type { AlertsPageResult } from './api'
import type { Alert } from './types'

const FIRING: Alert = {
  id: 'a-1',
  ruleId: 'r-1',
  ruleName: 'Budget > 90%',
  severity: 'CRITICAL',
  status: 'FIRING',
  agentId: 'aa-001',
  firstFiredAt: '2026-05-14T09:00:00Z',
  resolvedAt: null,
  destinationIds: ['slack-ops'],
}

const RESOLVED: Alert = { ...FIRING, status: 'RESOLVED', resolvedAt: '2026-05-14T09:30:00Z' }
const SUPPRESSED: Alert = { ...FIRING, status: 'SUPPRESSED' }

function page(items: readonly Alert[], total: number | null = items.length): AlertsPageResult {
  return { items, total, page: 1, perPage: 50 }
}

function seed(initial: AlertsPageResult) {
  const client = new QueryClient()
  client.setQueryData(ALERTS_LIST_KEY, initial)
  return client
}

function cached(client: QueryClient): AlertsPageResult | undefined {
  return client.getQueryData<AlertsPageResult>(ALERTS_LIST_KEY)
}

describe('applyFire', () => {
  it('prepends a new alert to the cached page', () => {
    const existing: Alert = { ...FIRING, id: 'a-prev' }
    const client = seed(page([existing]))
    applyFire(client, FIRING)
    expect(cached(client)?.items.map((a) => a.id)).toEqual(['a-1', 'a-prev'])
  })

  it('grows the reported total alongside the page', () => {
    const client = seed(page([{ ...FIRING, id: 'a-prev' }], 214))
    applyFire(client, FIRING)
    expect(cached(client)?.total).toBe(215)
  })

  it('leaves an unknown total unknown', () => {
    const client = seed(page([{ ...FIRING, id: 'a-prev' }], null))
    applyFire(client, FIRING)
    expect(cached(client)?.total).toBeNull()
  })

  it('replaces an existing alert with the same id rather than duplicating', () => {
    const client = seed(page([{ ...FIRING, severity: 'LOW' }], 7))
    applyFire(client, FIRING)
    expect(cached(client)?.items).toHaveLength(1)
    expect(cached(client)?.items[0].severity).toBe('CRITICAL')
    // A replacement is not a new alert, so the total must not move.
    expect(cached(client)?.total).toBe(7)
  })

  it('does nothing when no list cache is present', () => {
    const client = new QueryClient()
    applyFire(client, FIRING)
    expect(cached(client)).toBeUndefined()
  })

  it('does not reach into a single-alert detail cache', () => {
    const client = seed(page([FIRING]))
    client.setQueryData(alertDetailKey('a-1'), { ...FIRING, routingLog: [] })
    expect(() => applyFire(client, { ...FIRING, id: 'a-2' })).not.toThrow()
    expect(client.getQueryData(alertDetailKey('a-1'))).toMatchObject({ id: 'a-1' })
  })
})

describe('applyResolve', () => {
  it('updates the matching row to RESOLVED in place', () => {
    const client = seed(page([FIRING]))
    applyResolve(client, RESOLVED)
    expect(cached(client)?.items[0].status).toBe('RESOLVED')
  })

  it('leaves non-matching rows untouched', () => {
    const other: Alert = { ...FIRING, id: 'a-other' }
    const client = seed(page([other, FIRING]))
    applyResolve(client, RESOLVED)
    expect(cached(client)?.items.find((a) => a.id === 'a-other')?.status).toBe('FIRING')
  })

  it('does not invent a row for an alert outside the loaded page', () => {
    const client = seed(page([FIRING], 214))
    applyResolve(client, { ...RESOLVED, id: 'a-off-page' })
    expect(cached(client)?.items.map((a) => a.id)).toEqual(['a-1'])
  })
})

describe('applySilence', () => {
  it('updates the matching row to SUPPRESSED', () => {
    const client = seed(page([FIRING]))
    applySilence(client, SUPPRESSED)
    expect(cached(client)?.items[0].status).toBe('SUPPRESSED')
  })
})
