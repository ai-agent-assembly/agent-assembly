import { QueryClient } from '@tanstack/react-query'
import { describe, expect, it } from 'vitest'
import { applyFire, applyResolve, applySilence } from './alertsStreamSync'
import { alertsQueryKeys } from './endpoints'
import { DEFAULT_ALERT_FILTERS, type Alert } from './types'

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

function seed(initial: readonly Alert[]) {
  const client = new QueryClient()
  client.setQueryData([alertsQueryKeys.alerts, DEFAULT_ALERT_FILTERS], initial)
  return client
}

describe('applyFire', () => {
  it('prepends a new alert to every list cache', () => {
    const existing: Alert = { ...FIRING, id: 'a-prev' }
    const client = seed([existing])
    applyFire(client, FIRING)
    const cached = client.getQueryData<readonly Alert[]>([
      alertsQueryKeys.alerts,
      DEFAULT_ALERT_FILTERS,
    ])
    expect(cached?.map((a) => a.id)).toEqual(['a-1', 'a-prev'])
  })

  it('replaces an existing alert with the same id rather than duplicating', () => {
    const client = seed([{ ...FIRING, severity: 'LOW' }])
    applyFire(client, FIRING)
    const cached = client.getQueryData<readonly Alert[]>([
      alertsQueryKeys.alerts,
      DEFAULT_ALERT_FILTERS,
    ])
    expect(cached).toHaveLength(1)
    expect(cached?.[0].severity).toBe('CRITICAL')
  })

  it('does nothing when no list cache is present', () => {
    const client = new QueryClient()
    applyFire(client, FIRING)
    expect(
      client.getQueryData([alertsQueryKeys.alerts, DEFAULT_ALERT_FILTERS]),
    ).toBeUndefined()
  })
})

describe('applyResolve', () => {
  it('updates the matching row to RESOLVED in place', () => {
    const client = seed([FIRING])
    applyResolve(client, RESOLVED)
    const cached = client.getQueryData<readonly Alert[]>([
      alertsQueryKeys.alerts,
      DEFAULT_ALERT_FILTERS,
    ])
    expect(cached?.[0].status).toBe('RESOLVED')
  })

  it('leaves non-matching rows untouched', () => {
    const other: Alert = { ...FIRING, id: 'a-other' }
    const client = seed([other, FIRING])
    applyResolve(client, RESOLVED)
    const cached = client.getQueryData<readonly Alert[]>([
      alertsQueryKeys.alerts,
      DEFAULT_ALERT_FILTERS,
    ])
    expect(cached?.find((a) => a.id === 'a-other')?.status).toBe('FIRING')
  })
})

describe('applySilence', () => {
  it('updates the matching row to SUPPRESSED', () => {
    const client = seed([FIRING])
    applySilence(client, SUPPRESSED)
    const cached = client.getQueryData<readonly Alert[]>([
      alertsQueryKeys.alerts,
      DEFAULT_ALERT_FILTERS,
    ])
    expect(cached?.[0].status).toBe('SUPPRESSED')
  })
})
