import { describe, expect, it } from 'vitest'
import { criticalFiringBadge, criticalFiringCount, isOpenIncident } from './alertBadge'
import { absent, known } from '../../lib/truthfulness'
import type { Alert } from './types'

function alert(patch: Partial<Alert>): Alert {
  return {
    id: 'a',
    ruleId: 'r',
    ruleName: 'rule',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: null,
    firstFiredAt: '2026-05-13T09:00:00Z',
    resolvedAt: null,
    destinationIds: [],
    ...patch,
  }
}

describe('criticalFiringCount', () => {
  it('counts only CRITICAL alerts that are still firing', () => {
    const rows = [
      alert({ id: '1' }),
      alert({ id: '2', status: 'RESOLVED', resolvedAt: '2026-05-13T10:00:00Z' }),
      alert({ id: '3', status: 'SUPPRESSED' }),
      alert({ id: '4', severity: 'HIGH' }),
    ]
    expect(criticalFiringCount(rows)).toBe(1)
  })

  it('does not count a long-resolved CRITICAL — the badge must go away', () => {
    const rows = [alert({ id: '1', status: 'RESOLVED', resolvedAt: '2026-01-01T00:00:00Z' })]
    expect(criticalFiringCount(rows)).toBe(0)
  })
})

describe('isOpenIncident', () => {
  it('treats a deliberate silence as not demanding attention', () => {
    expect(isOpenIncident(alert({ status: 'SUPPRESSED' }))).toBe(false)
    expect(isOpenIncident(alert({ status: 'FIRING' }))).toBe(true)
  })
})

describe('criticalFiringBadge', () => {
  it('reports a real zero as a known value', () => {
    const badge = criticalFiringBadge(known([alert({ severity: 'LOW' })]))
    expect(badge).toEqual({ known: true, value: 0 })
  })

  it('propagates an outage instead of reporting zero critical alerts', () => {
    const badge = criticalFiringBadge(absent<readonly Alert[]>('unavailable', 'HTTP 503'))
    expect(badge.known).toBe(false)
    expect(badge).toMatchObject({ state: 'unavailable', detail: 'HTTP 503' })
  })
})
