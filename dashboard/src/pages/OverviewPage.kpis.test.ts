import { describe, it, expect } from 'vitest'
import type { FleetAgent } from '../features/agents/fleetTypes'
import type { Alert } from '../features/alerts/types'
import { compareBySeverity, deriveOverviewKpis } from './OverviewPage.kpis'

function makeFleetAgent(overrides: Partial<FleetAgent> = {}): FleetAgent {
  return {
    source: {} as FleetAgent['source'],
    id: 'agent-1',
    name: 'research-bot',
    framework: 'langgraph',
    status: 'active',
    owner: null,
    mode: 'enforce',
    flagged: false,
    lastSeen: null,
    trust: null,
    blocked24h: null,
    scrubbed24h: null,
    note: null,
    ...overrides,
  }
}

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 'alert-1',
    ruleId: 'rule-1',
    ruleName: 'shell.exec blocked',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: 'research-bot',
    firstFiredAt: '2026-01-01T14:02:08Z',
    resolvedAt: null,
    destinationIds: [],
    ...overrides,
  }
}

describe('compareBySeverity', () => {
  it('orders CRITICAL before HIGH before MEDIUM before LOW', () => {
    const alerts = [
      makeAlert({ id: 'lo', severity: 'LOW' }),
      makeAlert({ id: 'med', severity: 'MEDIUM' }),
      makeAlert({ id: 'crit', severity: 'CRITICAL' }),
      makeAlert({ id: 'hi', severity: 'HIGH' }),
    ]
    const sorted = [...alerts].sort(compareBySeverity).map((a) => a.id)
    expect(sorted).toEqual(['crit', 'hi', 'med', 'lo'])
  })

  it('treats equal severities as equal (returns 0)', () => {
    expect(compareBySeverity(makeAlert({ severity: 'HIGH' }), makeAlert({ severity: 'HIGH' }))).toBe(
      0,
    )
  })
})

describe('deriveOverviewKpis', () => {
  it('returns full-score posture for an empty fleet (total === 0 branch)', () => {
    const kpis = deriveOverviewKpis([], [])
    expect(kpis.total).toBe(0)
    expect(kpis.flagged).toBe(0)
    expect(kpis.identityScore).toBe(100)
    expect(kpis.capabilityScore).toBe(100)
    expect(kpis.scrubScore).toBe(91)
    // (100 + 100 + 91) / 3 → 97 (rounded).
    expect(kpis.overallScore).toBe(97)
    expect(kpis.topAlert).toBeUndefined()
    expect(kpis.firingAlerts).toEqual([])
  })

  it('counts modes and flags across the fleet', () => {
    const kpis = deriveOverviewKpis(
      [
        makeFleetAgent({ id: 'a', mode: 'enforce' }),
        makeFleetAgent({ id: 'b', mode: 'enforce' }),
        makeFleetAgent({ id: 'c', mode: 'shadow' }),
        makeFleetAgent({ id: 'd', mode: 'off' }),
        makeFleetAgent({ id: 'e', mode: 'enforce', flagged: true }),
      ],
      [],
    )
    expect(kpis.total).toBe(5)
    expect(kpis.enforcing).toBe(3)
    expect(kpis.shadow).toBe(1)
    expect(kpis.flagged).toBe(1)
  })

  it('degrades identity and capability scores as agents are flagged', () => {
    // 1 of 4 flagged: identity = 100 - 1*3 = 97; capability = round(100 - (1/4)*100*0.5) = 88.
    const kpis = deriveOverviewKpis(
      [
        makeFleetAgent({ id: 'a', flagged: true }),
        makeFleetAgent({ id: 'b' }),
        makeFleetAgent({ id: 'c' }),
        makeFleetAgent({ id: 'd' }),
      ],
      [],
    )
    expect(kpis.flagged).toBe(1)
    expect(kpis.identityScore).toBe(97)
    expect(kpis.capabilityScore).toBe(88)
  })

  it('clamps the identity score at zero when many agents are flagged', () => {
    // 40 flagged → 100 - 40*3 = -20 → clamped to 0.
    const fleet = Array.from({ length: 40 }, (_, i) =>
      makeFleetAgent({ id: `a${i}`, flagged: true }),
    )
    const kpis = deriveOverviewKpis(fleet, [])
    expect(kpis.flagged).toBe(40)
    expect(kpis.identityScore).toBe(0)
  })

  it('sums blocked and scrubbed counts, treating null metrics as zero', () => {
    const kpis = deriveOverviewKpis(
      [
        makeFleetAgent({ id: 'a', blocked24h: 3, scrubbed24h: 10 }),
        makeFleetAgent({ id: 'b', blocked24h: null, scrubbed24h: null }),
        makeFleetAgent({ id: 'c', blocked24h: 2, scrubbed24h: 5 }),
      ],
      [],
    )
    expect(kpis.blocked).toBe(5)
    expect(kpis.scrubbed).toBe(15)
  })

  it('keeps only FIRING alerts and picks the most-severe as the top alert', () => {
    const kpis = deriveOverviewKpis(
      [makeFleetAgent()],
      [
        makeAlert({ id: 'resolved-crit', severity: 'CRITICAL', status: 'RESOLVED' }),
        makeAlert({ id: 'firing-med', severity: 'MEDIUM', status: 'FIRING' }),
        makeAlert({ id: 'firing-crit', severity: 'CRITICAL', status: 'FIRING' }),
        makeAlert({ id: 'suppressed-hi', severity: 'HIGH', status: 'SUPPRESSED' }),
      ],
    )
    expect(kpis.firingAlerts.map((a) => a.id)).toEqual(['firing-med', 'firing-crit'])
    expect(kpis.topAlert?.id).toBe('firing-crit')
  })

  it('leaves the top alert undefined when nothing is firing', () => {
    const kpis = deriveOverviewKpis(
      [makeFleetAgent()],
      [makeAlert({ status: 'RESOLVED' }), makeAlert({ status: 'SUPPRESSED' })],
    )
    expect(kpis.firingAlerts).toEqual([])
    expect(kpis.topAlert).toBeUndefined()
  })
})
