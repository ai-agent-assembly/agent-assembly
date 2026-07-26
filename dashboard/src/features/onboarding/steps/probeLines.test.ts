import { describe, expect, it } from 'vitest'
import { buildProbeLines } from './probeLines'
import { absent, known } from '../../../lib/truthfulness'
import type { GatewayHealth } from '../api'

const HEALTHY: GatewayHealth = {
  status: 'ok',
  version: '0.0.1',
  api_version: 'v1',
  uptime_secs: 900,
  active_connections: 2,
  pipeline_lag_ms: 0,
  checks: { storage: 'ok', policy_engine: 'ok' },
}

describe('buildProbeLines', () => {
  it('emits no ok line for any absence', () => {
    for (const state of ['unavailable', 'unknown', 'unconfigured', 'not-supported'] as const) {
      const lines = buildProbeLines(absent(state, 'detail here'))
      expect(lines.some((l) => l.kind === 'ok')).toBe(false)
      expect(lines.filter((l) => l.kind === 'err')).toHaveLength(2)
    }
  })

  it('falls back to "no response" when the absence carries no detail', () => {
    const lines = buildProbeLines(absent('unavailable'))
    expect(lines.at(-1)).toEqual({ kind: 'err', text: 'no response' })
  })

  it('says so plainly when the gateway reports no subsystem checks at all', () => {
    const lines = buildProbeLines(known({ ...HEALTHY, checks: {} }))
    expect(lines.some((l) => l.text.includes('none reported'))).toBe(true)
    expect(lines.at(-1)?.kind).toBe('ok')
  })
})
