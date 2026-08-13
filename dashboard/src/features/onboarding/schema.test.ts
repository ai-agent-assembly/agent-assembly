import { describe, expect, it } from 'vitest'
import { decodeGatewayHealth, decodeRegistryAnswer } from './schema'

/**
 * Unit coverage for the registry decoder's own branches (AAASM-5380 S3).
 *
 * The enroll-step component test proves the *surface* degrades to absence; this
 * proves the decoder itself — both the conforming path and every rejection
 * path, including the `firstFault` path-vs-root message branch — so a malformed
 * body can never reach the step's `.map` / meter as a fabricated count.
 */
describe('decodeRegistryAnswer', () => {
  it('conforms a well-formed registry envelope and passes the body through', () => {
    const body = {
      total: 2,
      items: [
        { id: 'a1', name: 'researcher', framework: 'langgraph' },
        { id: 'a2', name: 'planner', framework: 'crewai' },
      ],
    }
    const result = decodeRegistryAnswer(body)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.total).toBe(2)
      expect(result.value.items).toHaveLength(2)
    }
  })

  it('rejects a body missing `total`, naming the offending field', () => {
    const result = decodeRegistryAnswer({ items: [] })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toContain('total')
      expect(result.reason).toBeTruthy()
    }
  })

  it('rejects a non-array `items` (the shape that would crash `.map`)', () => {
    const result = decodeRegistryAnswer({ total: 1, items: {} })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('items')
  })

  it('rejects a row missing a required string field', () => {
    const result = decodeRegistryAnswer({ total: 1, items: [{ id: 'a1', name: 'x' }] })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('framework')
  })

  it('rejects a non-object body via the root-path message branch', () => {
    const result = decodeRegistryAnswer(42)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })
})

/**
 * Unit coverage for the gateway-health decoder's own branches (AAASM-5380 S4).
 *
 * The step-2 component test proves the *surface* degrades to a failure line;
 * this proves the decoder itself — the conforming path and every rejection path
 * — so a malformed body can never reach `Object.entries(health.checks)` in
 * `probeLines.ts` as a `TypeError`. It reuses `asHealthResponse`'s recognise/
 * decline rule, so these are the same shapes that path already declined.
 */
describe('decodeGatewayHealth', () => {
  const HEALTHY = {
    status: 'ok',
    version: '0.0.1',
    api_version: 'v1',
    uptime_secs: 900,
    active_connections: 2,
    pipeline_lag_ms: 0,
    checks: { storage: 'ok', policy_engine: 'ok' },
  }

  it('conforms a well-formed health report and passes the body through', () => {
    const result = decodeGatewayHealth(HEALTHY)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.status).toBe('ok')
      expect(result.value.checks).toEqual({ storage: 'ok', policy_engine: 'ok' })
    }
  })

  it('conforms a degraded report — a 503 body is still a health report', () => {
    const result = decodeGatewayHealth({
      ...HEALTHY,
      status: 'degraded',
      checks: { storage: 'degraded', policy_engine: 'ok' },
    })
    expect(result.ok).toBe(true)
  })

  it('rejects a 200 body with no `checks` — the shape that crashed Object.entries', () => {
    const result = decodeGatewayHealth({ status: 'ok', version: '0.0.1', api_version: 'v1' })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })

  it('rejects a non-map `checks` (an array of statuses is not a string-valued map)', () => {
    const result = decodeGatewayHealth({ ...HEALTHY, checks: ['ok', 'ok'] })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })

  it('rejects a `checks` whose values are not all strings', () => {
    const result = decodeGatewayHealth({ ...HEALTHY, checks: { storage: 'ok', lag: 12 } })
    expect(result.ok).toBe(false)
  })

  it('rejects a body missing `status`', () => {
    const result = decodeGatewayHealth({
      version: '0.0.1',
      api_version: 'v1',
      checks: { storage: 'ok' },
    })
    expect(result.ok).toBe(false)
  })

  it('rejects an empty-string `status`', () => {
    const result = decodeGatewayHealth({ ...HEALTHY, status: '' })
    expect(result.ok).toBe(false)
  })

  it('rejects a non-object body (a proxy HTML error page)', () => {
    const result = decodeGatewayHealth('not a health report')
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })
})
