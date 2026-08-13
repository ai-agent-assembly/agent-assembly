import { expect, test } from '@playwright/test'

/**
 * AAASM-5694 — the assertions that only a real backend can answer.
 *
 * # Why this file exists
 *
 * `tests/e2e/README.md` records that of the 44 gated specs, **all 44** stub every
 * network call, so the gate compares the frontend against its own hand-written
 * mocks and "its real-backend coverage is exactly zero". AAASM-4892 is the
 * demonstrated cost: the pagination envelope changed, the app had already been
 * fixed, and it was the *mocks* that were stale — a green gate certified the
 * frontend against a contract the backend no longer had.
 *
 * Every assertion below is made against a live `aa-api-server` over a real HTTP
 * round trip. Nothing here is stubbed, and nothing here can be satisfied by
 * editing a fixture.
 *
 * # This spec fails when the backend is absent — deliberately
 *
 * `verify-aaasm-5360.spec.ts` skips without its fixture, which is right for a
 * spec that also runs on a developer laptop. This one is different: it exists
 * *only* inside the lane that provisions the backend, so "the backend was not
 * there" is a lane failure, not a reason to opt out. A skip here would recreate
 * the exact defect AAASM-5694 reports — a suite that records real-backend
 * verification as having happened while running nothing.
 */

const API = process.env.AA_API_BASE ?? 'http://127.0.0.1:7700'

/**
 * The `{ items, page, per_page, total }` envelope every paginated endpoint
 * returns (AAASM-4892), asserted structurally.
 *
 * Exported because the drift demonstration below runs this exact function
 * against the pre-fix shape. An assertion helper that the demonstration
 * re-implements would prove nothing about the assertion the lane actually runs.
 */
export function assertPaginatedEnvelope(body: unknown, endpoint: string): void {
  if (Array.isArray(body)) {
    throw new Error(
      `${endpoint} returned a bare array — this is the pre-AAASM-4892 shape. ` +
        `The dashboard reads \`body.items\`, so a bare array reaches ` +
        `\`(f.data ?? []).map\` as a non-array and throws in an ErrorBoundary.`
    )
  }
  if (body === null || typeof body !== 'object') {
    throw new Error(`${endpoint} returned ${typeof body}, expected an object envelope`)
  }
  const envelope = body as Record<string, unknown>
  for (const key of ['items', 'page', 'per_page', 'total']) {
    if (!(key in envelope)) {
      throw new Error(`${endpoint} envelope is missing required key \`${key}\``)
    }
  }
  if (!Array.isArray(envelope.items)) {
    throw new Error(`${endpoint} \`items\` is ${typeof envelope.items}, expected an array`)
  }
  for (const key of ['page', 'per_page', 'total']) {
    if (typeof envelope[key] !== 'number') {
      throw new Error(`${endpoint} \`${key}\` is ${typeof envelope[key]}, expected a number`)
    }
  }
}

/**
 * The endpoints whose OpenAPI schema is a `Paginated*Response` wrapper.
 *
 * Read from `openapi/v1.yaml`, not from the dashboard's beliefs about it — the
 * point of this lane is to compare the app against the server, so a list derived
 * from the frontend would reintroduce the circularity it exists to break.
 */
const PAGINATED_ENDPOINTS = [
  '/api/v1/agents',
  '/api/v1/alerts',
  '/api/v1/approvals',
  '/api/v1/logs',
  '/api/v1/policies',
] as const

test.describe('AAASM-5694 — real-backend contract', () => {
  test('the server is actually up (no silent skip)', async () => {
    const response = await fetch(`${API}/api/v1/health`)
    expect(
      response.ok,
      `no aa-api-server on ${API}. This lane provisions it; if this fails the ` +
        `lane is misconfigured, and skipping would hide exactly that.`
    ).toBe(true)
  })

  for (const endpoint of PAGINATED_ENDPOINTS) {
    test(`${endpoint} returns the AAASM-4892 pagination envelope`, async () => {
      const response = await fetch(`${API}${endpoint}?page=1&per_page=5`)

      // 200 or nothing. An earlier version treated any non-500 as an acceptable
      // "scoping answer", annotated it, and returned — so booting this lane's own
      // server with auth left on produced five 401s, twelve green tests and an
      // exit code of 0 while asserting nothing about any envelope. That is the
      // defect this whole lane exists to remove, reappearing one level down: the
      // skip-guard counts tests that RAN, not assertions that FIRED, so an
      // annotation nothing reads is indistinguishable from a pass.
      //
      // This lane provisions an unauthenticated server by construction
      // (`AASM_API_AUTH=off`), so a 401/403 means the harness is wrong and a
      // 404 means the route moved. Both must be loud.
      expect(
        response.status,
        `${endpoint} must answer 200 in this lane — the server is booted with ` +
          `AASM_API_AUTH=off, so 401/403 means the harness is misconfigured and ` +
          `404 means the route moved. Either way the envelope went unchecked.`
      ).toBe(200)

      assertPaginatedEnvelope(await response.json(), endpoint)
    })
  }

  /**
   * AC3, demonstrated rather than asserted.
   *
   * AAASM-5694 requires proof that at least one assertion in this lane *would*
   * have caught the AAASM-4892 drift. Claiming it would is worth nothing — the
   * claim is checked here by running the lane's own `assertPaginatedEnvelope`
   * against the exact pre-fix shape (a bare array, which is what a generic
   * `Vec<T>` annotation serialised) and requiring it to reject.
   *
   * If someone later loosens the helper so a bare array passes, this test goes
   * red, which is the property that makes the AC durable rather than a one-off
   * observation recorded in a ticket.
   */
  test('the envelope assertion rejects the pre-AAASM-4892 bare-array shape', () => {
    const preFixShape = [{ id: 'agent-1' }, { id: 'agent-2' }]

    expect(() => assertPaginatedEnvelope(preFixShape, '/api/v1/agents')).toThrow(
      /bare array/
    )

    // ...and the post-fix shape must pass, so the demonstration is not merely
    // an assertion that rejects everything.
    expect(() =>
      assertPaginatedEnvelope(
        { items: preFixShape, page: 1, per_page: 5, total: 2 },
        '/api/v1/agents'
      )
    ).not.toThrow()

    // A partial envelope is the more realistic drift: a handler that grew
    // `items` but not the counters.
    expect(() =>
      assertPaginatedEnvelope({ items: preFixShape }, '/api/v1/agents')
    ).toThrow(/missing required key/)
  })
})
