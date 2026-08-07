/**
 * The sensitive-data fetch boundary (AAASM-5360).
 *
 * These drive the real `api.GET` through a mock, so the path from an HTTP
 * outcome to an access state is exercised end to end rather than by handing
 * `readAccess` a hand-built error.
 *
 * ## Falsification record
 *
 *  - **M-D — flatten the statuses.** Return `{ kind: 'failed' }` from
 *    `readAccess` for every `SensitiveDataHttpError`, i.e. the shape the generic
 *    `certainFromShapedQuery` fold already has. **4 failed, 14 passed (18):**
 *    `classifies a 403 as a refusal rather than a failure`,
 *    `classifies a 503 as a projection that is not enabled`,
 *    `classifies a 400 as a session with no organisation to read`, and
 *    `classifies a 401 as an unauthenticated session`.
 *    Note which one survived: `gives every blocking state its own title and
 *    description` stayed green, because it builds the states literally and tests
 *    the *copy*, not the classifier. The two halves are deliberately separate —
 *    distinct classification with identical copy would tell an operator nothing,
 *    and one test cannot be evidence for both.
 *  - **M-E — default the acknowledgement.** Make `requestComplianceExport` send
 *    `acknowledge_export: true` regardless of its argument. **1 failed, 17
 *    passed (18):** `sends the export acknowledgement exactly as it was given,
 *    never defaulted`.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  OFFENDER_DIMENSIONS,
  SensitiveDataHttpError,
  accessBlocks,
  accessDescription,
  accessIsRetryable,
  accessTitle,
  readAccess,
  requestComplianceExport,
  summaryFromQuery,
} from './api'
import { DEFAULT_FILTERS, activeFilterCount, filterCacheKey, filterQuery, withFilter } from './filters'
import { SCOPE, WORKED_EXAMPLE_COUNTERS, ratesFor } from './__tests__/fixtures'

const getMock = vi.fn()

vi.mock('../../api/client', () => ({
  api: { GET: (...args: unknown[]) => getMock(...args) },
}))

beforeEach(() => {
  getMock.mockReset()
})

/** An openapi-fetch result for a failing status. */
const failure = (status: number) => ({
  data: undefined,
  error: { title: 'problem' },
  response: { status },
})

describe('readAccess', () => {
  it('reports a healthy outcome as ok and a pending one as pending', () => {
    expect(readAccess({ data: {}, error: null }).kind).toBe('ok')
    // TanStack Query populates `error: null` on pending and success alike, so a
    // bare `!== undefined` check would report a healthy query as broken.
    expect(readAccess({ isPending: true, error: null }).kind).toBe('pending')
  })

  it('classifies a 403 as a refusal rather than a failure', async () => {
    getMock.mockResolvedValue(failure(403))
    const error = await captureError()
    const access = readAccess({ isError: true, error })
    expect(access.kind).toBe('forbidden')
    expect(accessBlocks(access)).toBe(true)
    // Retrying a refusal re-asks a question already answered, so no retry
    // affordance is offered.
    expect(accessIsRetryable(access)).toBe(false)
  })

  it('classifies a 503 as a projection that is not enabled', async () => {
    getMock.mockResolvedValue(failure(503))
    const access = readAccess({ isError: true, error: await captureError() })
    expect(access.kind).toBe('projection-off')
    // The distinction the API's own doc insists on: "the projection is off" and
    // "the window was quiet" are different answers.
    expect(accessDescription(access)).toContain('This is not an empty window')
  })

  it('classifies a 400 as a session with no organisation to read', async () => {
    getMock.mockResolvedValue(failure(400))
    const access = readAccess({ isError: true, error: await captureError() })
    expect(access.kind).toBe('unscoped')
    expect(accessDescription(access)).toContain('never names an organisation on your behalf')
  })

  it('classifies a 401 as an unauthenticated session', async () => {
    getMock.mockResolvedValue(failure(401))
    expect(readAccess({ isError: true, error: await captureError() }).kind).toBe('unauthenticated')
  })

  it('classifies a request that never reached a server as a generic, retryable failure', async () => {
    getMock.mockResolvedValue({ data: undefined, error: 'network down' })
    const access = readAccess({ isError: true, error: await captureError() })
    expect(access.kind).toBe('failed')
    expect(accessIsRetryable(access)).toBe(true)
  })

  it('classifies a non-HTTP throw without inventing a status for it', () => {
    const access = readAccess({ isError: true, error: new Error('boom') })
    expect(access.kind).toBe('failed')
    if (access.kind !== 'failed') return
    expect(access.detail).toBe('boom')
  })

  it('gives every blocking state its own title and description', () => {
    // Distinct classification is worthless if the copy is the same. The states
    // an operator can reach are enumerated and their text compared pairwise.
    const states = [
      { kind: 'unauthenticated' },
      { kind: 'forbidden' },
      { kind: 'unscoped' },
      { kind: 'projection-off' },
      { kind: 'failed', detail: 'x' },
    ] as const
    const titles = states.map(accessTitle)
    const descriptions = states.map(accessDescription)
    expect(new Set(titles).size).toBe(states.length)
    expect(new Set(descriptions).size).toBe(states.length)
    // And none of them is the ok title, which would read as a successful read.
    expect(titles).not.toContain(accessTitle({ kind: 'ok' }))
  })
})

describe('summaryFromQuery', () => {
  it('yields the decoded body for a conforming response', () => {
    const body = {
      scope: SCOPE,
      counters: WORKED_EXAMPLE_COUNTERS,
      rates: ratesFor(WORKED_EXAMPLE_COUNTERS),
      by_category: [],
    }
    const result = summaryFromQuery({ data: body, error: null })
    expect(result.known).toBe(true)
    if (!result.known) return
    expect(result.value.counters.finding_count).toBe(3)
  })

  it('reports a body it cannot read as unknown, naming the field, rather than as zeros', () => {
    const result = summaryFromQuery({ data: { scope: SCOPE }, error: null })
    expect(result.known).toBe(false)
    if (result.known) return
    expect(result.state).toBe('unknown')
    expect(result.detail).toContain('counters')
  })

  it('reports a failed request as unavailable rather than as an empty window', () => {
    const result = summaryFromQuery({ isError: true, error: new Error('nope') })
    expect(result.known).toBe(false)
    if (result.known) return
    expect(result.state).toBe('unavailable')
  })
})

describe('the compliance export', () => {
  it('sends the export acknowledgement exactly as it was given, never defaulted', async () => {
    getMock.mockResolvedValue({ data: { ok: true }, error: undefined, response: { status: 200 } })

    await requestComplianceExport(DEFAULT_FILTERS, true)
    expect(getMock.mock.calls[0][1].params.query.acknowledge_export).toBe(true)

    // The false path exists so the gate itself is testable — and so that a
    // component which has *not* obtained a confirmation cannot accidentally
    // satisfy it by omission.
    await requestComplianceExport(DEFAULT_FILTERS, false)
    expect(getMock.mock.calls[1][1].params.query.acknowledge_export).toBe(false)
  })

  // Deliberately no test here asserting "importing this module issues no
  // export". With `getMock` reset before every test, such an assertion passes
  // whatever the module does — it would be evidence of nothing. The real claim
  // ("mounting the export panel issues no request") is asserted where it can
  // fail, in `ExportPanel.test.tsx`.

  it('rejects with the status when the gateway refuses the export', async () => {
    getMock.mockResolvedValue(failure(403))
    await expect(requestComplianceExport(DEFAULT_FILTERS, true)).rejects.toBeInstanceOf(
      SensitiveDataHttpError,
    )
  })
})

describe('filters', () => {
  it('never sends an org_id, because the dashboard cannot know which orgs a token may read', () => {
    const query = filterQuery(withFilter(DEFAULT_FILTERS, 'agent_id', 'research-bot-04'))
    expect(Object.keys(query)).not.toContain('org_id')
    expect(query.range).toBe('7d')
    expect(query.agent_id).toBe('research-bot-04')
  })

  it('does not count the window as a filter', () => {
    // Otherwise every query looks filtered and "nothing was recorded" can never
    // be told apart from "the filters excluded everything".
    expect(activeFilterCount(DEFAULT_FILTERS)).toBe(0)
    expect(activeFilterCount({ range: '90d' })).toBe(0)
    expect(activeFilterCount(withFilter(DEFAULT_FILTERS, 'category', 'pii'))).toBe(1)
  })

  it('treats a blank value as no filter rather than as a filter matching nothing', () => {
    const cleared = withFilter(withFilter(DEFAULT_FILTERS, 'tool', 'gmail.send'), 'tool', '  ')
    expect(activeFilterCount(cleared)).toBe(0)
    expect(Object.keys(filterQuery(cleared))).toEqual(['range'])
  })

  it('gives logically equal filter sets the same cache key whatever order they were built in', () => {
    const a = withFilter(withFilter(DEFAULT_FILTERS, 'category', 'pii'), 'severity', 'critical')
    const b = withFilter(withFilter(DEFAULT_FILTERS, 'severity', 'critical'), 'category', 'pii')
    expect(filterCacheKey(a)).toBe(filterCacheKey(b))
    expect(filterCacheKey(a)).not.toBe(filterCacheKey(DEFAULT_FILTERS))
  })
})

describe('offender dimensions', () => {
  it('ranks only the four dimensions the route accepts', () => {
    // `agent` and `destination` are legitimate here and forbidden as *metric
    // labels* — the ranking is over the event store, not a time series.
    expect([...OFFENDER_DIMENSIONS]).toEqual(['agent', 'root_agent', 'tool', 'destination'])
  })
})

/** Issue one export request and return whatever it threw. */
async function captureError(): Promise<unknown> {
  try {
    await requestComplianceExport(DEFAULT_FILTERS, true)
  } catch (error) {
    return error
  }
  throw new Error('the request was expected to reject')
}
