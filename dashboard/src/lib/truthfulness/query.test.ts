import { isAbsent, isKnown } from './absence'
import { certainFromQuery } from './query'

/**
 * The literal shapes TanStack Query v5 declares, copied field-for-field from
 * `@tanstack/query-core`'s `QueryObserver*Result` interfaces.
 *
 * Hand-trimmed fixtures are what let the `error !== undefined` bug ship: they
 * omitted the `error` key, while every real success and pending result carries
 * `error: null`. These fixtures exist so the module is tested against the input
 * shape its own docs advertise ("a hook result passes straight in"), not
 * against a convenient subset of it.
 */
const TANSTACK_SUCCESS = <T,>(data: T) =>
  ({
    data,
    error: null,
    isError: false,
    isPending: false,
    isLoading: false,
    isLoadingError: false,
    isRefetchError: false,
    isSuccess: true,
    status: 'success',
  }) as const

const TANSTACK_PENDING = {
  data: undefined,
  error: null,
  isError: false,
  isPending: true,
  isLoadingError: false,
  isRefetchError: false,
  isSuccess: false,
  status: 'pending',
} as const

const TANSTACK_ERROR = (error: unknown) =>
  ({
    data: undefined,
    error,
    isError: true,
    isPending: false,
    isLoading: false,
    isLoadingError: true,
    isRefetchError: false,
    isSuccess: false,
    status: 'error',
  }) as const

describe('certainFromQuery — against the real TanStack result shapes', () => {
  it('reports a successful query as known, not as a failure', () => {
    // Regression: TanStack sets `error: null` on every success, so a
    // `!== undefined` guard reported every healthy query as unavailable.
    const value = certainFromQuery(TANSTACK_SUCCESS({ total: 7 }))
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value).toEqual({ total: 7 })
  })

  it('reports a successful query carrying a zero as that zero', () => {
    const value = certainFromQuery(TANSTACK_SUCCESS(0))
    expect(isKnown(value) && value.value).toBe(0)
  })

  it('reports a pending query as unknown, not as a failure', () => {
    // Pending also carries `error: null`.
    const value = certainFromQuery<number>(TANSTACK_PENDING)
    expect(isAbsent(value) && value.state).toBe('unknown')
  })

  it('still reports a genuinely failed query as unavailable', () => {
    const value = certainFromQuery<number>(TANSTACK_ERROR(new Error('HTTP 503')))
    expect(isAbsent(value) && value.state).toBe('unavailable')
    expect(isAbsent(value) && value.detail).toBe('HTTP 503')
  })
})

describe('certainFromQuery', () => {
  it('maps a rejected query to unavailable, keeping the message as detail', () => {
    const value = certainFromQuery<number>({ isError: true, error: new Error('HTTP 503') })
    expect(isKnown(value)).toBe(false)
    expect(isAbsent(value) && value.state).toBe('unavailable')
    expect(isAbsent(value) && value.detail).toBe('HTTP 503')
  })

  it('treats a thrown value as a failure even without the isError flag', () => {
    const value = certainFromQuery<number>({ error: 'network down' })
    expect(isAbsent(value) && value.state).toBe('unavailable')
    expect(isAbsent(value) && value.detail).toBe('network down')
  })

  it('treats an explicit null error as the absence of an error', () => {
    const value = certainFromQuery({ data: 3, error: null })
    expect(isKnown(value) && value.value).toBe(3)
  })

  it('omits detail for a non-descriptive thrown value', () => {
    const value = certainFromQuery<number>({ isError: true, error: { code: 1 } })
    expect(isAbsent(value) && value.state).toBe('unavailable')
    expect(isAbsent(value) && value.detail).toBeUndefined()
  })

  it('maps an in-flight query to unknown, not to a fault', () => {
    // A slow request is not a broken one; rendering a fault tone while data is
    // in flight trains operators to ignore fault tones.
    const value = certainFromQuery<number>({ isPending: true })
    expect(isAbsent(value) && value.state).toBe('unknown')
  })

  it('reports an error ahead of a pending flag', () => {
    const value = certainFromQuery<number>({ isPending: true, isError: true })
    expect(isAbsent(value) && value.state).toBe('unavailable')
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
  ])('maps a %s payload to unknown by default', (_label, data) => {
    const value = certainFromQuery<number>({ data })
    expect(isAbsent(value) && value.state).toBe('unknown')
  })

  it('honours an explicit whenEmpty state', () => {
    const value = certainFromQuery<number>({ data: null }, { whenEmpty: 'unconfigured' })
    expect(isAbsent(value) && value.state).toBe('unconfigured')
  })

  it('never turns a failure into a zero', () => {
    // The bug this helper exists to make unwritable.
    const value = certainFromQuery<number>({ isError: true, error: new Error('boom') })
    expect(isKnown(value)).toBe(false)
    expect((value as { value?: number }).value).toBeUndefined()
  })

  it('passes a real payload through, including a legitimate zero', () => {
    const value = certainFromQuery<number>({ data: 0 })
    expect(isKnown(value) && value.value).toBe(0)
  })

  it('labels a fixture payload as demo rather than as truth', () => {
    const value = certainFromQuery<number>({ data: 5 }, { isDemo: true })
    expect(isKnown(value)).toBe(false)
    expect(isAbsent(value) && value.state).toBe('demo')
    expect(isAbsent(value) && value.sample).toBe(5)
  })
})
