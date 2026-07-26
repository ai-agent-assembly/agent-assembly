import { isAbsent, isKnown } from './absence'
import { certainFromQuery } from './query'

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
