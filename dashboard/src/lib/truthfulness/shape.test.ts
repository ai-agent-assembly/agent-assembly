/**
 * The render-boundary shape check (AAASM-5366).
 *
 * Two properties matter here and nothing else does:
 *
 *  - a body that does not match its schema becomes an **absence carrying a
 *    reason** — never a throw, and never a value;
 *  - the decoder is asked only about a body that actually arrived, so an error,
 *    a pending request and an empty payload keep the states `certainFromQuery`
 *    already gives them rather than being re-described as "unreadable".
 */
import { describe, it, expect, vi } from 'vitest'
import { certainFromShapedQuery, conforms, violates, type Decoder } from './shape'
import { isKnown } from './absence'

/** Accepts anything that is an object with a numeric `n`. */
const numeric: Decoder<{ n: number }> = (body) => {
  if (typeof body === 'object' && body !== null && typeof (body as { n?: unknown }).n === 'number') {
    return conforms(body as { n: number })
  }
  return violates('n: expected number')
}

describe('certainFromShapedQuery', () => {
  it('returns the decoded value when the body matches', () => {
    const value = certainFromShapedQuery({ data: { n: 4 }, error: null }, numeric)
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value.n).toBe(4)
  })

  it('turns a body that does not match into an absence carrying the reason', () => {
    // The whole point: a 200 the dashboard cannot read is a thing it does not
    // know, stated as such — not an exception on the way to a field access.
    const value = certainFromShapedQuery({ data: {}, error: null }, numeric)
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unknown')
      expect(value.detail).toBe('n: expected number')
    }
  })

  it('reports an unreadable body as unknown, not as unavailable', () => {
    // `unavailable` asserts the request failed, and it did not. On the Scrub
    // page the two also render differently: `unavailable` offers a retry, which
    // cannot fix a version skew, and has nowhere to put the reason.
    const value = certainFromShapedQuery({ data: { n: 'four' }, error: null }, numeric)
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.state).not.toBe('unavailable')
  })

  it('keeps a failed request unavailable without consulting the decoder', () => {
    const decode = vi.fn(numeric)
    const value = certainFromShapedQuery({ isError: true, error: new Error('HTTP 503') }, decode)
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unavailable')
      expect(value.detail).toBe('HTTP 503')
    }
    expect(decode).not.toHaveBeenCalled()
  })

  it('keeps an in-flight request unknown without consulting the decoder', () => {
    const decode = vi.fn(numeric)
    const value = certainFromShapedQuery({ isPending: true, error: null }, decode)
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.detail).toBe('Request in flight')
    expect(decode).not.toHaveBeenCalled()
  })

  it('honours whenEmpty for a 200 that carried no payload at all', () => {
    // "Nothing came back" and "what came back is unreadable" are different
    // facts, and the caller gets to name the first one.
    const value = certainFromShapedQuery({ data: null, error: null }, numeric, {
      whenEmpty: 'unconfigured',
    })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.state).toBe('unconfigured')
  })

  it('never substitutes a value for an unreadable body', () => {
    // A decoder cannot smuggle a default in through the failing branch: the
    // absent side of the union has no `value` at all, so there is nowhere for a
    // fabricated `0` to live.
    const value = certainFromShapedQuery({ data: { n: null }, error: null }, numeric)
    expect(value).toEqual({ known: false, state: 'unknown', detail: 'n: expected number' })
  })
})
