import { describe, expect, it } from 'vitest'
import { ignorePromise } from './ignorePromise'

describe('ignorePromise', () => {
  it('returns undefined for a resolving promise', () => {
    expect(ignorePromise(Promise.resolve('ok'))).toBeUndefined()
  })

  it('tolerates a non-thenable argument', () => {
    // Mocked callbacks (e.g. a test refetch) may return undefined rather than
    // a promise; ignorePromise must not throw, matching the old `void` idiom.
    expect(() => ignorePromise(undefined)).not.toThrow()
  })

  it('swallows a rejection rather than letting it propagate', async () => {
    // A floating rejected promise would surface as an unhandled rejection;
    // ignorePromise attaches a catch handler so awaiting a follow-up tick
    // completes without the rejection being re-thrown here.
    expect(() => ignorePromise(Promise.reject(new Error('boom')))).not.toThrow()
    await Promise.resolve()
  })
})
