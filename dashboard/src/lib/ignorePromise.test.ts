import { describe, expect, it, vi } from 'vitest'
import { ignorePromise } from './ignorePromise'

describe('ignorePromise', () => {
  it('returns undefined for a resolving promise', () => {
    expect(ignorePromise(Promise.resolve('ok'))).toBeUndefined()
  })

  it('swallows a rejection without producing an unhandled rejection', async () => {
    const onUnhandled = vi.fn()
    process.on('unhandledRejection', onUnhandled)
    try {
      ignorePromise(Promise.reject(new Error('boom')))
      // Let the microtask queue + a macrotask drain so any unhandled
      // rejection would have fired by now.
      await new Promise((resolve) => setTimeout(resolve, 0))
      expect(onUnhandled).not.toHaveBeenCalled()
    } finally {
      process.off('unhandledRejection', onUnhandled)
    }
  })
})
