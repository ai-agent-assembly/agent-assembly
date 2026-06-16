/**
 * Explicitly discard a promise whose settlement we deliberately do not await.
 *
 * Used for fire-and-forget calls in synchronous contexts — React event
 * handlers and React Query `onSuccess`/`onSettled` callbacks — where the
 * returned promise (e.g. `refetch()` / `invalidateQueries()`) never rejects
 * in practice and there is nothing to do with its result.
 *
 * This replaces the bare `void promise()` idiom: it satisfies
 * `@typescript-eslint/no-floating-promises` while making the intent explicit
 * (and not tripping SonarCloud's `typescript:S3735` "void operator" rule).
 */
export function ignorePromise(promise: Promise<unknown>): void {
  // Attach a no-op handler so an unexpected rejection cannot surface as an
  // unhandled-rejection warning. Intentionally swallows — callers use this
  // only for promises that do not reject in practice.
  promise.catch(() => {
    /* intentionally empty: swallow — see doc comment above */
  })
}
