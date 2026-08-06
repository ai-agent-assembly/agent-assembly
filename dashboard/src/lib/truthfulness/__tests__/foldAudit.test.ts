/**
 * The undecoded-fold ratchet, retired to a bare invariant (AAASM-5380).
 *
 * ## What this used to be, and why it is smaller now
 *
 * AAASM-5366 shipped `certainFromShapedQuery`, whose design argument is that the
 * "decode before you read a field" guarantee should be a type error rather than
 * something to remember — true only for the lanes that call it. For the lanes
 * that still called `certainFromQuery` with a `QueryOutcome<T>` whose `T` was an
 * unverified wire claim, this file was the ratchet: it carried an `AUDIT` list of
 * every such fold with a stated disposition, asserted the *set of files* and the
 * *count per file* against that list, and failed if either grew. Some entries
 * were recorded as live defects awaiting their own tickets under the AAASM-5380
 * umbrella.
 *
 * AAASM-5380 slice S8 migrated the last of them — the Overview approvals/alerts/
 * enforcement folds and the shell's alerts badge — onto `certainFromShapedQuery`.
 * With the set empty, the machinery that tracked *which* files fold and *how
 * many times* each does has nothing left to track: there is no allowlist in
 * `.eslintrc.cjs` and no `AUDIT` array here. So the per-file bookkeeping, the
 * count assertions, and the allowlist-vs-AUDIT agreement check are gone.
 *
 * ## What it guards now
 *
 * Three things, each still meaningful with the set empty:
 *
 *  1. **Zero undecoded folds anywhere in app code.** The whole point of the
 *     migration — a scan across `src/**` (excluding the vocabulary itself, tests
 *     and stories) that fails if *any* file calls `certainFromQuery`. This is the
 *     old `countCalls`-over-the-tree total, asserted to be 0 rather than compared
 *     to a per-file list. A new `certainFromQuery(` (or `certainFromQuery<`) call
 *     lands here; migrate it onto `certainFromShapedQuery`.
 *  2. **No inline suppression of the `no-restricted-imports` rule.** Two lines
 *     defeat both halves of the old ratchet at once — an
 *     `// eslint-disable-next-line no-restricted-imports` above
 *     `import { certainFromQuery as fold }` silences the lint rule (the directive
 *     is genuinely used, so `--report-unused-disable-directives` stays quiet) and
 *     the text scan skips `import` lines and looks for `certainFromQuery(`/`<`, so
 *     `fold(` is invisible. A suppression must therefore be argued for in
 *     `.eslintrc.cjs`, in the open, not in the file that wants it.
 *  3. **The migrated modules' exported `*FromQuery` folds still reject a body
 *     that is not their schema.** The scan above catches a fold that skips the
 *     decoder; the export sweep below catches a fold that *has* a decoder and
 *     gets it wrong, by putting the bodies a proxy or a version-skewed API
 *     produce through every `*FromQuery` these modules export.
 *
 * ## Exactly how much of this is machine-checked
 *
 * The scan sees source *text*, so an import alias or a namespace call would slip
 * past it — that hole is covered by the `no-restricted-imports` rule in
 * `.eslintrc.cjs`, which resolves imports. Neither half is sufficient alone: the
 * lint rule cannot count folds within a file (moot now that the count is zero),
 * and this scan cannot see through a rename. The inline-suppressor check (2) is
 * what stops the third door that defeats both.
 */
import { describe, expect, it } from 'vitest'
import * as capabilityApi from '../../../features/capability/api'
import * as policyBadge from '../../../features/policies/policyBadge'
import { isKnown, type Certain, type QueryOutcome } from '..'

/**
 * Every source file, as text, resolved by Vite rather than by `node:fs`.
 *
 * `import.meta.glob` keeps this on the same module graph the app compiles
 * against — no `@types/node` in the app's `tsconfig`, and no assumption about
 * the process working directory, which differs between a root run and a
 * filtered one. The `.css?raw` tests in this repo read files the same way.
 */
const SOURCES: Record<string, string> = import.meta.glob('/src/**/*.{ts,tsx}', {
  query: '?raw',
  eager: true,
  import: 'default',
})

/** Files whose `certainFromQuery` uses are the mechanism itself, not consumers. */
function isExempt(relPath: string): boolean {
  return (
    relPath.startsWith('lib/truthfulness/') ||
    relPath.includes('.test.') ||
    relPath.includes('.stories.')
  )
}

/**
 * Count real calls, not mentions.
 *
 * A line that is a comment or an import names the helper without calling it, and
 * this area is unusually comment-heavy — counting those would make the invariant
 * fire on a docs edit. Kept from the old ratchet unchanged: it is the exact
 * counter whose per-tree total the migration drove to zero.
 */
function countCalls(source: string): number {
  let calls = 0
  for (const raw of source.split('\n')) {
    const line = raw.trim()
    if (line.startsWith('*') || line.startsWith('//') || line.startsWith('import')) continue
    for (const match of line.matchAll(/certainFromQuery[(<]/g)) {
      void match
      calls += 1
    }
  }
  return calls
}

describe('no app-code fold reads a body it has not decoded', () => {
  const folds = new Map<string, number>()
  for (const [path, source] of Object.entries(SOURCES)) {
    const rel = path.replace(/^\/src\//, '')
    if (isExempt(rel)) continue
    const calls = countCalls(source)
    if (calls > 0) folds.set(rel, calls)
  }

  it('sees the tree at all, so the assertion below cannot pass vacuously', () => {
    // If the scanner broke — a renamed helper, a changed source root, a regex
    // that matches nothing — it would agree the empty set has no folds while a
    // live one sat in the tree. Prove it is actually reading source first: the
    // repo has thousands of ts/tsx files, and this test's own name string
    // contains neither `certainFromQuery(` nor `<`, so it is not itself counted.
    expect(Object.keys(SOURCES).length).toBeGreaterThan(100)
  })

  it('finds zero undecoded certainFromQuery folds anywhere in app code', () => {
    // AAASM-5380 emptied the set. A new `certainFromQuery(` or `certainFromQuery<`
    // call in any non-exempt file lands here — migrate it onto
    // `certainFromShapedQuery` (src/lib/truthfulness/shape.ts), which cannot be
    // called without a decoder because its parameter is `unknown`.
    expect(Object.fromEntries(folds)).toEqual({})
  })

  it('has not silently lost the two lanes AAASM-5369 migrated', () => {
    // Neither may reappear as an undecoded fold: both call
    // `certainFromShapedQuery`, and a regression that reverted either would show
    // up in the scan above rather than as a silent loss of the guarantee.
    expect(folds.has('features/capability/api.ts')).toBe(false)
    expect(folds.has('features/policies/policyBadge.ts')).toBe(false)
  })

  /**
   * The third door, which neither half of the ratchet was watching
   * (AAASM-5369 delta review).
   *
   * Two lines defeat *both* halves at once:
   *
   *   // eslint-disable-next-line no-restricted-imports
   *   import { certainFromQuery as fold } from '../lib/truthfulness'
   *
   * ESLint stays silent because the directive is genuinely used, so
   * `--report-unused-disable-directives` does not fire either; and `countCalls`
   * skips `import` lines and looks for `certainFromQuery` followed by `(` or `<`,
   * so `fold(` is invisible to it. Suppressing the rule is therefore a decision
   * that has to be made in the open, in `.eslintrc.cjs`, rather than in the file
   * that wants the exemption.
   */
  it('lets no file suppress the undecoded-fold rule inline', () => {
    const suppressors: string[] = []
    for (const [path, source] of Object.entries(SOURCES)) {
      const rel = path.replace(/^\/src\//, '')
      if (rel.includes('__tests__/foldAudit')) continue
      if (/eslint-disable[^\n]*no-restricted-imports/.test(source)) suppressors.push(rel)
    }
    expect(suppressors).toEqual([])
  })
})

/**
 * The export sweep AAASM-5366 built for `features/scrub/`, extended to the
 * lanes AAASM-5369 migrated.
 *
 * It does not name folds. It enumerates every `*FromQuery` a migrated module
 * exports and puts the same unreadable bodies through all of them, so a fold
 * added to one of these modules later without a decoder fails here without
 * anyone remembering to add a case for it. The scan above catches a fold that
 * skips the decoder; this catches a fold that has one and gets it wrong.
 */
describe('every *FromQuery the migrated modules export, on a body that is not its schema', () => {
  type Fold = (outcome: QueryOutcome<unknown>) => Certain<unknown>

  const MODULES: readonly [string, Record<string, unknown>][] = [
    ['features/capability/api', capabilityApi],
    ['features/policies/policyBadge', policyBadge],
  ]

  const folds = MODULES.flatMap(([module, exports]) =>
    Object.entries(exports)
      .filter(([name, value]) => name.endsWith('FromQuery') && typeof value === 'function')
      // Code-unit order, not `localeCompare`: the expected list below is checked
      // literally, and a locale-sensitive sort would make it a different list
      // on a different machine.
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([name, value]): [string, Fold] => [`${module}#${name}`, value as Fold]),
  )

  it('finds every fold these modules use, so the sweep cannot pass vacuously', () => {
    expect(folds.map(([name]) => name)).toEqual([
      'features/capability/api#capabilityMatrixFromQuery',
      'features/capability/api#cascadeEvidenceFromQuery',
      'features/policies/policyBadge#inactivePolicyBadgeFromQuery',
    ])
  })

  // The bodies a proxy, a partial deploy and a version-skewed API produce.
  // `{}` is the one AAASM-5366 observed unmounting a page.
  //
  // `[]` is deliberately NOT here, unlike in the scrub sweep. It is unreadable
  // for the capability fold but it is a perfectly well-formed *empty policy
  // list* for the badge fold, which correctly reports `known(0)` — the rail
  // then suppresses the badge, which is the honest rendering of "we asked, and
  // no version is inactive". Asserting an absence for it would force a
  // fabricated absence, which is the same sin as a fabricated zero pointing the
  // other way. Each fold's own suite covers its `[]` behaviour.
  const UNREADABLE: readonly [string, unknown][] = [
    ['an empty object', {}],
    ['a scalar', 42],
    ['a string', 'nope'],
    ['an envelope whose rows are empty objects', { policies: [{}], items: [{}], total: 1 }],
  ]

  for (const [name, fold] of folds) {
    for (const [description, body] of UNREADABLE) {
      it(`${name} reports an absence for ${description}, and does not throw`, () => {
        const value = fold({ data: body, error: null })
        expect(isKnown(value)).toBe(false)
        if (!isKnown(value)) {
          // Not `unavailable`: the request succeeded. The operator is told we
          // could not determine the value, and why.
          expect(value.state).toBe('unknown')
          expect(value.detail).toBeTruthy()
        }
      })
    }
  }
})
