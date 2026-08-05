/**
 * The repo-wide disposition of every undecoded `certainFromQuery` fold
 * (AAASM-5369).
 *
 * ## Why a test and not a document
 *
 * AAASM-5366 shipped `certainFromShapedQuery`, whose whole design argument is
 * that the guarantee should be a type error rather than something to remember.
 * That works for the lanes that call it. It says nothing about the lanes that
 * still call `certainFromQuery` with a `QueryOutcome<T>` whose `T` is an
 * unverified wire claim — and it cannot, because those lanes compile perfectly.
 *
 * A prose audit of them decays the day someone adds the nineteenth. So the
 * audit lives here: the list below is the complete, frozen set of undecoded
 * folds outside `lib/truthfulness/`, each with a stated reason. Adding a new
 * `certainFromQuery` call anywhere fails this file, and the only ways to make
 * it pass again are to migrate the fold onto a decoder or to write down why it
 * is safe. That is exactly the review this ticket was raised out of, made
 * automatic.
 *
 * ## What a disposition means
 *
 * - `guarded-at-fetch` — the query function *validates* the body and throws on
 *   anything it cannot read, so a schema-invalid `200` reaches the fold as
 *   `unavailable` and the fold's own field reads are unreachable. This is a
 *   claim about specific lines of code, cited in each entry, not about a
 *   comment nearby: two of the comments in this area asserted safety that the
 *   code did not provide.
 * - `constructed-client-side` — the query function builds the value itself
 *   (a `Map`, an object literal), so there is no wire shape to mistrust.
 * - `hazardous` — a schema-invalid `200` reaches the fold intact and produces
 *   either a `TypeError` or a fabricated value. **These are live defects.**
 *   They are recorded rather than fixed here because each needs its own
 *   decoder, its own absence rendering and its own mutation proof, and folding
 *   eight page migrations into a shell-and-capability bugfix would make the
 *   diff unreviewable. Each names the ticket that carries it.
 *
 * `hazardous` is deliberately allowed to pass this test. A test that failed on
 * them would be turned off within a day, and the value here is the ratchet:
 * the *set* cannot grow silently, and nothing can move out of `hazardous`
 * without someone editing this file and saying why.
 *
 * ## Exactly how much of this is machine-checked
 *
 * Two things, and they are the two that decay: the **set of files** that fold a
 * query undecoded, and the **count per file**. Nothing here resolves a query
 * function or re-derives a disposition — those came from a human reading each
 * `queryFn`, and the `reason` strings are that human's claim, checked only for
 * shape. Do not describe this file as machine-checking the dispositions; the
 * AAASM-5369 review caught exactly that overstatement being made about it, on a
 * PR whose subject is artefacts claiming properties the code does not provide.
 *
 * The set and the count are enforced by a **text scan**, which an import alias
 * (`import { certainFromQuery as fold }`) or a namespace call (`T.certainFromQuery`)
 * would slip past. The compiler-enforced half of the ratchet is the
 * `no-restricted-imports` rule in `.eslintrc.cjs`, whose allowlist is the same
 * set of files (five, since AAASM-5380 migrated the two approvals surfaces, then
 * the Fleet and Step-5-enroll agent lists, then the step-2 gateway-health
 * probe, and then the AlertsPage rules/alerts/total folds); it
 * catches aliasing and namespace access for free. Neither half
 * is sufficient alone — the lint rule cannot count folds within a file, and this
 * scan cannot see through a rename.
 */
import { describe, expect, it } from 'vitest'
import * as capabilityApi from '../../../features/capability/api'
import * as policyBadge from '../../../features/policies/policyBadge'
import { isKnown, type Certain, type QueryOutcome } from '..'
import eslintrc from '../../../../.eslintrc.cjs'

/**
 * The allowlist as ESLint actually reads it.
 *
 * Taken from the config object rather than re-typed here, so this compares the
 * two lists instead of comparing this file to a copy of itself. The allowlist
 * override is the one that switches `no-restricted-imports` off for a set of
 * literal paths; the other such override targets glob patterns (the
 * vocabulary's own module and the test files), which is what distinguishes
 * them.
 */
const ESLINT_ALLOWLIST: readonly string[] = (eslintrc.overrides ?? [])
  .filter((o) => o.rules?.['no-restricted-imports'] === 'off')
  .filter((o) => o.files.every((f) => !f.includes('*')))
  .flatMap((o) => o.files)

type Disposition = 'guarded-at-fetch' | 'constructed-client-side' | 'hazardous'

interface FoldSite {
  /** Path relative to `src/`. */
  readonly file: string
  /** How many undecoded `certainFromQuery` calls this file makes. */
  readonly calls: number
  readonly disposition: Disposition
  /** Why — citing the code that makes it so, not a comment that claims it. */
  readonly reason: string
}

/**
 * Every undecoded fold in the dashboard, as of AAASM-5369.
 *
 * Verified by reading each query function, not by trusting the annotation at
 * the call site — the annotation is the thing under suspicion.
 */
const AUDIT: readonly FoldSite[] = [
  {
    file: 'components/AppShell.tsx',
    calls: 1,
    disposition: 'guarded-at-fetch',
    reason:
      'The alerts fold. `readAlertsPage` runs `parseAlertList` (features/alerts/parseAlert.ts), which throws `AlertShapeError` on a non-array `items` and on any row without a string id or with an unrecognised severity/status. So `alerts.data` is a validated `Alert[]` or the query is in error. This is the one fold that runs outside every ErrorBoundary in the tree — the sibling policies fold in the same component was AAASM-5369 site 1 — and it is safe only because that parse throws first.',
  },
  {
    file: 'components/agentDetail/agentPosture.ts',
    calls: 1,
    disposition: 'hazardous',
    reason:
      'A non-array `resources` throws inside the generator `tallyVerdicts` consumes, at render, outside any queryFn. A truthy non-array `policies` makes `cascadeEvidenceOf` read `.length` as `undefined`, which is not `0`, so the empty-cascade guard is skipped and counting proceeds on unread data. `api/capability.ts` casts the body (`data as CapabilityMatrix`); the hook only incidentally checks `agents` via `.find`. Follow-up: AAASM-5380.',
  },
  {
    file: 'pages/CostsPage.tsx',
    calls: 2,
    disposition: 'hazardous',
    reason:
      'Both hooks in features/teams/api.ts end in `data as CostSummary` / `data as TopologyOverview` — the module comment calls them accepted-risk casts. Every downstream read is optional-chained, so nothing throws; instead `whenEmpty: "unconfigured"` never fires (the body is non-null) and `countBlockedByBudget` returns a measured-looking `known(0)` teams blocked by budget. Follow-up: AAASM-5380.',
  },
  {
    file: 'pages/OverviewPage.tsx',
    calls: 3,
    disposition: 'hazardous',
    reason:
      'Mixed, and one fold lighter since AAASM-5380 slice S2. `alerts` is guarded by `parseAlertList`; `enforcement` is a Map built client-side. `approvals` inherits the `?? []` and renders a confident "0 pending approvals". The `policies` fold that used to live here is now decoded through `decodePolicyList` (features/policies/schema.ts) and no longer counts an unread body — closing AAASM-5379, the literal `undefined ACTIVE POLICIES` it rendered. Follow-up: AAASM-5378 (the approvals `?? []`), AAASM-5380 (the remaining three folds).',
  },
  {
    file: 'pages/TeamsPage.tsx',
    calls: 1,
    disposition: 'hazardous',
    reason:
      'One fold lighter since AAASM-5380 slice S3: the topology-nodes fold now runs through `decodeTopologyNodes` (features/agents/schema.ts) and the hook carries `nodes` intact rather than `?? []`, so a missing or non-array `nodes` reports an absence rather than a confident "0 unclaimed" chip or a `.filter` crash. The remaining fold is the overview census: `useTopologyOverviewQuery` is a bare cast, and a missing `total_agent_count` makes the census `unaccountedFor` compute to `NaN` rather than reporting the disagreement it exists to report. Follow-up: AAASM-5380.',
  },
]

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
 * A line that is a comment or an import names the helper without calling it,
 * and this area is unusually comment-heavy — counting those would make the
 * expected numbers meaningless and the ratchet fire on a docs edit.
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

describe('the undecoded-fold audit is complete', () => {
  const found = new Map<string, number>()
  for (const [path, source] of Object.entries(SOURCES)) {
    const rel = path.replace(/^\/src\//, '')
    if (isExempt(rel)) continue
    const calls = countCalls(source)
    if (calls > 0) found.set(rel, calls)
  }

  it('finds folds at all, so the comparison below cannot pass vacuously', () => {
    // If the scanner broke — a renamed helper, a changed source root, a regex
    // that matches nothing — every assertion in this file would agree that the
    // empty set equals the empty set. It must see the real ones first.
    expect(found.size).toBeGreaterThan(3)
    expect([...found.values()].reduce((a, b) => a + b, 0)).toBeGreaterThan(5)
  })

  it('records every file that folds a query without a decoder', () => {
    // A new `certainFromQuery` anywhere lands here. Migrate it onto
    // `certainFromShapedQuery`, or add it above with a stated reason.
    expect([...found.keys()].sort()).toEqual(AUDIT.map((s) => s.file).sort())
  })

  it('records how many folds each file makes, so a new one in an old file lands too', () => {
    // Without this, adding a fifth fold to OverviewPage.tsx would pass — the
    // file is already listed. The count is what makes the ratchet per-fold.
    const expected = Object.fromEntries(AUDIT.map((s) => [s.file, s.calls]))
    expect(Object.fromEntries([...found].sort())).toEqual(
      Object.fromEntries(Object.entries(expected).sort()),
    )
  })

  /**
   * What this block does **not** do (AAASM-5369 review).
   *
   * It reads no query function and resolves no import. These are assertions
   * about the *prose* — that a reason is long enough to be a reason, that a
   * "safe" verdict names a mechanism, that a "hazardous" one names its ticket.
   * The dispositions themselves were established by a human reading each query
   * function, and nothing here re-derives that.
   *
   * The distinction matters because this PR's own review caught the claim
   * "machine-checked disposition" being made about exactly this code. The
   * machine checks two things: the *set* of files, and the *count* per file.
   * Everything else in `AUDIT` is an author's claim, and should be read as one.
   */
  it('gives every entry a prose reason of the shape its disposition requires', () => {
    for (const site of AUDIT) {
      expect(site.reason.length).toBeGreaterThan(80)
      // A disposition of "safe" has to name what makes it safe.
      if (site.disposition !== 'hazardous') {
        expect(site.reason).toMatch(/throw|constructs|built|Map/i)
      }
      // A live defect has to name the ticket tracking it, not just say that
      // one exists. A bare "Follow-up." is the same untraceable gesture this
      // audit replaced prose with.
      //
      // Anchored to the `Follow-up:` marker, not a bare /AAASM-\d+/ (AAASM-5369
      // delta review): two of these reasons already cite an unrelated ticket in
      // their body — AAASM-5167 for the approvals comment, AAASM-5369 for the
      // sibling defect — so the loose form matched them even after the
      // follow-up was reverted to a bare "Follow-up.", and the assertion passed
      // with the exact defect it was added to catch.
      if (site.disposition === 'hazardous') {
        expect(site.reason).toMatch(/Follow-up: AAASM-\d+/)
      }
    }
  })

  /**
   * The third door, which neither half of the ratchet was watching
   * (AAASM-5369 delta review).
   *
   * The eslintrc's allowlist is not the only way to ship an undecoded fold. Two
   * lines defeat *both* halves at once:
   *
   *   // eslint-disable-next-line no-restricted-imports
   *   import { certainFromQuery as fold } from '../lib/truthfulness'
   *
   * ESLint stays silent because the directive is genuinely used, so
   * `--report-unused-disable-directives` does not fire either; and `countCalls`
   * skips `import` lines and looks for `certainFromQuery` followed by `(` or
   * `<`, so `fold(` is invisible to it. Verified: eslint exit 0 and this file
   * 18/18 green, with a live undecoded fold in the tree.
   *
   * Suppressing the rule is therefore a decision that has to be made in the
   * open, in `.eslintrc.cjs`, rather than in the file that wants the exemption.
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

  /**
   * The eslintrc allowlist and this AUDIT are one list kept in two places, and
   * the premise of the whole ratchet is that manual bookkeeping decays. So the
   * bookkeeping is checked too.
   */
  it('agrees with the eslintrc allowlist, file for file', () => {
    expect([...ESLINT_ALLOWLIST].sort()).toEqual(AUDIT.map((s) => `src/${s.file}`).sort())
  })

  it('has not quietly relabelled the two lanes AAASM-5369 migrated', () => {
    // Neither may reappear here: both now call `certainFromShapedQuery`, and a
    // regression that reverted either would show up as a new audit entry rather
    // than as a silent loss of the guarantee.
    expect(found.has('features/capability/api.ts')).toBe(false)
    expect(found.has('features/policies/policyBadge.ts')).toBe(false)
  })
})

/**
 * The export sweep AAASM-5366 built for `features/scrub/`, extended to the
 * lanes AAASM-5369 migrated.
 *
 * It does not name folds. It enumerates every `*FromQuery` a migrated module
 * exports and puts the same unreadable bodies through all of them, so a fold
 * added to one of these modules later without a decoder fails here without
 * anyone remembering to add a case for it. The audit above catches a fold that
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
