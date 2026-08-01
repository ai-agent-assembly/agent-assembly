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
 *   diff unreviewable. Each carries the follow-up it belongs to.
 *
 * `hazardous` is deliberately allowed to pass this test. A test that failed on
 * them would be turned off within a day, and the value here is the ratchet:
 * the *set* cannot grow silently, and nothing can move out of `hazardous`
 * without someone editing this file and saying why.
 */
import { describe, expect, it } from 'vitest'
import * as capabilityApi from '../../../features/capability/api'
import * as policyBadge from '../../../features/policies/policyBadge'
import { isKnown, type Certain, type QueryOutcome } from '..'

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
      'A non-array `resources` throws inside the generator `tallyVerdicts` consumes, at render, outside any queryFn. A truthy non-array `policies` makes `cascadeEvidenceOf` read `.length` as `undefined`, which is not `0`, so the empty-cascade guard is skipped and counting proceeds on unread data. `api/capability.ts` casts the body (`data as CapabilityMatrix`); the hook only incidentally checks `agents` via `.find`. Follow-up.',
  },
  {
    file: 'features/approvals/ApprovalsBellButton.tsx',
    calls: 1,
    disposition: 'hazardous',
    reason:
      'features/approvals/api.ts returns `data?.items ?? []`, so a body with no `items` becomes a known empty queue and the header aria-label reads "no approvals are waiting" — an affirmative all-clear from an unread body. The AAASM-5167 comment claiming "the three cases are now distinct" holds for a transport failure only. Follow-up.',
  },
  {
    file: 'features/onboarding/steps/Step2InstallSdk.tsx',
    calls: 1,
    disposition: 'hazardous',
    reason:
      'The non-2xx path is validated by `asHealthResponse`, but the 2xx path in features/onboarding/api.ts returns the body unchecked, and `buildProbeLines` calls `Object.entries(health.checks)` — a TypeError on a 200 without `checks`. It cannot emit a false "gateway reachable" (a missing `status` fails `!== "ok"`), so this is a crash rather than a fabrication. Follow-up.',
  },
  {
    file: 'features/onboarding/steps/Step5EnrollAgent.tsx',
    calls: 1,
    disposition: 'hazardous',
    reason:
      'features/onboarding/api.ts reads `data.total` / `data.items` off a cast body. A missing `total` renders an empty meter and the pane prints "the registry answered: no agents registered yet"; a non-array `items` throws in `.map` at render. Follow-up.',
  },
  {
    file: 'pages/AlertsPage.tsx',
    calls: 3,
    disposition: 'hazardous',
    reason:
      'Two of the three are safe — `alertsState` and `totalState` come through `parseAlertList` / `finiteOrNull`. The third, `rulesState`, comes from `useAlertRulesQuery`, which is a bare `as` cast over `response.json()`; `indexRulesById` then builds a Map from it and throws on a non-array. Recorded as hazardous because the file contains a live one. Follow-up.',
  },
  {
    file: 'pages/CostsPage.tsx',
    calls: 2,
    disposition: 'hazardous',
    reason:
      'Both hooks in features/teams/api.ts end in `data as CostSummary` / `data as TopologyOverview` — the module comment calls them accepted-risk casts. Every downstream read is optional-chained, so nothing throws; instead `whenEmpty: "unconfigured"` never fires (the body is non-null) and `countBlockedByBudget` returns a measured-looking `known(0)` teams blocked by budget. Follow-up.',
  },
  {
    file: 'pages/FleetPage.tsx',
    calls: 1,
    disposition: 'hazardous',
    reason:
      'features/agents/api.ts returns `data?.items ?? []`, so a body with no `items` renders the "no agents registered" empty state — an affirmative claim about the fleet from an unread body. A truthy non-array `items` throws in a sibling `.map` on the same render. Follow-up.',
  },
  {
    file: 'pages/LiveOpsPage.tsx',
    calls: 1,
    disposition: 'hazardous',
    reason:
      'Same `?? []` in features/approvals/api.ts as the bell. ApprovalPool then renders "No pending approvals / Nothing is waiting for a human decision right now" with no absence badge. The comment there frames the `?? []` as a safety property; it is the fail-open. Follow-up.',
  },
  {
    file: 'pages/OverviewPage.tsx',
    calls: 4,
    disposition: 'hazardous',
    reason:
      'Mixed. `alerts` is guarded by `parseAlertList`; `enforcement` is a Map built client-side. `approvals` inherits the `?? []` and renders a confident "0 pending approvals". `policies` is the *same* defect AAASM-5369 fixed for the nav rail — `usePoliciesQuery` checks `!data?.items` for truthiness only, so `{"items":[{},{}]}` still counts to a confident 2 here. That one is the direct sibling of this ticket and should take the same decoder. Follow-up.',
  },
  {
    file: 'pages/TeamsPage.tsx',
    calls: 2,
    disposition: 'hazardous',
    reason:
      'The topology-agents hook constructs its object but passes `nodes` through a `?? []`, so a missing `nodes` renders a confident "0 unclaimed" chip and a truthy non-array throws in `.filter`. The overview hook is a bare cast, and a missing `total_agent_count` makes the census `unaccountedFor` compute to `NaN` rather than reporting the disagreement it exists to report. Follow-up.',
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
    expect(found.size).toBeGreaterThan(5)
    expect([...found.values()].reduce((a, b) => a + b, 0)).toBeGreaterThan(10)
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

  it('gives every entry a reason that cites code, not a nearby comment', () => {
    for (const site of AUDIT) {
      expect(site.reason.length).toBeGreaterThan(80)
      // A disposition of "safe" has to name what makes it safe.
      if (site.disposition !== 'hazardous') {
        expect(site.reason).toMatch(/throw|constructs|built|Map/i)
      }
      // A live defect has to name where it is tracked.
      if (site.disposition === 'hazardous') {
        expect(site.reason).toMatch(/follow-up/i)
      }
    }
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
