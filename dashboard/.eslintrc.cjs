// AAASM-5369: the modules still allowed to fold a query outcome without
// first decoding the body (six, since AAASM-5380 migrated the two approvals
// surfaces, then the Fleet and Step-5-enroll agent lists, and then the step-2
// gateway-health probe). Every one of them
// is recorded, with the disposition
// of each fold and the ticket that carries it, in
// `src/lib/truthfulness/__tests__/foldAudit.test.ts` — keep the two in step.
//
// This list and that test are the two halves of one ratchet, and neither is
// sufficient alone. The test scans source *text*, so it counts folds per file
// but an `import { certainFromQuery as fold }` or a `T.certainFromQuery`
// namespace call walks straight past it (both were demonstrated in review).
// This rule resolves imports, so aliasing and namespace access are caught for
// free — but it cannot tell one fold in a file from five. Removing either half
// re-opens a hole the other does not cover.
//
// Adding a file here is a decision to ship an undecoded fold. The alternative
// is `certainFromShapedQuery`, which cannot be called without a decoder because
// its parameter is `unknown`.
//
// This list is not the only door, and saying it was would be the overclaim this
// ticket exists to remove: an `// eslint-disable-next-line
// no-restricted-imports` above an aliased import silences this rule *and* is
// invisible to the text scan, because the directive is genuinely used (so
// `--report-unused-disable-directives` stays quiet) and the scan skips `import`
// lines. That door is closed from the other side — the audit test asserts no
// source file carries such a directive — so a suppression has to be argued for
// here, in the open, rather than in the file that wants it.
const UNDECODED_FOLD_ALLOWLIST = [
  'src/components/AppShell.tsx',
  'src/components/agentDetail/agentPosture.ts',
  'src/pages/AlertsPage.tsx',
  'src/pages/CostsPage.tsx',
  'src/pages/OverviewPage.tsx',
  'src/pages/TeamsPage.tsx',
]

const NO_UNDECODED_FOLD = {
  'no-restricted-imports': [
    'error',
    {
      patterns: [
        {
          group: ['**/lib/truthfulness', '**/lib/truthfulness/query'],
          importNames: ['certainFromQuery'],
          message:
            'Use `certainFromShapedQuery` with a decoder (see src/lib/truthfulness/shape.ts). `certainFromQuery` takes a `QueryOutcome<T>` whose `T` is an unverified wire claim, so a fold can read a field off a body that never matched the schema - that unmounted AppShell and reported an unread capability matrix as zero policy documents (AAASM-5369). If this module genuinely must fold undecoded, add it to UNDECODED_FOLD_ALLOWLIST in .eslintrc.cjs and record the disposition in src/lib/truthfulness/__tests__/foldAudit.test.ts.',
        },
      ],
    },
  ],
}

module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  // Mirrors the build-output directories `.gitignore` lists for this package,
  // rather than the subset that has happened to cause trouble. None of these
  // is reachable from the `lint` script today — it targets `src tests
  // .storybook` filtered to ts/tsx — but any of them becomes thousands of
  // errors in minified vendor code the moment someone lints a bare path, and
  // enumerating only the ones that have already bitten is how the next one
  // bites. `coverage` is the live example: `lcov-report/` ships standalone JS.
  ignorePatterns: [
    'dist',
    'storybook-static',
    'playwright-report',
    'test-results',
    'coverage',
    '.eslintrc.cjs',
  ],
  parser: '@typescript-eslint/parser',
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': [
      'warn',
      { allowConstantExport: true },
    ],
    // AAASM-5216/5245: ban `Record<...>` object-literal lookup tables so the
    // Epic AAASM-5208 conversion to `Map`/`Object.create(null)` (wire-keyed
    // lookups resolve Object.prototype otherwise, AAASM-5109/5190) doesn't
    // regress. Pure AST rule, no type-aware parser project required. Three
    // known, deliberate gaps — do not try to close these here:
    //   1. Misses write-side `= {}` accumulators (e.g. `const headers:
    //      Record<string, string> = {}`) — excluded on purpose so every
    //      legitimate empty-accumulator pattern in the codebase isn't
    //      flagged. `properties.length>0` is the guard; do not remove it.
    //   2. Will flag legitimate `Record<SomeUnion, T>` tables that could be
    //      narrowed to a union key instead of converted to Map. Intentional:
    //      it forces the author to either narrow the type or use Map, not a
    //      false positive to suppress.
    //   3. Trusts the key type annotation even though nothing enforces it at
    //      runtime — a bare `as T` cast at a fetch boundary can make a
    //      `Record<SomeUnion, X>` unsafe despite looking type-safe here.
    //      AAASM-5217 audits those bare-cast sites separately; this rule
    //      can't see across that boundary.
    'no-restricted-syntax': [
      'error',
      {
        selector:
          "VariableDeclarator[id.typeAnnotation.typeAnnotation.typeName.name='Record'] > ObjectExpression[properties.length>0]",
        message:
          'Lookup tables must be `new Map([...])`, not a Record<> object literal - object literals resolve Object.prototype for wire-supplied keys (AAASM-5109/5190).',
      },
    ],
    ...NO_UNDECODED_FOLD,
  },
  overrides: [
    {
      // The audited modules (six, after AAASM-5380). Turning the rule off per-file rather than
      // exempting a directory keeps the exemption exactly as wide as the audit:
      // a *sibling* of an allowlisted page gets no exemption from its neighbour.
      files: UNDECODED_FOLD_ALLOWLIST,
      rules: { 'no-restricted-imports': 'off' },
    },
    {
      // The vocabulary's own tests exercise `certainFromQuery` directly - that
      // is their subject, and the fold audit imports it to prove the ratchet
      // fires. Restricting them would only make the guard untestable.
      files: ['src/lib/truthfulness/**', 'src/**/*.test.ts', 'src/**/*.test.tsx'],
      rules: { 'no-restricted-imports': 'off' },
    },
  ],
}
