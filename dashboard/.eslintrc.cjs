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
  },
}
