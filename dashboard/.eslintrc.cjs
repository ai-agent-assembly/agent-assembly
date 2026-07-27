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
  },
}
