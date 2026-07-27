module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  // `storybook-static` is build output, like `dist`. Without it the lint
  // result depends on whether anyone has run `build-storybook` — a clean
  // checkout passes and a developer's tree fails on minified bundles.
  ignorePatterns: ['dist', 'storybook-static', '.eslintrc.cjs'],
  parser: '@typescript-eslint/parser',
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': [
      'warn',
      { allowConstantExport: true },
    ],
  },
}
