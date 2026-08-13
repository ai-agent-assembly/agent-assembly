/**
 * ESLint for the DI-API reference client.
 *
 * `no-restricted-imports` is the cheap, editor-visible half of this package's
 * containment argument: a thin client that imported `node:child_process` or an
 * HTTP stack would have crossed a boundary the ticket forbids. The load-bearing
 * half is `test/guards.test.ts`, which scans the built source rather than
 * trusting a lint rule someone can disable with a comment.
 */
module.exports = {
  root: true,
  env: { node: true, es2022: true },
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
  ignorePatterns: ['dist/', 'src/generated/'],
  rules: {
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    'no-restricted-imports': [
      'error',
      {
        paths: [
          { name: 'child_process', message: 'A thin DI-API client starts no processes.' },
          { name: 'node:child_process', message: 'A thin DI-API client starts no processes.' },
          { name: 'http', message: 'The DI-API is a Unix socket; loopback TCP is ADR 0030 forbidden design 7.' },
          { name: 'node:http', message: 'The DI-API is a Unix socket; loopback TCP is ADR 0030 forbidden design 7.' },
          { name: 'https', message: 'The DI-API is a Unix socket; loopback TCP is ADR 0030 forbidden design 7.' },
          { name: 'node:https', message: 'The DI-API is a Unix socket; loopback TCP is ADR 0030 forbidden design 7.' },
          { name: 'node:dgram', message: 'A thin DI-API client opens no network sockets.' },
          { name: 'node:vm', message: 'A thin DI-API client evaluates nothing.' },
        ],
      },
    ],
  },
  overrides: [
    {
      files: ['test/**/*.ts', 'scripts/**/*.mjs'],
      rules: {
        // Tests must be able to spawn the Rust harness and read generated
        // output; the restriction is a property of the shipped client, not of
        // the thing that proves the client has it.
        'no-restricted-imports': 'off',
      },
    },
  ],
};
