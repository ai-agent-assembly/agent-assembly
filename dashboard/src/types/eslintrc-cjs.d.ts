/**
 * Types for importing `.eslintrc.cjs` from a test (AAASM-5369).
 *
 * `src/lib/truthfulness/__tests__/foldAudit.test.ts` compares the ESLint
 * undecoded-fold allowlist against its own `AUDIT` list, because the two are
 * one list kept in two places and the premise of that ratchet is that manual
 * bookkeeping decays. Reading the config object is what makes it a comparison
 * of the two lists rather than a comparison of the test to a copy of itself.
 *
 * Only the shape that comparison reads is declared. The file is CommonJS and
 * the package has no `allowJs`, so without this the import is an implicit
 * `any` and `noImplicitAny` rejects it — declaring the two fields is more
 * honest than widening the compiler settings for one import.
 */
declare module '*.eslintrc.cjs' {
  interface EslintOverride {
    readonly files: string[]
    readonly rules?: { readonly [ruleName: string]: unknown }
  }
  const config: { readonly overrides?: EslintOverride[] }
  export default config
}
