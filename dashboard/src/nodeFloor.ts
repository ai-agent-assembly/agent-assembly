// AAASM-6198: decide whether the host Node is below this package's declared
// floor, and say so in one sentence a reader can act on.
//
// This lives in `src/` so it is typechecked, linted and unit-tested, but its
// only caller is `vite.config.ts` — nothing in the application imports it, so it
// is not part of the bundle. The call has to happen from the config because that
// is the only code that runs in the process that starts vitest. A check in
// `src/test-setup.ts` cannot fire on a too-old Node: jsdom 30 dereferences the
// `Iterator` global at require time, which does not exist before Node 22, so the
// forks worker dies with `ReferenceError: Iterator is not defined` and the setup
// file never executes. Running from the config also covers `vite build` and
// `vite dev`, not just the test run.
//
// Deliberately pure and parameterised rather than reading `process` itself:
// `@types/node` is not a dependency of this package, and a function taking the
// two strings can be tested over every case including the ones that are awkward
// to produce by actually running an old Node.

/**
 * Returns a warning to print, or `null` when the host Node is acceptable or
 * cannot be determined.
 *
 * @param declaredRange the `engines.node` value, e.g. `">=22"`
 * @param hostVersion `process.version`, e.g. `"v20.19.6"`
 */
export function nodeFloorWarning(
  declaredRange: string | undefined,
  hostVersion: string | undefined,
): string | null {
  const minimumMajor = Number(/(\d+)/.exec(declaredRange ?? '')?.[1])
  const hostMajor = Number(/^v?(\d+)/.exec(hostVersion ?? '')?.[1])

  // Unreadable either side means silence, not a false alarm: an absent
  // `process` is some non-Node runner, and an `engines` range this cannot parse
  // is a packaging question rather than a host problem.
  if (!Number.isFinite(minimumMajor) || !Number.isFinite(hostMajor)) {
    return null
  }
  if (hostMajor >= minimumMajor) {
    return null
  }

  return (
    `[dashboard] Node ${hostVersion} is below the supported floor "${declaredRange}" ` +
    `declared in dashboard/package.json engines.node. This suite is verified on Node 22, ` +
    `24 and 26. Expect failures that are the environment rather than the product — on ` +
    `Node 20 the test run dies in jsdom with "Iterator is not defined" before any test ` +
    `executes. Use the version in dashboard/.nvmrc.`
  )
}
