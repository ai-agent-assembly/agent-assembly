// Spawn helper for the AAASM-5904 dashboard E2E
// (`sensitive-data-reference-journey.spec.ts`).
//
// Invokes the long-running `e2e_fixture_main` test in `aa-integration-tests`
// (see `aa-integration-tests/tests/e2e_sensitive_data_reference_journey.rs`)
// as a child process, waits for its
// `READY <api_base_url> <proxy_addr> <canary_value>` line on stdout, and
// exposes the api-server base URL, the raw canary value, and the child
// handle so the spec can route dashboard API calls to it via `page.route()`,
// assert the canary's absence, and kill the child in `test.afterAll`. The
// fixture drives its own canary request through the real proxy before
// printing READY, so by the time this resolves the dashboard's Alerts view
// already has something to show — the spec itself sends nothing.
//
// `canaryValue` is a synthetic, run-unique fake credential ([`Canary`]'s own
// docs in the Rust harness) — safe to carry over stdout and into the browser
// spec's assertions, never a real secret.
//
// Modeled directly on `hitl-fixture.ts` (AAASM-1571); not merged with it
// because the two fixtures spawn different Rust test binaries and expose
// different READY payloads.

import { type ChildProcess, spawn } from 'node:child_process'
import { resolve } from 'node:path'

/** Workspace root (the agent-assembly Cargo workspace root) — see `hitl-fixture.ts`. */
const REPO_ROOT = resolve(process.cwd(), '..')

/** How long to wait for `READY` after spawn. Generous margin over the
 * fixture's own real work (spawn a real proxy + api-server, send one HTTPS
 * request, poll for the alert — seconds, not minutes): this budget exists
 * for `SENSITIVE_DATA_JOURNEY_BIN_PATH` being unset (local/dev runs, which
 * pay a real `cargo test` build), not for the pre-built-binary CI path. */
const READY_TIMEOUT_MS = 6 * 60 * 1000

export interface FixtureHandle {
  /** Base URL the fixture's `aa-api-server` is listening on, e.g. `http://127.0.0.1:54321`. */
  baseUrl: string
  /** The raw synthetic canary value the fixture sent through the proxy — never a real secret. */
  canaryValue: string
  /** The cargo child process; killed via `killFixture()`. */
  child: ChildProcess
}

/**
 * Spawn the fixture and wait for its
 * `READY <api_base_url> <proxy_addr> <canary_value>` line. Resolves to a
 * {@link FixtureHandle}; rejects if the fixture exits before printing READY,
 * prints a malformed READY line, or the deadline elapses.
 *
 * If `SENSITIVE_DATA_JOURNEY_BIN_PATH` is set, execs that path directly with
 * libtest's own CLI (`<bin> e2e_fixture_main --ignored --nocapture --exact`)
 * instead of going through `cargo test --test
 * e2e_sensitive_data_reference_journey e2e_fixture_main -- ...`.
 *
 * This isn't a speed optimisation over an already-fast path — it exists
 * because that `cargo test` invocation is measurably NOT fast here.
 * Independent review + direct CI investigation, AAASM-5904 (runs
 * 32840166399, 32842166884, 32844163717): the test-name-filtered `cargo
 * test` shape resolves a different unit graph than the CI job's own
 * unfiltered `--no-run` pre-build step, so it recompiles several shared
 * crates every time regardless of build-step ordering; separately, one CI
 * run spent ~327s with the fixture's `cargo test` child producing zero
 * stderr output before a single "Compiling" line appeared — genuinely
 * blocked on something inside cargo's own invocation-time behaviour, not
 * slow compilation (the compile itself, once it started, took 28s). Neither
 * is fully root-caused. Executing the already-built binary directly
 * sidesteps both: no `cargo` invocation at all means neither failure mode
 * has anything to trigger on. `ci.yml`'s pre-build step captures the exact
 * path via `--message-format=json` right after building it.
 *
 * Falls back to the `cargo test` path when the env var is unset — local/dev
 * runs, where the hash-suffixed binary path isn't known without a discovery
 * step this file doesn't perform on its own.
 */
export async function spawnFixture(): Promise<FixtureHandle> {
  const preBuiltBin = process.env.SENSITIVE_DATA_JOURNEY_BIN_PATH
  const child = preBuiltBin
    ? spawn(preBuiltBin, ['e2e_fixture_main', '--ignored', '--nocapture', '--exact'], {
        cwd: REPO_ROOT,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    : spawn(
        'cargo',
        [
          'test',
          '--test',
          'e2e_sensitive_data_reference_journey',
          'e2e_fixture_main',
          '--',
          '--ignored',
          '--nocapture',
          '--exact',
        ],
        { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] },
      )

  const { baseUrl, canaryValue } = await waitForReady(child)
  return { baseUrl, canaryValue, child }
}

/** Send SIGTERM to a previously-spawned fixture. Safe to call with `undefined`. */
export function killFixture(handle: FixtureHandle | undefined): void {
  if (!handle) return
  if (handle.child.exitCode === null) {
    handle.child.kill('SIGTERM')
  }
}

function waitForReady(child: ChildProcess): Promise<{ baseUrl: string; canaryValue: string }> {
  return new Promise((res, rej) => {
    const deadline = Date.now() + READY_TIMEOUT_MS
    let stdoutBuf = ''
    let stderrBuf = ''
    let timer: NodeJS.Timeout | undefined

    const settle = (fn: () => void) => {
      if (timer) clearTimeout(timer)
      fn()
    }

    child.stdout!.on('data', (chunk: Buffer) => {
      stdoutBuf += chunk.toString('utf8')
      // `READY <api_base_url> <proxy_addr> <canary_value>` — the proxy
      // address is printed for parity with `hitl-fixture.ts` but unused
      // here; the third token is what this spec's leak checks need.
      const m = stdoutBuf.match(/READY (\S+) (\S+) (\S+)/)
      if (m) settle(() => res({ baseUrl: m[1], canaryValue: m[3] }))
    })
    child.stderr!.on('data', (chunk: Buffer) => {
      stderrBuf += chunk.toString('utf8')
    })
    child.on('error', (err) => settle(() => rej(err)))
    child.on('exit', (code, signal) =>
      settle(() =>
        rej(new Error(`fixture exited before READY: code=${code} signal=${signal}\n--- stderr ---\n${stderrBuf}`)),
      ),
    )

    const tick = () => {
      if (Date.now() > deadline) {
        try {
          child.kill('SIGTERM')
        } catch {
          /* ignore */
        }
        settle(() =>
          rej(
            new Error(`fixture did not print READY within ${READY_TIMEOUT_MS} ms\n--- stderr ---\n${stderrBuf}`),
          ),
        )
        return
      }
      timer = setTimeout(tick, 500)
    }
    tick()
  })
}
