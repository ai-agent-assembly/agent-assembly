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

/** How long to wait for `READY` after spawn. This fixture's cold path also
 * builds `aa-api-server` and `aasm proxy start`'s dependencies, plus sends a
 * real cross-process request — 4 min mirrors `hitl-fixture.ts`'s observed
 * CI-cold worst case. */
const READY_TIMEOUT_MS = 4 * 60 * 1000

export interface FixtureHandle {
  /** Base URL the fixture's `aa-api-server` is listening on, e.g. `http://127.0.0.1:54321`. */
  baseUrl: string
  /** The raw synthetic canary value the fixture sent through the proxy — never a real secret. */
  canaryValue: string
  /** The cargo child process; killed via `killFixture()`. */
  child: ChildProcess
}

/**
 * Spawn `cargo test --test e2e_sensitive_data_reference_journey
 * e2e_fixture_main` and wait for its
 * `READY <api_base_url> <proxy_addr> <canary_value>` line. Resolves to a
 * {@link FixtureHandle}; rejects if the fixture exits before printing READY,
 * prints a malformed READY line, or the deadline elapses.
 */
export async function spawnFixture(): Promise<FixtureHandle> {
  const child = spawn(
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
