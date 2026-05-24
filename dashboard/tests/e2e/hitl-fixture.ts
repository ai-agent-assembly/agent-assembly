// Spawn helper for the AAASM-1571 ST-P-5 dashboard E2E (`hitl-approval.spec.ts`).
//
// Invokes the long-running `e2e_fixture_main` test in `aa-integration-tests`
// (see `aa-integration-tests/tests/e2e_hitl_approval.rs`) as a child process,
// waits for its `READY <url>` line on stdout, and exposes the base URL plus
// the child handle so the spec can route dashboard API calls to it via
// `page.route()` and kill the child in `test.afterAll`.
//
// Used by `hitl-approval.spec.ts`; intentionally not registered as
// Playwright `globalSetup` so the existing 20+ MSW-mocked specs are not
// slowed down by spawning a Rust gateway they don't need.

import { type ChildProcess, spawn } from 'node:child_process'
import { resolve } from 'node:path'

/**
 * Workspace root (the agent-assembly Cargo workspace root).
 *
 * Playwright runs with `cwd` set to the dashboard package root, so the
 * workspace root is one level up. Uses `process.cwd()` (Playwright sets
 * it deterministically) to stay compatible with both CJS and ESM module
 * loading without depending on `import.meta.url`.
 */
const REPO_ROOT = resolve(process.cwd(), '..')

/** How long to wait for `READY` after spawn. Cold `cargo test` builds can be
 * very slow on CI; 4 min covers the worst case observed in practice. */
const READY_TIMEOUT_MS = 4 * 60 * 1000

export interface FixtureHandle {
  /** Base URL the fixture's gateway is listening on, e.g. `http://127.0.0.1:54321`. */
  baseUrl: string
  /** The cargo child process; killed via `killFixture()`. */
  child: ChildProcess
}

/**
 * Spawn `cargo test --test e2e_hitl_approval e2e_fixture_main` and wait for
 * its `READY <url>` line. Resolves to a {@link FixtureHandle}; rejects if
 * the fixture exits before printing READY or if the deadline elapses.
 */
export async function spawnFixture(): Promise<FixtureHandle> {
  const child = spawn(
    'cargo',
    ['test', '--test', 'e2e_hitl_approval', 'e2e_fixture_main', '--', '--ignored', '--nocapture', '--exact'],
    { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] },
  )

  const baseUrl = await waitForReady(child)
  return { baseUrl, child }
}

/** Send SIGTERM to a previously-spawned fixture. Safe to call with `undefined`. */
export function killFixture(handle: FixtureHandle | undefined): void {
  if (!handle) return
  if (handle.child.exitCode === null) {
    handle.child.kill('SIGTERM')
  }
}

function waitForReady(child: ChildProcess): Promise<string> {
  return new Promise<string>((res, rej) => {
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
      const m = stdoutBuf.match(/READY (\S+)/)
      if (m) settle(() => res(m[1]))
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
