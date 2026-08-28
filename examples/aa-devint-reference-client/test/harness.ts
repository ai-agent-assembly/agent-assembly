/**
 * Spawns the real DI-API server for the contract suite.
 *
 * `examples/aa-devint-reference-client/harness` is `aa_runtime::devint`'s actual
 * `DevIntServer` — real codec, real token store, real scope check, real
 * negotiation — behind a stand-in lifecycle. Every assertion in `test/contract`
 * therefore describes the boundary as shipped. A mock would only prove that the
 * mock was written to agree with the test.
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { TargetOptions } from '../src/client.js';

const pkgRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const repoRoot = dirname(dirname(pkgRoot));
const BINARY = join(repoRoot, 'target', 'debug', 'aa-devint-harness');

/** The fixture enrolments the harness issues, one per boundary under test. */
/**
 * A target that names no project.
 *
 * The harness's fake lifecycle installs host-wide, so there is no project for a
 * caller's directory to disagree with. A test about *which* project is answered
 * builds its own target rather than widening this one — a shared constant that
 * quietly acquired a path would make every test here assert about that path.
 *
 * `userConfigHome` (AAASM-5957) is a fixed synthetic path rather than `''`:
 * an unstated scope is treated as possibly user-scoped by the server's own
 * mandatory-configuration-home check (the same reasoning that makes an
 * unstated scope possibly project-scoped for `refuse_project_scope_below_v6`
 * on the client side), so a real, existing-parent path is required here too.
 * Only the *parent* of the path has to exist (mirroring `~/.claude` not
 * existing before a first install), so this is `os.tmpdir()` itself joined
 * with a leaf that need not — `os.tmpdir()` is always a real directory.
 */
export const HOST_WIDE: TargetOptions = {
  settingsScope: '',
  projectRoot: '',
  userConfigHome: join(tmpdir(), '.claude'),
};

export interface HarnessTokens {
  /** Every verb, every tool. What the operator CLI holds. */
  readonly full: string;
  /** Every verb, `claude-code` only. What a per-tool integration client gets. */
  readonly claudeOnly: string;
  /** `list_tools`, `status`, `scoped_events`, `verify` — no mutation. */
  readonly readOnly: string;
  /** `status` on `claude-code` and nothing else. */
  readonly statusOnly: string;
  /** Live record, past its absolute expiry. */
  readonly expired: string;
}

/** A running DI-API server. */
export interface Harness {
  readonly socket: string;
  readonly tokens: HarnessTokens;
  /** The secret the poisoned plan fixture carries. Must never reach a client. */
  readonly leakSentinel: string;
  /** The secret behind the redaction label in the event fixture. */
  readonly eventSentinel: string;
  stop(): Promise<void>;
}

interface Ready {
  socket: string;
  tokens: HarnessTokens;
  leakSentinel: string;
  eventSentinel: string;
}

/** Start a server on a fresh temporary socket. */
export async function startHarness(socketPath: string): Promise<Harness> {
  if (!existsSync(BINARY)) {
    throw new Error(
      `${BINARY} is missing. Build it first:\n  cargo build -p aa-devint-harness\n` +
        'The contract suite runs against the real DI-API server, not a mock.',
    );
  }

  const child: ChildProcessWithoutNullStreams = spawn(BINARY, [socketPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const ready = await new Promise<Ready>((resolve, reject) => {
    let out = '';
    let err = '';
    const timer = setTimeout(() => reject(new Error(`harness did not become ready: ${err}`)), 20_000);
    child.stdout.on('data', (chunk: Buffer) => {
      out += chunk.toString();
      const newline = out.indexOf('\n');
      if (newline === -1) return;
      clearTimeout(timer);
      resolve(JSON.parse(out.slice(0, newline)) as Ready);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      err += chunk.toString();
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`harness exited with ${code}: ${err}`));
    });
  });

  return {
    socket: ready.socket,
    tokens: ready.tokens,
    leakSentinel: ready.leakSentinel,
    eventSentinel: ready.eventSentinel,
    async stop(): Promise<void> {
      // Closing stdin is the documented shutdown signal, so a suite that dies
      // cannot leave a socket behind.
      child.stdin.end();
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 3_000);
        child.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    },
  };
}
