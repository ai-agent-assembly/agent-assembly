/**
 * Where the runtime's DI-API socket is, and whether anything is listening.
 *
 * Mirrors `aa-runtime/src/devint/socket.rs`: `$AA_DEVINT_SOCKET`, else
 * `$HOME/.aa/run/devint.sock`. The path is *resolved*, never guessed at, and
 * never widened — there is no `/tmp` fallback and no loopback TCP alternative
 * (ADR 0030 forbidden design 7).
 *
 * The absence of the socket means **the runtime is not running**. That is a
 * bootstrap prompt, not an error to retry in a loop: the thin client is the
 * only layer that exists when the runtime does not, so a silent retry shows a
 * user a spinner in place of the one instruction that would fix it.
 */
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

/** Environment variable that overrides the socket path. */
export const SOCKET_PATH_ENV = 'AA_DEVINT_SOCKET';

/** Directory under `$HOME` that holds runtime sockets. */
const RUN_DIR = '.aa/run';

/** The socket file name inside {@link RUN_DIR}. */
const SOCKET_FILE = 'devint.sock';

/** Whether the runtime appears to be listening. */
export type Discovery =
  | { readonly kind: 'present'; readonly path: string }
  | { readonly kind: 'runtime-not-running'; readonly path: string };

/**
 * Resolve the socket path from the environment, falling back to the
 * convention. `env` is injectable so a test never has to mutate the process.
 */
export function socketPath(env: NodeJS.ProcessEnv = process.env): string {
  const override = env[SOCKET_PATH_ENV];
  if (override !== undefined && override !== '') return override;
  return join(env['HOME'] ?? homedir(), RUN_DIR, SOCKET_FILE);
}

/** Probe for a listening runtime without connecting to it. */
export function discover(env: NodeJS.ProcessEnv = process.env): Discovery {
  const path = socketPath(env);
  return existsSync(path) ? { kind: 'present', path } : { kind: 'runtime-not-running', path };
}
