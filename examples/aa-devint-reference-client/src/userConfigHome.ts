/**
 * Which configuration home a `user`-scope invocation writes into, resolved
 * **here** and per invocation (AAASM-5957).
 *
 * Mirrors `project.ts` exactly, one scope over: the service is a daemon
 * shared by every client on the host, started once, from whichever
 * environment happened to launch it. A service that read its own
 * `CLAUDE_CONFIG_DIR`/`HOME` was answering a different question — it wrote
 * one caller's managed keys into an unrelated identity's real configuration
 * home, and changed its mind on every restart.
 *
 * So the configuration home travels with the request, absolute, from the
 * only process that knows it. This mirrors `aa-cli`'s own
 * `user_config_home_for_plan` on purpose: the rule belongs to the boundary
 * rather than to one client.
 *
 * It is sent at every scope, not only `user`. At `project` and `managed`
 * scope the service uses it for exactly one thing: disclosing in the plan
 * that a user configuration exists nearby and will be left alone.
 */
import { join, resolve } from 'node:path';

/** Environment variable that overrides the configuration home. */
export const USER_CONFIG_HOME_ENV = 'AA_DEVINT_USER_CONFIG_HOME';

/** The one scope at which the service refuses a request that names no configuration home. */
const USER_SCOPE = 'user';

/**
 * The absolute configuration home to send with a request at `settingsScope`.
 *
 * `env` is injectable so a test never has to mutate the process, the same
 * way `projectRoot` in `project.ts` takes its environment.
 *
 * Falls back to `$HOME/.claude`, matching `aa-devtool-claude-code`'s own
 * `user_config_home_from` precedence (`CLAUDE_CONFIG_DIR`, else
 * `$HOME/.claude`) so a plugin ported from this client resolves the same
 * destination the CLI would from the same environment.
 */
export function userConfigHome(settingsScope: string, env: NodeJS.ProcessEnv = process.env): string {
  const override = env[USER_CONFIG_HOME_ENV] ?? env.CLAUDE_CONFIG_DIR;
  if (override !== undefined && override !== '') return resolve(override);
  const home = env.HOME;
  if (home !== undefined && home !== '') return resolve(join(home, '.claude'));
  // Neither is set. Reported rather than quietly sent as "": at `user` scope
  // the service refuses, and "this configuration home could not be
  // determined" is something the user can act on where a refusal from the
  // far side is not.
  if (settingsScope === USER_SCOPE) {
    throw new Error(
      `this configuration home could not be determined (neither CLAUDE_CONFIG_DIR nor HOME is set); ` +
        `set one of them, use the "project" scope, or set ${USER_CONFIG_HOME_ENV}`,
    );
  }
  // At `project` and `managed` scope the home is context, not a destination,
  // so what the user asked for still happens — minus the disclosure about a
  // nearby user configuration.
  return '';
}
