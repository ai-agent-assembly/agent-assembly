/**
 * Which project this invocation is in, resolved **here** and per invocation.
 *
 * `settings_scope` says which *kind* of surface a plan may write. At `project`
 * scope it does not say *whose*, and the service on the other end of the socket
 * cannot supply the missing half: it is a daemon shared by every client on the
 * host, started once, from whichever directory happened to launch it. A service
 * that read its own working directory was therefore answering a different
 * question — it wrote one caller's managed keys into an unrelated repository's
 * checked-in `.claude/settings.json`, and changed its mind on every restart
 * (AAASM-5913).
 *
 * So the project travels with the request, absolute, from the only process that
 * knows it. This mirrors `aa-cli`'s own `resolve_project_root` on purpose: the
 * rule belongs to the boundary rather than to one client, and a plugin author
 * reading either side should find the same rule.
 *
 * It is sent at every scope, not only `project`. At `user` and `managed` scope
 * the service uses it for exactly one thing: disclosing in the plan that a
 * project configuration exists nearby and will be left alone. That warning was
 * previously computed against the daemon's directory, which made it a statement
 * about a repository the user was not in.
 *
 * Naming a root is still not naming a destination. The service resolves the file
 * to write from the scope and the root together, by its own rule — a caller
 * cannot name a settings path (ADR 0030 matrix row 6).
 */
import { resolve } from 'node:path';

/** Environment variable that overrides the project root. */
export const PROJECT_ROOT_ENV = 'AA_DEVINT_PROJECT_ROOT';

/** The one scope at which the service refuses a request that names no project. */
const PROJECT_SCOPE = 'project';

/**
 * The absolute project root to send with a request at `settingsScope`.
 *
 * `env` and `cwd` are injectable so a test never has to mutate the process, the
 * same way `socketPath` in `discovery.ts` takes its environment.
 *
 * The override exists because "the project" and "the directory this process was
 * started in" coincide only for a terminal. A VS Code extension host is started
 * once for a window and may hold several workspace folders; a plugin ported from
 * this client passes the folder the user acted on here rather than inheriting
 * whatever `process.cwd()` happens to be — which would be the same mistake this
 * field exists to fix, one layer up.
 *
 * A relative override is resolved rather than passed through. The service
 * refuses a relative path, and it is right to: relative to *its* directory is
 * not relative to ours, and this is the only place the intended answer is
 * knowable.
 */
export function projectRoot(
  settingsScope: string,
  env: NodeJS.ProcessEnv = process.env,
  cwd: () => string = () => process.cwd(),
): string {
  const override = env[PROJECT_ROOT_ENV];
  if (override !== undefined && override !== '') return resolve(override);
  try {
    return cwd();
  } catch (error) {
    // A working directory that has been deleted or made unreadable. Reported
    // rather than quietly sent as "": at `project` scope the service refuses,
    // and "this project's directory could not be determined" is something the
    // user can act on where a refusal from the far side is not.
    if (settingsScope === PROJECT_SCOPE) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(
        `this project's directory could not be determined (${detail}); run from an existing ` +
          `directory, use the "user" scope, or set ${PROJECT_ROOT_ENV}`,
      );
    }
    // At `user` and `managed` scope the root is context, not a destination, so
    // what the user asked for still happens — minus the disclosure about a
    // nearby project configuration.
    return '';
  }
}
