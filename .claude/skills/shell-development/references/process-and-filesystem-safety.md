# Reference — process and filesystem safety

These mirror the non-waivable invariants in
`governance/engineering/security.md` ("Secrets — opaque-capability model"
and "Filesystem and process safety for governance tooling"), restated here
as shell-specific prohibited patterns plus their safe replacements. They
apply to every script this skill produces, not only scripts under
`governance/`.

## 1. Broad credential dumps

**Prohibited:** raw `env`, `printenv` (no argument), `set` (no argument,
which in a POSIX shell also lists every shell variable), `export -p`, or
`cat .env`/`cat .env.*`. Each of these prints every variable currently in
scope — secret and non-secret alike — to stdout, which lands in command
output, logs, and (via a subshell) command substitution captured by
something else.

**Why it matters:** a script does not need to intend to leak a secret for
this to be a leak — the output simply contains it, and anything that
captures or logs the script's stdout (CI log storage, a wrapper's
diagnostic capture, an agent's tool-result context) now contains it too.

**Do instead — presence-only checks:**

```sh
# Bad: dumps every var, secret or not
env | grep API_KEY

# Good: proves presence/non-emptiness without printing the value
[ -n "${API_KEY:-}" ] || { echo "API_KEY is not set" >&2; exit 1; }
```

For a single named variable whose value must be checked but never shown,
`[ -n "$VAR" ]`, a length count (`printf '%s' "$VAR" | wc -c`), or the
consuming client's own exit code are safe; printing `$VAR` itself is not.

## 2. `set -x` around credential-bearing commands

**Prohibited:** enabling `set -x` (or invoking `bash -x script.sh`) around
any command that constructs, passes, or consumes a credential. Xtrace
echoes the fully-expanded command line — including any secret substituted
into it — to stderr, which is exactly the "output" channel item 21 of the
global secret-handling policy forbids.

**Do instead:** scope `set -x`/`set +x` tightly around only the
non-sensitive portion of a script, or use a redacting wrapper that filters
known secret-shaped patterns before echoing a trace. If a command
genuinely needs to be traced for debugging and it touches a credential,
pass the credential through a file descriptor or stdin instead of a
literal argument so the trace never contains the value in the first place
(see item 3).

## 3. Secret values in argv or debug output

**Prohibited:** passing a secret as a literal command-line argument
(`curl -H "Authorization: Bearer $TOKEN"` is fine only until something logs
argv; `mysql -p"$PASSWORD"` is not) when a safer channel exists, or
printing a secret in any debug/verbose output path.

**Why it matters:** argv is visible to every other process on the same
host via `ps aux` / `/proc/<pid>/cmdline`, and is frequently captured
verbatim in shell history and CI step logs — a channel that is much easier
to accidentally expose than the process's own private stdin.

**Do instead:** prefer stdin, a temp env var scoped to the single
subprocess invocation, or a `--password-file`/`--data-file=-`-style flag
that reads from a file descriptor. This is the same shape as the global
`sync-neon-secret`-style pattern: pipe the value directly between two
processes so it never becomes a shell-composed string or an argument the
model (or a log line) ever sees as text.

## 4. Generic `pkill`/`killall`

**Prohibited:** `pkill <name>` or `killall <name>` where `<name>` matches
by process name/pattern rather than an exact, verified PID. On a shared
host, a CI runner, or a machine running multiple worktrees/sessions of the
same tool, a name-pattern match can and will kill an unrelated process
that happens to share the name.

**Do instead — exact PID + ownership check:**

```sh
# Bad: kills every process named "node" on the host
pkill node

# Good: find the exact PID(s) this script itself owns, verify, then kill
pid=$(cat "$PIDFILE")
if kill -0 "$pid" 2>/dev/null; then
    # optionally also verify via /proc/<pid>/cmdline or a recorded start-time
    # that this PID is really the process we started, not a reused PID
    kill "$pid"
else
    echo "no running process for PID $pid" >&2
fi
```

Record the PID when the process is started (a pidfile, or `$!` captured
immediately after backgrounding) so termination never has to guess by
name.

## 5. Ambiguous or unowned recursive delete

**Prohibited:** `rm -rf "$dir"` (or equivalent recursive delete) against a
path the script did not itself create in the current operation, without
first confirming the target's actual contents match what it expects to
find there. A wrong or stale `$dir` value (an unset variable expanding to
empty in an `rm -rf "$dir"/*`, a config default that doesn't match the
real deployment, a copy-pasted path) turns a routine cleanup into data
loss.

**Do instead — scoped deletion with explicit path and a sanity check:**

```sh
# Bad: silently deletes whatever $BUILD_DIR happens to expand to,
# including "/" if it's unset and the script isn't using set -u
rm -rf "$BUILD_DIR"/*

# Good: explicit path, existence + ownership check, then bounded delete
: "${BUILD_DIR:?BUILD_DIR must be set}"
case "$BUILD_DIR" in
    */build-output) ;;  # sanity-check the path shape before deleting
    *) echo "refusing to delete unexpected path: $BUILD_DIR" >&2; exit 1 ;;
esac
[ -d "$BUILD_DIR" ] && rm -rf "$BUILD_DIR"
```

`set -u` (see `references/safe-shell-patterns.md`) is a cheap first
defense against the empty-variable-expands-to-`/`-or-`.` class of this bug,
but is not a substitute for the explicit sanity check — `set -u` only
catches an *unset* variable, not one that's set to the wrong value.
