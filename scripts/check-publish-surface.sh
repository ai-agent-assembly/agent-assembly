#!/usr/bin/env bash
# AAASM-5309: published-surface coherence gate.
#
# WHY: every other release gate is mechanical — `cargo metadata` resolves,
# `cargo build --workspace` compiles, check-release-completeness.sh counts
# binaries, the version-drift check compares strings. All of them passed, on
# every rc, while the published `aasm` advertised `integrations` — a command
# family whose server (`spawn_devint` in aa-runtime) `.ci/strip-for-publish.sh`
# removes. The published CLI held the client, the published runtime held only
# the server *type*, and nothing bound the socket. A `cargo install aasm` user
# got a subcommand that autostarts a runtime, polls for a socket that never
# appears, times out, and prints a hint pointing at code that was stripped.
#
# A build cannot catch that: the stripped tree compiles perfectly. It is a
# coherence defect between two independently-stripped crates, so the check has
# to be about the *shape of the published surface*, not about compilation.
#
# WHAT IT ASSERTS
# ---------------
# On the post-strip tree, for the Developer Integration API specifically:
#
#   If no published binary binds the DI-API socket, then no command the
#   published CLI still advertises may be a client of it.
#
# Deliberately not a hardcoded list of held-back command names: the reachable
# command set is read out of the stripped `aa-cli/src/commands/mod.rs` and the
# client usage out of each surviving module's own sources, so a *new* DI-API
# command added tomorrow is covered without anyone remembering to list it. The
# implication also runs the other way — re-enable `spawn_devint` in the
# published runtime and the gate stops objecting, which is the correct answer.
#
# HOW: runs the real `.ci/strip-for-publish.sh` (not a reimplementation of it)
# over a throwaway copy of the tracked working tree, with the script's own
# cargo verification switched off. No compilation; ~1 second.
#
# Usage: scripts/check-publish-surface.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# The DI-API client path. A CLI module that names this is talking to the socket
# `spawn_devint` opens; nothing else in aa-cli has a reason to.
DEVINT_CLIENT_PATH="aa_runtime::devint"
# The runtime's DI-API bring-up. Present in the stripped tree => a published
# aa-runtime binds the socket.
DEVINT_BRINGUP="spawn_devint"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Copy the tracked working tree (not HEAD) so a developer running this locally
# sees the effect of edits they have not committed yet.
( cd "$REPO_ROOT" && git ls-files -z | tar --null -T - -cf - ) | tar -xf - -C "$WORK"

echo "publish-surface gate: stripping a throwaway copy of the tree"
STRIP_FOR_PUBLISH_VERIFY=0 bash "$WORK/.ci/strip-for-publish.sh" >/dev/null

CLI_MOD="$WORK/aa-cli/src/commands/mod.rs"
RUNTIME_RS="$WORK/aa-runtime/src/runtime.rs"

for f in "$CLI_MOD" "$RUNTIME_RS"; do
    [[ -f "$f" ]] || { echo "::error::expected file missing after strip: ${f#$WORK/}" >&2; exit 1; }
done

# Does anything in the published runtime actually bring the DI-API up? Comment
# lines are excluded so a leftover mention in prose cannot vouch for a bind.
if grep -v '^[[:space:]]*//' "$RUNTIME_RS" | grep -q "$DEVINT_BRINGUP"; then
    echo "publish-surface gate: OK"
    echo "  the published aa-runtime brings the DI-API up (${DEVINT_BRINGUP} survives the strip);"
    echo "  published CLI clients of it are therefore coherent."
    exit 0
fi

echo "  published aa-runtime does NOT bind the DI-API (${DEVINT_BRINGUP} is stripped)"

fail=0
# Command modules the published CLI still advertises, straight out of the
# stripped dispatch table.
while IFS= read -r m; do
    [[ -n "$m" ]] || continue
    src="$WORK/aa-cli/src/commands/$m.rs"
    [[ -f "$src" ]] || src="$WORK/aa-cli/src/commands/$m"
    [[ -e "$src" ]] || continue
    if grep -rq "$DEVINT_CLIENT_PATH" "$src"; then
        echo "::error::published \`aasm $m\` is a client of the Developer Integration API (${DEVINT_CLIENT_PATH}), but no published binary binds its socket — .ci/strip-for-publish.sh removes ${DEVINT_BRINGUP} from aa-runtime. A \`cargo install aasm\` user would get an advertised command that can only time out. Either wrap \`$m\` in a strip-for-publish region in aa-cli/src/commands/mod.rs, or stop stripping the runtime's DI-API bring-up (AAASM-5309)." >&2
        fail=1
    fi
done < <(sed -n 's/^pub mod \([a-z_][a-z0-9_]*\);$/\1/p' "$CLI_MOD")

if [ "$fail" -ne 0 ]; then
    echo "publish-surface gate: FAILED" >&2
    exit 1
fi

echo "publish-surface gate: OK"
echo "  no command the published aa-cli advertises depends on the unbound DI-API"
