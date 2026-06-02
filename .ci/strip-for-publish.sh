#!/usr/bin/env bash
# AAASM-2340: strip held-back surface from aa-cli before `cargo workspaces publish`.
#
# WHY this exists.
# ----------------
# `aa-cli` wires `aasm run` + `aasm tools` to the `aa-devtool*` adapter
# crates. The dev-tool subsystem isn't ready to ship in v0.0.1-alpha, so
# the `aa-devtool*` crates are `publish = false`. Cargo's publish
# verification rejects every dep with a `version = "..."` literal whose
# target isn't on crates.io — including optional, feature-gated, and
# target-cfg-conditional deps (empirically verified — see PR #843
# discussion).
#
# To keep ALL of aa-cli's dev-tool source code in tree while still
# shipping a `cargo install aasm` flow on crates.io, this script removes
# the held-back surface from the working tree right before publishing,
# then `cargo workspaces publish` runs against the stripped tree. The
# script is idempotent and operates on the working tree only — never on
# committed files — so the same checkout can host both source dev (full
# surface) and a publish run (reduced surface).
#
# What it strips.
# ---------------
# Two mechanisms:
#
#   1. **Region markers** — lines between matching `strip-for-publish:begin <name>`
#      and `strip-for-publish:end <name>` comment markers (inclusive) are
#      removed from the listed files.
#   2. **Explicit file deletions** — the source files that consume the
#      stripped deps are deleted, because their `use` lines would
#      otherwise dangle and fail to compile.
#
# Usage.
# ------
#   bash .ci/strip-for-publish.sh
#
# Exits 0 on success, non-zero on any failure. Idempotent: re-running on
# an already-stripped tree is a no-op.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---- Files that carry strip-for-publish:begin / :end markers ----
MARKED_FILES=(
    "${REPO_ROOT}/aa-cli/Cargo.toml"
    "${REPO_ROOT}/aa-cli/src/commands/mod.rs"
)

# ---- Files to delete outright (they consume held-back deps) ----
DELETED_FILES=(
    "${REPO_ROOT}/aa-cli/src/commands/run.rs"
    "${REPO_ROOT}/aa-cli/src/commands/tools.rs"
    "${REPO_ROOT}/aa-cli/tests/run_command.rs"
    "${REPO_ROOT}/aa-integration-tests/tests/cli_run.rs"
)

# Strip region. Uses awk to drop lines from
# `strip-for-publish:begin <region>` through `strip-for-publish:end <region>`
# inclusive. Lines are matched anywhere on the line (not just column 0) so
# both Rust `// ...` and TOML `# ...` comment styles work.
strip_regions() {
    local file="$1"
    local region="devtool"
    local tmp
    tmp="$(mktemp)"
    awk -v r="$region" '
        BEGIN { in_region = 0 }
        index($0, "strip-for-publish:begin " r) > 0 { in_region = 1; next }
        index($0, "strip-for-publish:end " r) > 0   { in_region = 0; next }
        in_region == 0 { print }
    ' "$file" > "$tmp"
    mv "$tmp" "$file"
}

echo "AAASM-2340 strip-for-publish: scrubbing held-back surface for crates.io publish"

for f in "${MARKED_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "  ! marked file not found: $f" >&2
        exit 1
    fi
    before="$(wc -l < "$f")"
    strip_regions "$f"
    after="$(wc -l < "$f")"
    echo "  - ${f#$REPO_ROOT/}: ${before} → ${after} lines"
done

for f in "${DELETED_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        rm "$f"
        echo "  - deleted ${f#$REPO_ROOT/}"
    fi
done

# Sanity check: aa-cli must still compile without dev-tool surface.
echo ""
echo "AAASM-2340 strip-for-publish: verifying aa-cli still builds after strip"
( cd "$REPO_ROOT" && cargo check -p aa-cli ) >/dev/null
echo "  ✓ aa-cli compiles cleanly without dev-tool surface"
