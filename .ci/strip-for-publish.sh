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
    # AAASM-2388: gateway NATS audit consumer (async-nats + publish=false
    # aa-storage-postgres). Removed so the published gateway has no held-back deps.
    "${REPO_ROOT}/aa-gateway/Cargo.toml"
    "${REPO_ROOT}/aa-gateway/src/lib.rs"
    "${REPO_ROOT}/aa-gateway/src/main.rs"
    # AAASM-2775: aa-integration-tests forwards a feature to aa-gateway's stripped
    # audit-consumer feature. Without this strip, cargo-workspaces resolution
    # fails at publish time on the dangling feature reference (alpha-6 release).
    "${REPO_ROOT}/aa-integration-tests/Cargo.toml"
    # AAASM-5280: the DI-API lifecycle service registers the built-in dev-tool
    # adapters through `aa-devtool` (publish = false). Removed so the published
    # runtime has no held-back deps; it still binds the DI-API and simply has
    # an empty integration registry.
    "${REPO_ROOT}/aa-runtime/Cargo.toml"
    "${REPO_ROOT}/aa-runtime/src/devint/mod.rs"
    "${REPO_ROOT}/aa-runtime/src/runtime.rs"
)

# ---- Files to delete outright (they consume held-back deps) ----
DELETED_FILES=(
    "${REPO_ROOT}/aa-cli/src/commands/run.rs"
    "${REPO_ROOT}/aa-cli/src/commands/tools.rs"
    "${REPO_ROOT}/aa-cli/tests/run_command.rs"
    "${REPO_ROOT}/aa-integration-tests/tests/cli_run.rs"
    # AAASM-5309: the `aasm integrations` CLI suites. `integrations_command.rs`
    # drives the subcommand that no longer exists post-strip;
    # `integrations_claude_code.rs` additionally imports
    # `aa_runtime::devint::adapters`, which is deleted just below — it would
    # fail to compile, not merely fail to pass.
    "${REPO_ROOT}/aa-cli/tests/integrations_command.rs"
    "${REPO_ROOT}/aa-cli/tests/integrations_claude_code.rs"
    # AAASM-2388: the audit consumer module + its integration test.
    "${REPO_ROOT}/aa-gateway/src/audit_consumer.rs"
    "${REPO_ROOT}/aa-gateway/tests/audit_consumer_e2e.rs"
    # AAASM-5280: the built-in adapter bridge consumes the stripped aa-devtool dep.
    "${REPO_ROOT}/aa-runtime/src/devint/adapters.rs"
)

# Strip region. Uses awk to drop lines from any
# `strip-for-publish:begin <region>` through its matching
# `strip-for-publish:end <region>` (inclusive), regardless of region name, so a
# single file may carry several independently-named regions. Lines are matched
# anywhere on the line (not just column 0) so both Rust `// ...` and TOML
# `# ...` comment styles work.
strip_regions() {
    local file="$1"
    local tmp
    tmp="$(mktemp)"
    awk '
        BEGIN { in_region = 0 }
        index($0, "strip-for-publish:begin ") > 0 { in_region = 1; next }
        index($0, "strip-for-publish:end ") > 0   { in_region = 0; next }
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

# AAASM-2388: aa-gateway must still compile without the audit-consumer surface.
echo ""
echo "AAASM-2388 strip-for-publish: verifying aa-gateway still builds after strip"
( cd "$REPO_ROOT" && cargo check -p aa-gateway ) >/dev/null
echo "  ✓ aa-gateway compiles cleanly without audit-consumer surface"
