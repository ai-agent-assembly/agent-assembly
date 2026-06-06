#!/usr/bin/env bash
# Standalone-build smoke for the shared SDK crates.
# AAASM-2559 (Epic AAASM-2552 — SDK security boundary + FFI consolidation).
#
# Usage: bash scripts/standalone-build-smoke.sh [crate ...]
#
# The thin per-language SDK shims (python-sdk, node-sdk) consume four crates
# from OUTSIDE this monorepo via a git SHA pin — the distribution mechanism
# chosen in ADR 0002 (docs/src/adr/0002-sdk-security-boundary.md). Inside the
# workspace these crates resolve through `path` deps and workspace inheritance
# (`version.workspace`, `[lints] workspace`, `dep = { workspace = true }`), none
# of which an external consumer sees directly. This script proves each crate is
# still buildable as a git-SHA-pinned dependency from a throwaway consumer that
# lives outside the workspace, catching path-coupling regressions before an SDK
# repo hits them.
#
# How it works, per crate:
#   1. Clone the repo at the current HEAD into a temp dir (committed files only —
#      a clean checkout, exactly what `cargo` fetches for a git dependency).
#   2. Generate a tiny external consumer crate (its own workspace) in a second
#      temp dir, depending on the crate via `{ git = "file://<clone>", rev = <sha> }`.
#   3. `cargo build` the consumer and assert it succeeds.
#
# The four crates and why they ship outside the workspace:
#   aa-core        wire types / traits consumed by the shims
#   aa-proto       generated protobuf/gRPC wire types
#   aa-security    advisory (non-authoritative) credential preflight
#   aa-sdk-client  UDS transport + AssemblyClient lifecycle
#
# Environment overrides:
#   CARGO                 cargo binary (default: cargo)
#   STANDALONE_SMOKE_OUT  temp working dir (default: a fresh mktemp -d, removed on exit)
#
# Exits 0 only when every crate builds standalone; non-zero otherwise.
# Requires: git, cargo, and protoc on PATH (aa-proto's build.rs invokes protoc).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO="${CARGO:-cargo}"

# Default crate set = the four shared crates the SDK shims pin externally.
# An explicit argument list overrides it (handy for debugging one crate).
if [[ "$#" -gt 0 ]]; then
    CRATES=("$@")
else
    CRATES=(aa-core aa-proto aa-security aa-sdk-client)
fi

if [[ -n "${STANDALONE_SMOKE_OUT:-}" ]]; then
    WORKDIR="${STANDALONE_SMOKE_OUT}"
    mkdir -p "${WORKDIR}"
    KEEP_WORKDIR=1
else
    WORKDIR="$(mktemp -d)"
    KEEP_WORKDIR=0
fi
# shellcheck disable=SC2329  # invoked indirectly via the EXIT trap below
cleanup() { [[ "${KEEP_WORKDIR}" -eq 0 ]] && rm -rf "${WORKDIR}"; }
trap cleanup EXIT

# Share one target dir across the per-crate consumers so common dependencies
# (aa-proto, aa-security, tokio, prost, ...) compile once instead of N times.
export CARGO_TARGET_DIR="${WORKDIR}/target"

command -v protoc >/dev/null 2>&1 || {
    echo "::error::protoc not found on PATH — aa-proto's build.rs needs it" >&2
    exit 1
}

SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD)"

# A clean clone of HEAD: cargo fetches a git dependency from committed objects
# only, so building against this clone reproduces exactly what an external
# consumer sees — uncommitted working-tree files never leak in.
CLONE="${WORKDIR}/agent-assembly-clean"
echo "AAASM-2559 standalone-build smoke"
echo "  repo:  ${REPO_ROOT}"
echo "  HEAD:  ${SHA}"
echo "  crates: ${CRATES[*]}"
echo ""
echo "==> Cloning a clean checkout of HEAD ..."
git clone --quiet --no-hardlinks "${REPO_ROOT}" "${CLONE}"
# Pin HEAD onto a named branch so cargo's `rev =` resolution always finds it,
# even when HEAD is a detached PR-merge commit on CI.
git -C "${CLONE}" checkout --quiet -B standalone-smoke-pin "${SHA}"
GIT_URL="file://${CLONE}"

failures=()
for crate in "${CRATES[@]}"; do
    echo ""
    echo "==> ${crate}: building as a git-SHA-pinned external consumer"
    consumer="${WORKDIR}/consume-${crate}"
    mkdir -p "${consumer}/src"
    cat > "${consumer}/Cargo.toml" <<EOF
[package]
name = "consume-${crate}"
version = "0.0.0"
edition = "2021"
publish = false

# Detach from any ancestor workspace: this consumer stands in for an external
# SDK repo and must resolve ${crate} purely through the git pin below.
[workspace]

[dependencies]
${crate} = { git = "${GIT_URL}", rev = "${SHA}", package = "${crate}" }
EOF
    echo "// Pulling ${crate} in as a dependency is enough to force a full build of it." \
        > "${consumer}/src/lib.rs"

    if ( cd "${consumer}" && "${CARGO}" build --quiet ); then
        echo "    ✓ ${crate} builds standalone (git pin, outside the workspace)"
    else
        echo "    ✗ ${crate} FAILED to build as a git-SHA-pinned dependency" >&2
        failures+=("${crate}")
    fi
done

echo ""
if [[ "${#failures[@]}" -eq 0 ]]; then
    echo "✓ all ${#CRATES[@]} shared crates build standalone at ${SHA}"
    exit 0
fi
echo "::error::standalone build failed for: ${failures[*]}" >&2
exit 1
