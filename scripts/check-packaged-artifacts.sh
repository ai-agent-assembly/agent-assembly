#!/usr/bin/env bash
# AAASM-5315 / AAASM-5316: packaged-artifact gate.
#
# WHY
# ---
# `release.yml` publishes with `cargo workspaces publish --no-verify`. That flag
# is not optional: cargo's verify step unpacks each tarball and compiles it in
# isolation, and `aa-ebpf/build.rs`'s `restore_manifest_from_stage` renames
# `Cargo.toml.embedded` back during that compile, tripping cargo's "Source
# directory was modified by build.rs during cargo publish" guard and aborting
# the release (AAASM-2463, commit 72fd24ec). The rationale recorded with the
# flag — "pre-tag CI already validates the workspace builds cleanly, so the
# per-crate verify step is redundant" — is false. A workspace build never
# separates a crate from its siblings, and separation is the entire defect class
# verify exists to catch:
#
#   * AAASM-5316 — `aa-cli/.gitignore` lists `_embedded/`, cargo's default file
#     enumeration is git-aware, so every published aa-cli tarball shipped ZERO
#     dashboard files. Workspace builds never noticed: build.rs mirrors the
#     sibling `dashboard/dist/` in.
#   * AAASM-5315 — aa-gateway's `sqlx::query!` macros read the offline cache at
#     the WORKSPACE root, which is outside the package, so the published crate
#     could not compile for any consumer. Workspace builds never noticed: the
#     root cache is right there.
#
# This gate reconstructs what `--verify` would have proved, without re-entering
# the aa-ebpf failure: package every publishable crate, assert the tarball
# CONTENTS, then build the real binaries out of the unpacked tarballs.
#
# WHY NOT `cargo publish --dry-run`
# ---------------------------------
# Per-crate `--dry-run` is structurally unusable here. It resolves each crate's
# internal deps against the ALREADY-PUBLISHED release, so `aa-runtime` fails
# with `unresolved import 'aa_core::integration'` — 13 errors — purely because
# the published `aa-core` predates that module (verified: `git ls-tree
# v0.0.1-rc.6 aa-core/src/`). That is a false negative about the previous
# release, not a fact about this tree.
#
# Step 5 avoids the trap by unpacking ALL the tarballs and adding a
# `[patch.crates-io]` block that points every `aa-*` dep at its unpacked
# sibling. Every internal dep then resolves to the artifact this run just
# produced — which is precisely what a topological publish yields, and what
# `cargo publish --verify` gets wrong.
#
# WHAT IT RUNS
# ------------
#   1. Publish-staging on a throwaway copy of the tree, mirroring release.yml
#      step-for-step (aa-cli/_embedded, aa-proto/_embedded, aa-ebpf/_embedded,
#      aa-gateway/.sqlx) and then the real `.ci/strip-for-publish.sh`.
#   2. Internal-dep version-pin drift check.
#   3. `cargo package --no-verify --allow-dirty` for every publishable crate.
#   4. Required-file assertions read from `cargo package --list` — the tarball
#      manifest, never the working directory.
#   5. Build `aasm`, `aa-gateway` and `aa-proxy` from the unpacked tarballs.
#   6. Run the packaged `aasm`: `--version`, `--help`, and every top-level
#      subcommand it advertises must actually dispatch.
#
# PREREQUISITE: `dashboard/dist/` must already be built (`pnpm build` in
# `dashboard/`), exactly as release.yml builds it before staging.
#
# Usage: scripts/check-packaged-artifacts.sh
#   PACKAGED_GATE_WORKDIR=<dir>     reuse a scratch dir across runs (dev only)
#   PACKAGED_GATE_TARGET_DIR=<dir>  persist/cache the packaged build's target dir
#   PACKAGED_GATE_SKIP_BUILD=1      stop after step 4 (fast contents-only check)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail=0
err() { echo "::error::$*" >&2; fail=1; }
step() { echo ""; echo "── $* ─────────────────────────────────────────"; }

# ---------------------------------------------------------------------------
# Throwaway copy of the tracked working tree (not HEAD), so a developer sees
# the effect of edits they have not committed yet — same convention as
# scripts/check-publish-surface.sh.
# ---------------------------------------------------------------------------
if [ -n "${PACKAGED_GATE_WORKDIR:-}" ]; then
    WORK="$PACKAGED_GATE_WORKDIR"
    rm -rf "$WORK"
    mkdir -p "$WORK"
else
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
fi

# The tree copy lives in a SUBdirectory of the scratch root, so that step 5 can
# unpack the tarballs as a sibling rather than inside the workspace — cargo
# refuses to build a package that sits under a workspace it is not a member of.
TREE="$WORK/tree"
mkdir -p "$TREE"

echo "packaged-artifact gate: staging a throwaway copy of the tree in $TREE"
( cd "$REPO_ROOT" && git ls-files -z | tar --null -T - -cf - ) | tar -xf - -C "$TREE"

# ---------------------------------------------------------------------------
# 1. Publish staging — mirrors .github/workflows/release.yml's publish-crates
#    job. Keep these steps in lockstep with that workflow: a divergence here
#    means the gate stops describing what actually ships.
# ---------------------------------------------------------------------------
step "1/6 publish staging (mirrors release.yml)"

# release.yml: "Build dashboard for crates.io bundling" (pnpm build). Done by
# the caller so this gate stays a pure shell script with no Node dependency.
if [ ! -f "$REPO_ROOT/dashboard/dist/index.html" ]; then
    echo "::error::dashboard/dist/index.html not found. release.yml runs \`pnpm build\` in dashboard/ before staging; do the same before running this gate." >&2
    exit 1
fi

# release.yml: "Stage dashboard/dist into aa-cli/_embedded for crates.io tarball"
rm -rf "$TREE/aa-cli/_embedded"
mkdir -p "$TREE/aa-cli/_embedded/dashboard"
cp -r "$REPO_ROOT/dashboard/dist" "$TREE/aa-cli/_embedded/dashboard/dist"
test -f "$TREE/aa-cli/_embedded/dashboard/dist/index.html"
echo "  ✓ aa-cli/_embedded staged ($(find "$TREE/aa-cli/_embedded" -type f | wc -l | tr -d ' ') files)"

# release.yml: "Populate aa-proto _embedded/proto/ mirror via build.rs"
( cd "$TREE" && cargo check -p aa-proto ) >/dev/null 2>&1
test -f "$TREE/aa-proto/_embedded/proto/common.proto"
echo "  ✓ aa-proto/_embedded staged ($(find "$TREE/aa-proto/_embedded" -type f | wc -l | tr -d ' ') files)"

# release.yml: "Stage aa-ebpf/_embedded/aa-ebpf-probes/ for crates.io publish".
# `perl -i` rather than release.yml's `sed -i` only because this script also has
# to run on a developer's macOS box, where BSD sed's -i takes a mandatory arg.
rm -rf "$TREE/aa-ebpf/_embedded"
mkdir -p "$TREE/aa-ebpf/_embedded"
cp -r "$TREE/aa-ebpf-probes" "$TREE/aa-ebpf/_embedded/aa-ebpf-probes"
rm -rf "$TREE/aa-ebpf/_embedded/aa-ebpf-probes/target"
perl -i -pe 's|aa-ebpf-common = \{ path = "\.\./aa-ebpf-common" \}|aa-ebpf-common = "0.0.1-alpha.3"|' \
    "$TREE/aa-ebpf/_embedded/aa-ebpf-probes/Cargo.toml"
grep -q 'aa-ebpf-common = "0.0.1-alpha.3"' "$TREE/aa-ebpf/_embedded/aa-ebpf-probes/Cargo.toml" \
    || { echo "::error::path-dep rewrite produced unexpected result"; exit 1; }
mv "$TREE/aa-ebpf/_embedded/aa-ebpf-probes/Cargo.toml" \
   "$TREE/aa-ebpf/_embedded/aa-ebpf-probes/Cargo.toml.embedded"
echo "  ✓ aa-ebpf/_embedded staged ($(find "$TREE/aa-ebpf/_embedded" -type f | wc -l | tr -d ' ') files)"

# release.yml: "Stage .sqlx offline query cache into aa-gateway" (AAASM-5315)
rm -rf "$TREE/aa-gateway/.sqlx"
cp -r "$TREE/.sqlx" "$TREE/aa-gateway/.sqlx"
echo "  ✓ aa-gateway/.sqlx staged ($(find "$TREE/aa-gateway/.sqlx" -type f | wc -l | tr -d ' ') files)"

# release.yml: "Strip held-back surface from aa-cli for crates.io publish".
# VERIFY=0 skips the script's own `cargo check`s; step 5 below compiles far more
# than they do, out of the tarballs rather than out of the workspace.
STRIP_FOR_PUBLISH_VERIFY=0 bash "$TREE/.ci/strip-for-publish.sh" >/dev/null
echo "  ✓ held-back surface stripped"

# ---------------------------------------------------------------------------
# 2. Version-pin drift. `[patch.crates-io]` in step 5 only takes effect when the
#    patched path's version satisfies the dependency requirement; a stale pin
#    would silently fall through to crates.io and "prove" the wrong artifact
#    builds. Assert the pins first so step 5's result means what it claims.
# ---------------------------------------------------------------------------
step "2/6 internal dependency version-pin drift"

WS_VERSION="$( cd "$TREE" && cargo metadata --no-deps --format-version=1 \
    | jq -r '.packages[] | select(.name == "aa-core") | .version' )"
echo "  workspace version: $WS_VERSION"

PUBLISHABLE="$( cd "$TREE" && cargo metadata --no-deps --format-version=1 \
    | jq -r '.packages[] | select(.publish != []) | .name' | sort )"

while IFS= read -r pkg; do
    [ -n "$pkg" ] || continue
    while IFS=$'\t' read -r dep req; do
        [ -n "$dep" ] || continue
        if [ "$req" != "^$WS_VERSION" ] && [ "$req" != "$WS_VERSION" ] && [ "$req" != "=$WS_VERSION" ]; then
            err "$pkg pins internal dep '$dep' at '$req', but the workspace publishes $WS_VERSION. A published crate whose sibling pin lags resolves against the PREVIOUS release, not this one."
        fi
    done < <( cd "$TREE" && cargo metadata --no-deps --format-version=1 \
        | jq -r --arg p "$pkg" '.packages[] | select(.name == $p) | .dependencies[]
                 | select(.name | startswith("aa-")) | select(.kind == null)
                 | [.name, .req] | @tsv' )
done <<EOF
$PUBLISHABLE
EOF
[ "$fail" -eq 0 ] && echo "  ✓ every internal aa-* pin matches the workspace version"

# ---------------------------------------------------------------------------
# 3. Package every publishable crate.
# ---------------------------------------------------------------------------
step "3/6 cargo package (--no-verify, see header for why verify cannot run)"

while IFS= read -r pkg; do
    [ -n "$pkg" ] || continue
    ( cd "$TREE" && cargo package -p "$pkg" --no-verify --allow-dirty ) >/dev/null 2>&1 \
        || { err "cargo package -p $pkg failed"; continue; }
    echo "  ✓ packaged $pkg"
done <<EOF
$PUBLISHABLE
EOF
[ "$fail" -eq 0 ] || { echo "packaged-artifact gate: FAILED (packaging)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 4. Required tarball contents. Read from `cargo package --list` — the tarball
#    manifest — so a file that exists on disk but is filtered out by cargo's
#    git-aware enumeration (the AAASM-5315/5316 shape exactly) still fails.
#
#    Format: <package> <literal-path-or-glob>. A glob entry must match at least
#    one listed path.
# ---------------------------------------------------------------------------
step "4/6 required files present in the tarball manifest"

REQUIRED_FILES="
aa-cli _embedded/dashboard/dist/index.html
aa-cli _embedded/dashboard/dist/assets/*
aa-proto _embedded/proto/common.proto
aa-proto _embedded/proto/*.proto
aa-ebpf _embedded/aa-ebpf-probes/Cargo.toml.embedded
aa-ebpf _embedded/aa-ebpf-probes/src/*
aa-gateway .sqlx/query-*.json
aa-gateway migrations/*
"

listing_of() { ( cd "$TREE" && cargo package -p "$1" --list --allow-dirty 2>/dev/null ); }

prev_pkg=""
listing=""
while read -r pkg pattern; do
    [ -n "$pkg" ] || continue
    if [ "$pkg" != "$prev_pkg" ]; then
        listing="$(listing_of "$pkg")"
        prev_pkg="$pkg"
    fi
    matched=0
    while IFS= read -r entry; do
        # shellcheck disable=SC2254  # $pattern is a deliberate glob
        case "$entry" in
            $pattern) matched=1; break ;;
        esac
    done <<EOF
$listing
EOF
    if [ "$matched" -eq 1 ]; then
        echo "  ✓ $pkg: $pattern"
    else
        err "$pkg tarball does not contain '$pattern'. \`cargo package --list\` is the authority here — the file may well exist in the working tree and still be dropped, which is how AAASM-5315 and AAASM-5316 shipped. Check the crate's \`include\` in $pkg/Cargo.toml and the staging step in .github/workflows/release.yml."
    fi
done <<EOF
$REQUIRED_FILES
EOF
[ "$fail" -eq 0 ] || { echo "packaged-artifact gate: FAILED (tarball contents)" >&2; exit 1; }

if [ "${PACKAGED_GATE_SKIP_BUILD:-0}" = "1" ]; then
    echo ""
    echo "packaged-artifact gate: PACKAGED_GATE_SKIP_BUILD=1 — stopping after contents checks"
    exit 0
fi

# ---------------------------------------------------------------------------
# 5. Build the release binaries out of the unpacked tarballs.
# ---------------------------------------------------------------------------
step "5/6 build aasm + aa-gateway + aa-proxy from the unpacked tarballs"

UNPACK="$WORK/unpacked"
mkdir -p "$UNPACK"
for crate in "$TREE"/target/package/*.crate; do
    tar -xzf "$crate" -C "$UNPACK"
done
echo "  unpacked $(find "$UNPACK" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ') crates into $UNPACK"

TOP="$UNPACK/aa-cli-$WS_VERSION"
[ -d "$TOP" ] || { echo "::error::expected unpacked $TOP" >&2; exit 1; }

# Point every internal dep at the sibling that was just unpacked. Without this
# they resolve to the PREVIOUS crates.io release and the build tests the wrong
# artifact (see the header's dry-run note).
{
    echo ""
    echo "# Injected by scripts/check-packaged-artifacts.sh — resolve every internal"
    echo "# dep to the tarball produced by this run, not the previous release."
    echo "[patch.crates-io]"
    for d in "$UNPACK"/aa-*/; do
        name="$(basename "$d")"
        name="${name%-"$WS_VERSION"}"
        [ "$name" = "aa-cli" ] && continue
        echo "$name = { path = \"../$(basename "$d")\" }"
    done
} >> "$TOP/Cargo.toml"

# Kept out of $TOP so it survives PACKAGED_GATE_WORKDIR being recreated and so
# CI can cache it: the third-party half of this build is identical run to run.
PACKAGED_TARGET_DIR="${PACKAGED_GATE_TARGET_DIR:-$WORK/packaged-target}"

build_from_tarball() {
    local desc="$1"; shift
    echo "  building $desc ..."
    if ! ( cd "$TOP" && CARGO_TARGET_DIR="$PACKAGED_TARGET_DIR" cargo build "$@" ) 2> "$WORK/build-$desc.log"; then
        echo "  ✗ $desc FAILED — last 40 lines:" >&2
        tail -40 "$WORK/build-$desc.log" >&2
        err "the packaged artifact does not build: $desc. The workspace build passing proves nothing about this — that is the whole point of the gate."
        return 1
    fi
    echo "  ✓ $desc"
}

build_from_tarball aasm --bin aasm
build_from_tarball aa-gateway -p aa-gateway --bins
build_from_tarball aa-proxy -p aa-proxy --bins
[ "$fail" -eq 0 ] || { echo "packaged-artifact gate: FAILED (packaged build)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 6. Run the packaged binary. check-publish-surface.sh approximates this by
#    reading the stripped dispatch table as text; this asserts it against the
#    artifact a `cargo install aasm` user actually receives.
# ---------------------------------------------------------------------------
step "6/6 run the packaged aasm"

AASM="$PACKAGED_TARGET_DIR/debug/aasm"
[ -x "$AASM" ] || { echo "::error::packaged aasm binary not at $AASM" >&2; exit 1; }

version_out="$("$AASM" --version 2>&1)" \
    || err "packaged \`aasm --version\` exited non-zero: $version_out"
echo "  aasm --version → $version_out"
case "$version_out" in
    *"$WS_VERSION"*) ;;
    *) err "packaged \`aasm --version\` reports '$version_out', which does not carry the published version $WS_VERSION." ;;
esac

help_out="$("$AASM" --help 2>&1)" || err "packaged \`aasm --help\` exited non-zero"

# Top-level subcommands the packaged binary ADVERTISES, straight out of its own
# help. Not a hardcoded list: a command added tomorrow is covered.
advertised="$(printf '%s\n' "$help_out" \
    | awk '/^Commands:/{c=1;next} c && /^[A-Za-z]/{exit} c && NF {print $1}' \
    | grep -v '^help$' || true)"

[ -n "$advertised" ] || err "packaged \`aasm --help\` advertises no subcommands at all"
echo "  advertised: $(printf '%s' "$advertised" | tr '\n' ' ')"

while IFS= read -r cmd; do
    [ -n "$cmd" ] || continue
    if out="$("$AASM" "$cmd" --help 2>&1)"; then
        printf '  ✓ aasm %s\n' "$cmd"
    else
        err "packaged \`aasm $cmd\` is advertised by --help but does not dispatch: $(printf '%s' "$out" | head -3 | tr '\n' ' ')"
    fi
done <<EOF
$advertised
EOF

echo ""
if [ "$fail" -ne 0 ]; then
    echo "packaged-artifact gate: FAILED" >&2
    exit 1
fi
echo "packaged-artifact gate: OK"
echo "  every publishable crate packages, carries its required files, builds from"
echo "  its own tarball, and the packaged aasm dispatches every command it advertises."
