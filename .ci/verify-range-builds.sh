#!/usr/bin/env bash
#
# verify-range-builds.sh — build every commit a merge will introduce.
#
# AAASM-5385.
#
# WHAT THIS CLOSES
# ----------------
# CONTRIBUTING requires commits to be bisectable ("keep commits small and
# bisectable"). Nothing enforced it. Two distinct holes existed, and they need
# different arguments — conflating them produces a gate that closes neither:
#
#   1. An intermediate commit that does not build. Partial staging (`git add`
#      of one file while others stay modified) is the normal way to produce an
#      atomic commit, and it routinely records an index that was never built:
#      lefthook runs `cargo clippy` against the WORKING TREE, but `git commit`
#      records the INDEX. When they differ, the hook validates a tree that is
#      never committed. No pre-commit hook can close this without stashing, and
#      `lefthook.toml` is deliberately left alone (AAASM-5385 acceptance).
#
#   2. A merge commit that does not build even though both of its parents do.
#      `git merge` exiting 0 means "no textual conflict", which is not the same
#      claim as "the result compiles". Rename detection and independent edits to
#      disjoint regions of the same file both produce clean-but-broken merges.
#      This is a semantic conflict, and only a build can see it.
#
# The recorded instance of (2) on this repository is c596246a2100e706d20fca...,
# a local `git merge remote/main` on the AAASM-5354 branch. Both parents build;
# the merge does not (`cannot find engine in crate`, aa-policy). It reached
# `main` because the next commit repaired it, so every commit CI ever built was
# green. See `.ci/bisect-skip.txt`.
#
# WHY THE RANGE IS `HEAD^1..HEAD` ON THE MERGE REF
# ------------------------------------------------
# On a `pull_request` event, `actions/checkout` checks out `refs/pull/N/merge`
# by default — GitHub's own synthetic merge of the PR into its base. This
# repository's `ci.yml` never overrides `ref:` on any job (verified: the only
# `ref:` in `.github/workflows/` is in `docs.yml`, for a `workflow_run`), so
# existing CI already builds the merge RESULT, not the PR head. That part was
# never broken and this script does not change it.
#
# We reuse `refs/pull/N/merge` rather than constructing a merge ourselves,
# because a merge we construct is a merge nobody will ever push: GitHub decides
# the parent order and strategy that actually lands, and re-deriving it risks
# validating a different tree than the one that merges. Taking GitHub's ref as
# given, the commits the merge introduces are exactly
#
#     git rev-list --reverse HEAD^1..HEAD      # HEAD^1 = base tip
#
# which yields every commit on the PR branch not already in the base, PLUS the
# synthetic merge commit itself as the final element. One range therefore covers
# both holes above: intermediate commits and the merge result.
#
# WHY `cargo check`, NOT `clippy` OR `build`
# ------------------------------------------
# Cost is the reason this gate survives rather than gets disabled. `cargo check`
# stops after type-checking and skips codegen/linking, and is what actually
# distinguishes "this commit compiles" from "this commit does not". Lint
# cleanliness and test outcomes at intermediate commits are not what bisect
# needs — `git bisect` needs each commit to BUILD so a test can be run against
# it. The tip is separately covered by the full `build`/`clippy`/`test` jobs, so
# nothing is lost by checking intermediate commits more cheaply than the tip.
#
# `--exclude aa-ebpf` matches the `build` and `clippy` jobs: aya-build shells
# out to a nightly toolchain, and `ebpf-build` covers that crate separately.
#
# USAGE
# -----
#   .ci/verify-range-builds.sh                 # infer range from HEAD (a merge)
#   .ci/verify-range-builds.sh <base> <head>   # explicit range
#
# Exits 0 if every commit in the range builds; 1 naming the first that does not.

set -euo pipefail

CARGO_CHECK_ARGS=(check --workspace --all-targets --exclude aa-ebpf)

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [[ $# -eq 2 ]]; then
    base=$(git rev-parse --verify "$1^{commit}")
    head=$(git rev-parse --verify "$2^{commit}")
elif [[ $# -eq 0 ]]; then
    head=$(git rev-parse --verify HEAD)
    if [[ -z "$(git rev-parse --verify --quiet "${head}^2" || true)" ]]; then
        echo "error: HEAD ($head) is not a merge commit, so the base cannot be" >&2
        echo "       inferred. Pass the range explicitly: $0 <base> <head>" >&2
        echo "       In CI this means the checkout was not refs/pull/N/merge." >&2
        exit 2
    fi
    base=$(git rev-parse --verify "${head}^1")
else
    echo "usage: $0 [<base> <head>]" >&2
    exit 2
fi

# Portable to bash 3.2 (the /bin/bash macOS still ships), so the same script a
# contributor runs locally is the one CI runs. `mapfile` would restrict this to
# bash 4+ and silently diverge the two.
commits=()
commit_count=0
while IFS= read -r line; do
    commits[commit_count]=$line
    commit_count=$((commit_count + 1))
done < <(git rev-list --reverse "${base}..${head}")

if [[ $commit_count -eq 0 ]]; then
    echo "No commits in ${base:0:9}..${head:0:9} — nothing to verify."
    exit 0
fi

echo "Range ${base:0:9}..${head:0:9} introduces ${commit_count} commit(s)."
echo

# A commit is skipped only when EVERY path it touches is provably incapable of
# affecting `cargo check` — documentation, images, CI config, dashboard sources
# (the dashboard's build output is not committed; aa-cli's build.rs tolerates
# its absence). The polarity matters: default to building, and skip only on
# proof of irrelevance. A filter that instead allow-lists "Rust-looking" paths
# silently stops covering every future file type that feeds the build.
is_skippable() {
    local commit=$1 path saw_path=0

    # A merge is never skipped: a semantic conflict can appear in a merge whose
    # own diff-tree output is empty or trivial, which is hole (2) exactly.
    if [[ -n "$(git rev-parse --verify --quiet "${commit}^2" || true)" ]]; then
        return 1
    fi

    while IFS= read -r path; do
        saw_path=1
        case "$path" in
            *.md | docs/* | .github/* | dashboard/* | \
            *.png | *.jpg | *.jpeg | *.svg | *.gif | *.ico | \
            LICENSE* | CODEOWNERS | .gitignore) ;;
            *) return 1 ;;
        esac
    done < <(git diff-tree --no-commit-id --name-only -r "$commit")

    # An empty diff (an empty commit, or a merge already handled above) is not
    # proof of irrelevance, so it is built rather than skipped.
    [[ $saw_path -eq 1 ]]
}

scratch=$(mktemp -d "${TMPDIR:-/tmp}/aa-range-build.XXXXXX")
worktree="$scratch/wt"
cleanup() {
    git worktree remove --force "$worktree" >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT

# One worktree reused across every commit, with one shared CARGO_TARGET_DIR, so
# cargo reuses compiled dependencies across the loop. Without this the gate
# costs a cold build per commit and would not be affordable.
git worktree add --detach --quiet "$worktree" "${commits[0]}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$scratch/target}"

failed=""
checked=0
skipped=0

for commit in "${commits[@]}"; do
    subject=$(git log -1 --format='%s' "$commit")
    short=${commit:0:9}

    if is_skippable "$commit"; then
        echo "skip  $short  $subject"
        skipped=$((skipped + 1))
        continue
    fi

    echo "build $short  $subject"
    git -C "$worktree" checkout --detach --quiet "$commit"

    if ! cargo "${CARGO_CHECK_ARGS[@]}" --manifest-path "$worktree/Cargo.toml" 2>&1 | sed 's/^/      | /'; then
        failed=$commit
        break
    fi
    checked=$((checked + 1))
done

echo
if [[ -n "$failed" ]]; then
    echo "::error::Commit ${failed:0:9} does not build: $(git log -1 --format='%s' "$failed")"
    cat >&2 <<EOF

Commit ${failed} does not build on its own.

Every commit that lands on main must build, so that 'git bisect' can run a
test at any point in history without first having to guess which commits are
merely broken scaffolding.

To reproduce it exactly:

    git worktree add --detach /tmp/broken ${failed}
    cd /tmp/broken && cargo ${CARGO_CHECK_ARGS[*]}

If it is an ordinary commit, the usual cause is partial staging — the fix
belongs squashed into that commit (interactive rebase), not appended as a
follow-up, since a later repair leaves the broken commit in history.

If it is a MERGE commit, both parents almost certainly build and the merge is
a semantic conflict that 'git merge' could not see. Redo the merge and fix the
result in the merge commit itself.
EOF
    exit 1
fi

echo "All ${checked} build-relevant commit(s) in the range build (${skipped} skipped as non-build paths)."
