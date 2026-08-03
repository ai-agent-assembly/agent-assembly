#!/usr/bin/env bash
#
# bisect-run.sh — a `git bisect run` predicate that skips unbuildable history.
#
# AAASM-5385.
#
# THE PROBLEM
# -----------
# `git bisect run <script>` scores each commit by the script's exit status:
# 0 = good, 1..124 = bad, 125 = skip, 128+ = abort. A commit that does not
# COMPILE cannot honestly answer good or bad — the test never ran. A naive
# "build && test" one-liner exits non-zero there, bisect scores it "bad", and
# the search moves its bound past the real first-bad commit. The result is a
# confident wrong answer, which is worse than no answer, because nothing in the
# output distinguishes it from a correct one.
#
# 125 is the only sound answer for such a commit, and this script exists to
# return it.
#
# USAGE
# -----
#     # Copy the script OUT of the repository first — see the warning below.
#     cp .ci/bisect-run.sh /tmp/aa-bisect-run.sh
#
#     git bisect start <bad> <good>
#     AA_BISECT_TEST='cargo test -p aa-gateway locale' \
#         git bisect run /tmp/aa-bisect-run.sh
#
# With no AA_BISECT_TEST, the predicate is "does this commit build", which is
# what you want when bisecting for the commit that broke the build itself.
#
# WHY THE SCRIPT MUST BE COPIED OUT OF THE WORKING TREE
# -----------------------------------------------------
# `git bisect` rewrites the working tree at every step. A script living at
# `.ci/bisect-run.sh` is therefore REPLACED by whatever that path held at each
# commit under test — and for every commit older than AAASM-5385 that is
# nothing at all, at which point `git bisect run` aborts with "cannot run". The
# same hazard applies to the skip list, which is why it is NOT read from the
# working tree either (see below). Copying the script to a path outside the
# repository is what makes it stable across the walk.
#
# WHY THE SKIP LIST IS READ FROM A REF, NOT FROM DISK
# ---------------------------------------------------
# `.ci/bisect-skip.txt` is read with `git show <ref>:.ci/bisect-skip.txt`, not
# `cat`. Reading it from the checked-out tree would consult the version of the
# list as it existed at the commit under test — which for the commits that most
# need skipping is an absent or shorter list, so the entries that matter would
# be invisible exactly when they are needed. Reading it from a ref yields the
# current, complete list at every step.

set -uo pipefail

SKIP_LIST_PATH=".ci/bisect-skip.txt"

BUILD_CMD=${AA_BISECT_BUILD:-"cargo check --workspace --all-targets --exclude aa-ebpf"}
TEST_CMD=${AA_BISECT_TEST:-}

EXIT_GOOD=0
EXIT_BAD=1
EXIT_SKIP=125
EXIT_ABORT=128

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "bisect-run: not inside a git repository" >&2
    exit $EXIT_ABORT
fi

# Resolve the ref the skip list is read from. `main` may not exist locally under
# that name — this repository's push remote is `remote`, not `origin`, and a
# fresh clone may have neither — so try the usual candidates and abort loudly
# rather than silently proceeding with an empty list. An empty list would make
# every unbuildable commit score "bad", which is the exact failure this script
# exists to prevent, so it must never be reached by accident.
resolve_list_ref() {
    local candidate
    if [[ -n "${AA_BISECT_LIST_REF:-}" ]]; then
        if git rev-parse --verify --quiet "${AA_BISECT_LIST_REF}:${SKIP_LIST_PATH}" >/dev/null; then
            printf '%s' "$AA_BISECT_LIST_REF"
            return 0
        fi
        return 1
    fi
    # NOT `HEAD`. During `git bisect run`, HEAD *is* the commit under test, so
    # falling back to it would read the list as it existed at that commit —
    # a different, older list at every step, which is exactly the hazard the
    # `git show <ref>:` approach exists to avoid (see the header). Aborting
    # loudly is the correct outcome when no stable ref can be found.
    for candidate in remote/main origin/main main; do
        if git rev-parse --verify --quiet "${candidate}:${SKIP_LIST_PATH}" >/dev/null; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

if ! list_ref=$(resolve_list_ref); then
    echo "bisect-run: cannot read ${SKIP_LIST_PATH} from any of" >&2
    echo "  \${AA_BISECT_LIST_REF}, remote/main, origin/main, main" >&2
    echo "Refusing to run: without the skip list every unbuildable commit would" >&2
    echo "be scored 'bad' and the bisect would return a wrong answer." >&2
    echo "Fetch the default branch, or set AA_BISECT_LIST_REF to a ref that has it." >&2
    exit $EXIT_ABORT
fi

commit=$(git rev-parse HEAD)
short=${commit:0:9}

# Match on full SHAs only. An abbreviated SHA in the list would risk a prefix
# collision and silently skip an unrelated commit.
# `matched` is tracked separately from `skip_reason` on purpose. Keying the
# decision off the reason text would make an entry that is a bare SHA with no
# reason — which passes the 40-char check above — yield an empty reason and so
# be silently ignored, building the commit instead of skipping it. That is a
# missing-data bug reported as a clean "good", the failure mode this whole
# script exists to avoid; the reason is for the human reading the output, and
# must not be load-bearing for the verdict.
matched=0
skip_reason=""
while IFS= read -r line; do
    case "$line" in
        '#'* | '') continue ;;
    esac
    entry_sha=${line%%[[:space:]]*}
    if [[ ${#entry_sha} -ne 40 ]]; then
        echo "bisect-run: malformed entry in ${SKIP_LIST_PATH} (not a 40-char SHA): ${entry_sha}" >&2
        exit $EXIT_ABORT
    fi
    if [[ "$entry_sha" == "$commit" ]]; then
        matched=1
        skip_reason=${line#"$entry_sha"}
        break
    fi
done < <(git show "${list_ref}:${SKIP_LIST_PATH}")

if [[ $matched -eq 1 ]]; then
    [[ -n "$skip_reason" ]] || skip_reason=" (no reason recorded — please add one)"
    echo "bisect-run: SKIP ${short} — known-unbuildable (${SKIP_LIST_PATH}@${list_ref})"
    echo "bisect-run: reason:${skip_reason}"
    exit $EXIT_SKIP
fi

echo "bisect-run: building ${short} — ${BUILD_CMD}"
if ! eval "$BUILD_CMD"; then
    # An unbuildable commit that is NOT on the list is still not a "bad" answer:
    # the test never ran, so the only honest verdict is skip. It is reported
    # loudly because it means the list needs an entry (or, if the commit is
    # recent, that `.ci/verify-range-builds.sh` was bypassed).
    echo "bisect-run: SKIP ${short} — does not build and is NOT in ${SKIP_LIST_PATH}." >&2
    echo "bisect-run: add it to the list (with a reason) so the next bisect is cheaper." >&2
    exit $EXIT_SKIP
fi

if [[ -z "$TEST_CMD" ]]; then
    echo "bisect-run: GOOD ${short} — builds (no AA_BISECT_TEST set)"
    exit $EXIT_GOOD
fi

echo "bisect-run: testing ${short} — ${TEST_CMD}"
if eval "$TEST_CMD"; then
    echo "bisect-run: GOOD ${short}"
    exit $EXIT_GOOD
fi

echo "bisect-run: BAD ${short}"
exit $EXIT_BAD
