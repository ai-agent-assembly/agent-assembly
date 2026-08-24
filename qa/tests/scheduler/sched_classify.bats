#!/usr/bin/env bats
# AAASM-5891: classification cannot silently drift from the file that
# actually decides (lefthook.toml), and identical concurrent pushes at the
# same commit dedupe rather than each spawning their own cargo_doc_workspace
# job — the actual incident this Story exists to fix.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

REPO_ROOT="$BATS_TEST_DIRNAME/../../.."

@test "aa-sched's push classification glob matches lefthook.toml's doc-hook glob" {
    local lefthook="$REPO_ROOT/lefthook.toml"
    [ -f "$lefthook" ]
    # The glob line is dozens of lines below the section header (a long
    # rationale comment block sits between them), so scope the search to
    # the whole [pre-push.commands.doc] section body — up to the next
    # `[section]` header or EOF — rather than a fixed line offset.
    local lefthook_glob
    lefthook_glob=$(awk '/^\[pre-push\.commands\.doc\]/{f=1;next} /^\[/{f=0} f' "$lefthook" | grep '^glob' | head -1)
    # Extract the quoted entries in order, e.g. glob = ["*.rs", "*Cargo.toml", "*Cargo.lock"]
    local patterns
    patterns=$(echo "$lefthook_glob" | grep -oE '"[^"]+"' | tr -d '"')
    local sched_patterns
    sched_patterns=$(grep -m1 '^DOC_GATE_GLOB_PATTERNS=' "$SCHED" | sed "s/^DOC_GATE_GLOB_PATTERNS='//;s/'$//")
    local sorted_lefthook sorted_sched
    sorted_lefthook=$(echo "$patterns" | sort | tr '\n' ' ')
    sorted_sched=$(echo "$sched_patterns" | tr ' ' '\n' | sort | tr '\n' ' ')
    [ "$sorted_lefthook" = "$sorted_sched" ]
}

@test "classify: a git push touching only non-doc-glob files is write_repo" {
    local repo
    repo="$(mktemp -d)"
    git -C "$repo" init -q
    git -C "$repo" commit -q --allow-empty -m init
    echo "hello" >"$repo/README.md"
    git -C "$repo" add README.md
    git -C "$repo" commit -q -m docs

    run "$SCHED" classify -- git push origin HEAD
    # No @{u}/remote configured, so classify falls back to `git ls-files`
    # scope from cwd — run from inside the repo to make the fallback
    # deterministic.
    cd "$repo" || exit 1
    run "$SCHED" classify -- git push origin HEAD
    [ "$output" = "write_repo" ]
    rm -rf "$repo"
}

@test "classify: a git push touching a .rs file is cargo_doc_workspace" {
    local repo
    repo="$(mktemp -d)"
    git -C "$repo" init -q
    git -C "$repo" commit -q --allow-empty -m init
    echo "fn main() {}" >"$repo/main.rs"
    git -C "$repo" add main.rs
    git -C "$repo" commit -q -m rust

    cd "$repo" || exit 1
    run "$SCHED" classify -- git push origin HEAD
    [ "$output" = "cargo_doc_workspace" ]
    rm -rf "$repo"
}

@test "run: a second identical push at the same HEAD dedupes (attaches, does not re-run)" {
    # Dedupe only fires for a literal `git push` invocation (see aa-sched's
    # fingerprint scoping), so this drives a REAL push at a real (local
    # bare) remote — not a stand-in fixture script. A pre-receive hook that
    # sleeps briefly keeps the winning `aa-sched run` process alive long
    # enough for the second, racing invocation to reliably observe its
    # fingerprint pointer rather than the test depending on exact timing.
    local remote repo
    remote="$(mktemp -d)"
    git -C "$remote" init -q --bare
    mkdir -p "$remote/hooks"
    cat >"$remote/hooks/pre-receive" <<'HOOK'
#!/bin/sh
sleep 2
cat >/dev/null
HOOK
    chmod +x "$remote/hooks/pre-receive"

    repo="$(mktemp -d)"
    git -C "$repo" init -q
    git -C "$repo" commit -q --allow-empty -m init
    git -C "$repo" remote add origin "$remote"
    cd "$repo" || exit 1

    sched_run_bg p1 --class cargo_doc_workspace --id push-1 --worktree "$repo" -- \
        git push origin HEAD:refs/heads/same-branch
    sched_run_bg p2 --class cargo_doc_workspace --id push-2 --worktree "$repo" -- \
        git push origin HEAD:refs/heads/same-branch

    sched_wait "$p1"
    local rc1=$?
    sched_wait "$p2"
    local rc2=$?
    [ "$rc1" -eq 0 ]
    [ "$rc2" -eq 0 ]

    # Only ONE cargo_doc_workspace job actually ran to completion; the
    # second attached to the first rather than spawning a duplicate real
    # push — matching the actual incident: the same branch pushed 3 times,
    # not three different pushes.
    [ -f "$AA_SCHED_HOME/jobs/push-1/status" ]
    [ ! -f "$AA_SCHED_HOME/jobs/push-2/status" ]
    rm -rf "$repo" "$remote"
}

@test "run: a push at a NEW HEAD does not dedupe against a prior push" {
    local repo
    repo="$(mktemp -d)"
    git -C "$repo" init -q
    git -C "$repo" commit -q --allow-empty -m init
    cd "$repo" || exit 1

    run "$SCHED" run --class lint_fast --id push-a --worktree "$repo" -- \
        "$FIXTURES/fake-progressing.sh" 1
    [ "$status" -eq 0 ]

    git -C "$repo" commit -q --allow-empty -m second

    run "$SCHED" run --class lint_fast --id push-b --worktree "$repo" -- \
        "$FIXTURES/fake-progressing.sh" 1
    [ "$status" -eq 0 ]

    [ -f "$AA_SCHED_HOME/jobs/push-a/status" ]
    [ -f "$AA_SCHED_HOME/jobs/push-b/status" ]
    rm -rf "$repo"
}
