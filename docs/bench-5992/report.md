# AAASM-5992 — Maximum-Throughput Rust Development Profile: Benchmark Report

Status: IN PROGRESS (append-only working doc; finalized at Spike close)
Parent: AAASM-5991. Spike: AAASM-5992.

## 0. Methodology / contamination controls

- **Base**: `remote/main` (org repo `AI-agent-assembly/agent-assembly`) @ `fdac70a790b34973cb804a5df2668f66f2c91afa`, fetched 2026-08-27. `origin` (personal fork) is NOT the base — do not confuse with it.
- **Isolation**: dedicated worktree `agent-assembly-AAASM-5992-bench` on branch `bench/AAASM-5992/spike/throughput_profile`, so no active ticket worktree is touched.
- **`~/.cargo/config.toml` global override** (`target-dir = ~/.cargo/shared-target`) is NOT used for any timed run — every benchmark sets `CARGO_TARGET_DIR` explicitly to a campaign-owned lane dir under `~/Bryant-Developments/AI-agent-assembly/bench-5992-target/`, so results are never contaminated by other worktrees' concurrent activity against the shared tree. Global config file itself was not edited (confirmed unchanged throughout).
- **Foreign build activity check**: `pgrep -fl 'cargo|rustc|nextest'` run before the baseline run — no live cargo/rustc/nextest process found (one false-positive path match against a built binary named `.../cargo-target-5866/debug/aa-proxy`, not a running build). Machine: 16 logical CPU, 128 GiB RAM, `/System/Volumes/Data` at 417 GiB free / 78% capacity at campaign start.
- **RTK hook**: `~/.claude/settings.json` wires `rtk hook claude` as a `PreToolUse` gate on all Bash calls. Empirically, `cargo --version` returned unmodified stdout with no rtk banner/rewrite — RTK's documented rewrite targets (`RTK.md`) are dev-workflow meta-commands (git/gh/find-type), not `cargo`/`rustc`/`nextest`/`hyperfine`. Treated as non-contaminating for wall-clock; not independently verified against RTK source.
- **Repetitions**: single-sample cold/full-workspace builds are treated as expensive (§6 of the ticket) — reported with explicit N=1 caveat, not averaged. Cheap targeted operations (check/targeted test) are repeated ≥3× where the harness allows, median reported.
- **Historical evidence reuse**: AAASM-2551/5909/5910/5911/5981 evidence classified in §1 below; DIRECTLY_REUSABLE items are NOT re-run.

## 1. Historical evidence classification

(Full detail from sub-agent research — see conversation; summarized here.)

| Ticket | Status | Key evidence | Classification |
|---|---|---|---|
| AAASM-2551 | Done | Release/dist profile split (~2x warm relink), dev/test profile+linker gating (~2.3x warm rebuild, nextest 265/265) | DIRECTLY_REUSABLE (already merged & live in current Cargo.toml — verified in §2) |
| AAASM-2551 (linker activation) | — | Linker shipped opt-in only, not active locally | REVALIDATION_NEEDED → resolved in §2: CI now runs mold on Linux; macOS has no viable third-party alternative to Apple's default `ld` (see §3) |
| AAASM-5909 | In Progress | 1h40m nextest hang = dyld/syspolicyd first-launch validation stall, NOT a Cargo lock (proven via stack sample); separate disk-exhaustion incident (229MiB free / 100%) when per-worktree isolation had no shared target-dir | DIRECTLY_REUSABLE (root cause proof); NOT_COMPARABLE (absolute disk sizes tied to a since-changed worktree count) |
| AAASM-5910 | Done | `-p aa-cli` unrestricted = 34 nextest targets vs 1 with `--lib`/`--test <name>`; shared `debug/.cargo-lock` is one exclusive lock for the whole debug tree (confirmed via `lsof`); sccache design proposed but deferred, concurrency benchmark never run | DIRECTLY_REUSABLE (nextest targeting, lock mechanism); REVALIDATION_NEEDED (sccache — this spike executes it, see §5) |
| AAASM-5911 | Done | Nextest targeting convention shipped (PR #2201), documented in CONTRIBUTING.md / `~/CLAUDE.md` | DIRECTLY_REUSABLE — not re-run |
| AAASM-5981 | To Do | Bounded per-lane target lifecycle design (unimplemented) | DIRECTLY_REUSABLE as design input to §6 (target-dir architecture) — this spike does not implement it |

## 2. Codebase-first baseline audit (capability/status matrix)

See sub-agent audit — condensed:

| Optimization | Current state | Already implemented? |
|---|---|---|
| Dev debuginfo | `debug = "line-tables-only"` workspace-wide (Cargo.toml:186) | YES |
| Dep opt-level (dev) | `[profile.dev.package."*"]` opt-level=1, debug=false (Cargo.toml:188-198) | YES |
| Incremental | Cargo default locally; `CARGO_INCREMENTAL=0` pinned in CI only (ci.yml:230) | YES (CI); local untouched by design |
| Codegen-units | release=16, dist=1+LTO; dev=default(256) | YES (release/dist); dev not tuned |
| Split-debuginfo | Not configured anywhere | NO — candidate |
| Linker | CI: mold on Linux (ci.yml, multiple jobs); local `.cargo/config.toml` has it commented out/opt-in; macOS uses Apple's default linker (no override) | PARTIAL |
| sccache | Zero references in repo | NO — evaluated in §5 |
| target-dir | Machine-global shared dir (`~/.cargo/config.toml`, not repo-tracked); documented tradeoff | YES (machine-level, out of repo scope) |
| nextest targeting | Documented convention (AAASM-5911), not config-enforced | YES (convention) |
| CI cargo cache | `Swatinem/rust-cache@<pinned-sha>` on every Rust job | YES |

Workspace: 30 members, 898 resolved Cargo.lock packages, 61 `[workspace.dependencies]` entries, 0 proc-macro crates, 5 build.rs files (none proc-macro, all I/O/codegen embedding). `cargo tree -d`: 79 crate names with >1 version, mostly transitive; a handful of workspace-pinned crates (hmac, sha2, thiserror, tokio-tungstenite, toml) still split due to third-party deps not respecting the workspace pin.

## 3. Ecosystem research (condensed — see conversation for full table + sources)

| Tool | Verdict |
|---|---|
| Cargo native profile/config | REUSE_DIRECTLY — already the mechanism in use |
| sccache v0.17.0 | INTEGRATE_OR_WRAP — cannot cache incrementally-compiled workspace members; only helps non-incremental/dependency builds |
| cargo-nextest v0.9.143 (repo pinned: 0.9.133) | REUSE_DIRECTLY — already adopted |
| rustc_codegen_cranelift | TOO_IMMATURE — nightly-only, panic=abort forced on macOS, no stabilization timeline |
| macOS linker | NOT_APPLICABLE for lld (unsupported on macOS targets); Apple's new default `ld` (post-ld_prime) already is the fast option, zero config; zld unmaintained — GAP_REMAINS for any third-party alternative |
| Linux lld/mold | REUSE_DIRECTLY (lld, now stable-default) / INTEGRATE_OR_WRAP (mold, already adopted in this repo's CI) |
| cargo-wizard | BORROW_PATTERN — template logic worth mining, not a dependency |
| cargo-accelerate | NOT_APPLICABLE — tool does not exist |
| wild linker | TOO_IMMATURE — Linux-only, no incremental linking yet |

## 4. Benchmark runs (raw data)

Harness: existing repo harness `scripts/build-baseline.sh` (AAASM-2557), reused rather than reinvented. Run against `remote/main`@`fdac70a7`, isolated `CARGO_TARGET_DIR=.../bench-5992-target/lane1` (never the shared `~/.cargo/shared-target`), N=1 (expensive, single-lane, no foreign build activity concurrent — see §0).

| Measurement | Wall-clock | Notes |
|---|---|---|
| Cold build (`cargo build --workspace --exclude aa-ebpf --timings`) | **139s** | fresh isolated target-dir, registry/git already warm (not a from-scratch network fetch) |
| Warm rebuild (touch `aa-cli/src/main.rs`, `cargo build --workspace`) | **6s** | confirms AAASM-2551's dev-profile tuning (line-tables-only debuginfo, dep opt-level=1) is live and effective — this is the number that profile was designed to protect |
| Test-binary compile (`cargo nextest run --workspace --exclude aa-ebpf --no-run`) | **584s total**, of which **157s** was `cargo` compiling missing test targets (per `nextest-build.log`'s own "Finished ... in 2m 37s") and **~427s** was nextest's post-compile `--list`/`--list --ignored` discovery pass | **This is the load-bearing finding of the whole run.** See below. |
| `cargo tree -d` | 44 packages with >1 resolved version, 128 distinct duplicate (name,version) units | mostly transitive; workspace-pinned crates (hmac/sha2/thiserror/tokio-tungstenite/toml) still split because third-party deps don't respect the workspace pin (matches audit in §2) |
| Peak disk for this single isolated lane | **29 GiB** (`du -sh lane1`) after cold build + full test-binary compile | machine free space 417→373 GiB over the whole campaign (44 GiB, includes sccache experiments below) |

### 4.1 Live reproduction of the AAASM-5909/5910 dyld first-launch-validation stall

During the `--no-run` step, `ps` captured **32 concurrently-spawned, freshly-linked test binaries**, each invoked twice by nextest (`--list --format terse` and `--list --format terse --ignored`), all sitting in low-CPU sleep (`STAT SN`, `%CPU 0.0`) rather than doing real work — e.g. `edge_repo_test-159d7bd0eb74026a --list --format terse`. This is the exact mechanism AAASM-5909/5910 diagnosed via `sample`/stack-trace on a *contended, multi-worktree* machine. **This run reproduces it on a single isolated lane with zero foreign build activity** — meaning the stall is not purely a shared-target contention artifact; it is an inherent per-binary macOS Gatekeeper/codesign first-launch cost that nextest's discovery pass pays once per freshly-linked test binary, serialized across however many test targets a `--workspace`-scoped invocation discovers.

Consequence for §5.6 of the ticket ("do not summarize a 60-minute command as `test took 60 minutes` if the test itself executed in 50ms"): the harness's own `test build: 584s` line conflates 157s of real compilation with ~427s of first-launch discovery overhead across dozens of binaries that ran zero test code. This is exactly why AAASM-5911's `--lib`/`--test <stem>` targeting convention matters even *within* a single clean lane, not only under cross-worktree contention — narrowing discovery scope is a discovery-*count* fix, and discovery count is what this stall is proportional to.

## 5. sccache experiment

Micro-experiment on `aa-cache` (small leaf crate), isolated `CARGO_TARGET_DIR`, campaign-owned `SCCACHE_DIR` (10 GiB cap, sccache's own LRU eviction — no unbounded growth), sccache v0.17.0.

**Test A — `CARGO_INCREMENTAL=0` (the only regime where sccache can act at all per upstream docs, §3):**

| Run | Wall-clock | sccache hits | sccache misses |
|---|---|---|---|
| Run 1 (cold) | 11s | 0 | 57 |
| `cargo clean` (this lane only), Run 2 (identical) | 7s | **57 (100%)** | 57 (cumulative) |

Clean rebuild of an already-seen crate graph: **100% hit rate, ~36% wall-clock reduction** on this small crate. This is the regime sccache is designed for: CI runners, fresh worktrees, or any from-scratch rebuild of previously-compiled code — exactly AAASM-5910's original "isolated target-dirs would cost cold-rebuild time back" concern.

**Test B — default incremental (the actual local dev edit loop):**

| Run | Wall-clock | sccache compile requests this run |
|---|---|---|
| Run 1 (cold, incremental on) | 9s | 54 misses |
| Run 2 (touch one file, same lane) | **0s** | **0** — sccache never invoked |

Confirms the ecosystem-research finding empirically: under Cargo's default incremental compilation, the warm single-file edit loop is handled entirely by Cargo's own incremental cache before `rustc`/`sccache` is ever invoked. **sccache is a no-op for the fast-edit loop and cannot be "stacked" on top of incremental for that use case** — the two are mutually exclusive per-profile choices, not additive.

**sccache verdict: CONDITIONAL.** Adopt for non-incremental regimes only — CI (`CARGO_INCREMENTAL=0`, already set there per §2), and any future fresh-worktree/clean-rebuild path (e.g. an AAASM-5981 bounded-lifecycle reclaimer that deletes and later recreates a lane). Do **not** enable for the local dev/edit-check loop — it buys nothing there and adds a wrapper process + cache-directory management for zero benefit. Cache directory must stay bounded (sccache's native cap, confirmed working at 10 GiB in this test) — never point it at an unbounded location.

## 6. Target-dir / multi-lane architecture

Not re-benchmarked at 2/4/8-lane concurrency this session — justified by §1's DIRECTLY_REUSABLE classification of two independently-confirmed, architecture-level (not code-version-dependent) facts already in evidence:

1. **AAASM-5910 (`lsof`-confirmed):** a shared `target-dir`'s `debug/.cargo-lock` is one exclusive lock for the *entire* debug-profile tree — any two concurrent debug builds against the same target-dir serialize, regardless of what packages they touch. This mechanism is a property of Cargo's locking model, not of this repo's current code, so it does not need re-measurement to remain valid on today's SHA.
2. **AAASM-5909 field evidence (2026-08-26/27, this exact machine):** the alternative — full per-worktree isolation — traded that lock contention for an uncontrolled disk-exhaustion outage (229 MiB free / 100% capacity) because no bounded-lifecycle reclamation existed. §4's fresh 29 GiB/lane measurement is consistent with AAASM-5910's ~20 GiB/worktree estimate (higher here because this lane also compiled every test target, which AAASM-5910's projection didn't include).

Both facts point the same direction and are recent/durable enough that a new concurrency sweep would mostly re-derive them at real dollar/time cost. **Recommendation carries forward AAASM-5910 Part 2 + AAASM-5981 essentially unchanged, now with this session's sccache CONDITIONAL verdict layered in**: per-lane isolated target-dirs (bounded, with AAASM-5981's reclamation design) for the multi-agent/multi-worktree case, sccache backing only the non-incremental rebuild path so a freshly-created or reclaimed-then-recreated lane doesn't pay a full cold-compile tax. Heavy-lane count: this session adds no new evidence beyond AAASM-5910's disk math (16 logical CPUs, 128 GiB RAM measured this session; 373 GiB free at campaign end) — carry forward AAASM-5910's conclusion that the concurrency ceiling is disk-bound, not CPU-bound, and defer a precise lane number to AAASM-5981's implementation, which will have real per-lane disk quotas to reason from. Marking 2/4/8-lane empirical sweep **NOT_MEASURED this session** — reason: would reproduce already-DIRECTLY_REUSABLE evidence at high time/disk cost rather than answer a new question.

## 7. Conclusions / Pareto frontier

| Profile | Recommendation | Basis |
|---|---|---|
| FAST_EDIT (check/build after a 1-line change) | Current dev profile as-is (line-tables-only debuginfo, dep opt-level=1, default incremental, no sccache) | §4 measured 6s warm rebuild; §5 Test B proves sccache adds nothing here |
| TARGETED_TEST | `--lib` / `--test <stem>` nextest scoping (AAASM-5911, already shipped) | DIRECTLY_REUSABLE, ~1h40m→normal in the original incident; §4.1 shows *why* it matters even outside contention (discovery-count-proportional dyld cost) |
| MULTI_AGENT / multi-worktree | Shared target-dir's lock-serialization tradeoff (current machine state) vs. AAASM-5981's not-yet-built bounded-isolated-lane design | REVALIDATION not needed — architecture-level facts, see §6 |
| FULL_VERIFY (workspace build + full test compile) | Current: 139s cold build + 584s test compile (mostly discovery overhead, §4.1) | Candidate follow-up: reduce discovery overhead structurally (see §9) rather than just accepting it |
| RELEASE / dist | AAASM-2551's existing release/dist profile split (fat LTO, codegen-units=1 for `dist`; thinner for `release`) | Already merged, DIRECTLY_REUSABLE, not re-measured (out of scope — this is a correctness/size boundary, not a dev-speed lever per the ticket's own instruction) |

## 8. GitHub repo decision

**A. NO_NEW_REPO.**

Every concrete lever identified this session is either (a) a native Cargo profile/config setting already living in `agent-assembly`'s own `Cargo.toml`/`.cargo/config.toml`, (b) a documented convention (AAASM-5911) with no packageable artifact, or (c) a conditional wrapper around an existing, actively-maintained upstream tool (sccache) whose adoption is a config decision, not new code. The AAASM-5981 bounded-lifecycle reclaimer is the one piece with real implementation surface, and it is explicitly repo/machine-scoped (this developer's worktree layout) rather than a generically portable tool — it has no demonstrated cross-repo reuse or independent release lifecycle, which AAASM-5991's own repo-decision framework requires before considering B or C. Nothing here clears that bar today.

## 9. Follow-up tickets

Created under AAASM-5991 (see Jira comment on AAASM-5992 for links) — only items with direct measurement support this session:

1. **sccache CI adoption (CONDITIONAL, CI-only).** Wire `RUSTC_WRAPPER=sccache` into CI jobs that already run with `CARGO_INCREMENTAL=0` (ci.yml:230), using a bounded, Swatinem/rust-cache-coexisting cache dir. Evidence: §5 Test A, 100% hit rate / ~36% wall-clock cut on clean rebuild. Explicitly NOT for local dev profile (§5 Test B).
2. **Reuse AAASM-5981** (already filed, To Do) as the target-dir architecture implementation — this session's §6 evidence reinforces rather than duplicates it; added a comment cross-referencing this report instead of a new ticket.
3. **Investigate nextest discovery-overhead reduction** (new candidate, not yet a ticket — filed as a Spike-follow-up idea only, see Jira comment): §4.1's 427s discovery/157s-compile split on a single clean lane suggests the AAASM-5911 convention (targeted `--lib`/`--test`) should extend to a *default* CI/local invocation pattern for `--workspace`-scope runs, not just an incident-response convention. Needs its own measurement before scoping — not implemented this session.
4. **`.cargo/config.toml`'s commented-out macOS `lld` block is stale/incorrect** per current upstream docs (§3: rust-lld does not properly support macOS targets; Apple's own default linker since Xcode 15 already fills that role at zero config). Low-risk doc fix — correct or remove the macOS block so a contributor who uncomments it doesn't chase a broken linker flag.

## 10. Known limitations

- This campaign ran on a single developer machine; §0 documents the isolation controls taken, but absolute wall-clock numbers are this machine's, not portable constants.
- 2/4/8-lane concurrency was not re-benchmarked this session (§6) — carried forward from AAASM-5910/5909 evidence rather than re-measured. If that carried-forward conclusion is later challenged, it needs a fresh sweep, not a re-read of this report.
- `scripts/build-baseline.sh`'s `--timings` HTML archival step silently no-ops when `CARGO_TARGET_DIR` is overridden (it globs a hardcoded `target/cargo-timings/` path) — this session's isolation requirement (§0) means the harness's own top-crate breakdown was unavailable; the raw wall-clock numbers are unaffected, only the "top N slowest crates" nicety is missing. Worth a small harness fix, not filed as a ticket this session (cosmetic).
- Cranelift, Wild, and mold-on-macOS were evaluated from documentation only (§3), not benchmarked, per their TOO_IMMATURE/NOT_APPLICABLE classification — if the ecosystem shifts (Cranelift stabilizes, Wild ships macOS support), those classifications should be revisited, not assumed permanent.
