# Contributing to agent-assembly

Thank you for your interest in contributing! This guide explains how to set up your environment and submit changes.

## Prerequisites

- **Rust stable** (≥ 1.75) — install via [rustup](https://rustup.rs/)
- **protoc** — Protocol Buffers compiler (`brew install protobuf` on macOS, `apt-get install protobuf-compiler` on Debian/Ubuntu); required by the `aa-proto` and `aa-gateway` build scripts, so the first `cargo build --workspace` fails without it
- **cargo-nextest** — `cargo install cargo-nextest`
- **cargo-deny** — `cargo install cargo-deny`
- **Lefthook** — `brew install lefthook` (macOS) or see [install guide](https://github.com/evilmartians/lefthook/blob/master/docs/install.md); the hook configuration lives in [`lefthook.toml`](lefthook.toml)
- **Rust nightly toolchain** (Linux, only for eBPF work) — the `aa-ebpf` crates compile for `bpfel-unknown-none` and require a recent kernel with BTF plus a nightly toolchain (see `aa-ebpf/README.md`); not needed for non-eBPF contributions

## Setup

```bash
git clone https://github.com/ai-agent-assembly/agent-assembly.git
cd agent-assembly

# Install git hooks (runs fmt, clippy, deny on commit; doc on push)
# See lefthook.toml for the full hook list.
lefthook install

# Verify the workspace builds
cargo build --workspace

# Run the test suite
cargo nextest run --workspace
```

## Faster builds (optional)

Two optimizations cut local build / rebuild time. The profile tuning is always
on; the faster linker is opt-in.

- **Optimized dev profile** (already enabled in [`Cargo.toml`](Cargo.toml)):
  dependencies build at `opt-level = 1` and workspace crates use
  `line-tables-only` debuginfo, so warm rebuilds link faster while test-failure
  backtraces stay readable. No setup required.
- **Faster linker** (opt-in): a faster linker dominates incremental link time.
  Install it once, then uncomment the block for your platform in
  [`.cargo/config.toml`](.cargo/config.toml):

  | Platform | Install | Linker |
  |---|---|---|
  | Linux | `sudo apt-get install -y mold clang` | mold |
  | macOS | `brew install llvm` | lld |

  The linker is left disabled by default so the workspace builds even without
  it installed.

## Branch Naming

Use the four-part format:

```
<release-or-phase>/<ticket>/<type>/<short_summary>
```

- `<release-or-phase>` — milestone or sprint identifier (e.g. `v0.0.1`, `phase1`).
- `<ticket>` — the ticket reference (e.g. `AAASM-1`).
- `<type>` — the change category (see table below).
- `<short_summary>` — 2–4 words in `snake_case`.

| `<type>` | When to use |
|---|---|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `refactor` | Refactor with no behavior change |
| `test` | Test-only change |
| `docs` | Documentation change |
| `config` | Configuration change |
| `deps` | Dependency upgrade |
| `remove` | Deletion or removal |
| `lint` | Lint or type-error fix |

Example: `v0.0.1/AAASM-42/feat/add_agent_registry`

> **External contributors** — the `AAASM-NN` project tracker is private, so you
> won't be able to mint a ticket. You don't need one: open a GitHub issue first
> (or reference an existing one) and use your GitHub issue number in the
> `<ticket>` slot (e.g. `v0.0.1/gh-123/feat/add_data_models`), or `noticket` if
> there's no issue yet. A maintainer will create the tracking `AAASM-NN` ticket
> and link it during review — a missing Jira reference will never block your PR.

## Commit Style

Use [Gitmoji](https://gitmoji.dev/) prefixed messages:

```
<emoji> (<scope>): <imperative summary>
```

**One commit per logical unit** — one new file, one property change, one function. Keep commits small and bisectable.

Examples:
- `✨ (aa-core): Add AgentId newtype wrapper`
- `🐛 (aa-gateway): Fix policy evaluation order for overlapping rules`
- `🔧 (ci): Add matrix build for MSRV check`

### Every commit must build (enforced)

"Bisectable" above is a hard requirement, not an aspiration: **every commit that
lands on `main` must compile on its own**. The `Every commit in the range builds`
CI job enforces it on each PR by walking `git rev-list HEAD^1..HEAD` over the
merge result and running `cargo check --workspace --all-targets --exclude
aa-ebpf` at each commit. It names the first commit that fails.

Run it yourself before pushing — it is the same script CI runs:

```bash
.ci/verify-range-builds.sh <base> <head>     # e.g. remote/main HEAD
```

Two things break this in practice, and neither is exotic:

- **Partial staging.** `git add` of one file while others stay modified records
  an index nobody built. The pre-commit hook cannot catch this: `cargo` reads
  the *working tree*, `git commit` records the *index*, and when they differ the
  hook validates a tree that is never committed. This is why `lefthook.toml`
  is not the place to fix it, and is deliberately left alone.
- **A clean-but-broken merge.** `git merge` exiting 0 means "no textual
  conflict" — not "the result compiles". Rename detection and independent edits
  to the same file both produce merges that build on neither side's terms while
  reporting success. `c596246a2` on `main` is a recorded instance: both parents
  build, the merge does not, and it entered `main` because the very next commit
  repaired it, so every tree CI ever built was green.

If the job names one of your commits, fix it **in that commit** — an interactive
rebase, or redoing the merge — rather than appending a repair. A follow-up fix
leaves the broken commit in history, which is the whole problem.

### Bisecting across known-broken history

`git bisect run` scores a commit by exit status: 0 good, 1 bad, 125 skip. A
commit that does not *compile* can answer neither good nor bad — the test never
ran — and a naive `build && test` script exits non-zero there, which bisect
scores "bad" and returns a confident wrong answer.

Use the supplied predicate, which returns 125 for such commits:

```bash
cp .ci/bisect-run.sh /tmp/aa-bisect-run.sh        # see below — must be copied out
git bisect start <bad> <good>
AA_BISECT_TEST='cargo test -p aa-gateway locale' git bisect run /tmp/aa-bisect-run.sh
```

With no `AA_BISECT_TEST`, the predicate is simply "does this commit build".

**Copy the script out of the working tree first.** `git bisect` rewrites the
tree at every step, so a script at `.ci/bisect-run.sh` is replaced by whatever
that path held at the commit under test — and for commits older than this gate,
by nothing at all, at which point bisect aborts. For the same reason the script
reads `.ci/bisect-skip.txt` via `git show <ref>:...` rather than from disk:
reading the list from the checked-out tree would consult the version that
existed at the commit under test, so the entries that matter would be invisible
exactly when they are needed.

`.ci/bisect-skip.txt` is the auditable list of commits already on `main` that do
not build. Adding an entry is one line — a full 40-character SHA and a reason.
An unbuildable commit that is *not* on the list is still skipped rather than
scored "bad", and reported loudly so the list can be extended. The list should
stop growing now that the CI gate prevents new entries.

## Adding a new crate

To add a new crate to the workspace:

1. Scaffold the crate with `cargo new --lib aa-<name>` from the repo root.
2. Add `aa-<name>` to the `members` array in the top-level [`Cargo.toml`](Cargo.toml).
3. In the new crate's `Cargo.toml`, inherit workspace metadata:

   ```toml
   [package]
   name = "aa-<name>"
   version.workspace = true
   edition.workspace = true
   license.workspace = true
   repository.workspace = true
   ```

4. Use `[workspace.lints.clippy]` from the top-level `Cargo.toml` — do **not** redefine clippy lints per-crate.
5. If the crate exposes a binary, declare it explicitly under `[[bin]]` (see [`aa-cli/Cargo.toml`](aa-cli/Cargo.toml) for the canonical example).
6. Run `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo doc --workspace --no-deps` to confirm the new crate integrates cleanly.
7. Add the crate to the **Crate Map** table and **Repository Layout** tree in [`README.md`](README.md).

## Pull Requests

- Open a PR against `main`.
- Title format: `[<ticket>] <emoji> (<scope>): <summary>` — external contributors
  without Jira access may use a GitHub issue reference (e.g. `[#123]`) or `[N/A]`
  in place of the `AAASM-NN` ticket; the Jira field in the PR template is
  optional for community PRs.
- Fill in the PR template — all checklist items must be addressed.
- CI must be green before review is requested.
- At least **1 approval** from the Pioneer team is required to merge.

## Developer Certificate of Origin (DCO)

We ask that you sign off each commit under the [Developer Certificate of Origin v1.1](https://developercertificate.org/) — this licenses your contribution to the project under the [Apache License 2.0](LICENSE). Sign-off is **currently advisory** (see the note below), consistent with the org-wide [contribution guide](https://github.com/ai-agent-assembly/.github/blob/HEAD/CONTRIBUTING.md).

Sign off by adding a `Signed-off-by` trailer to each commit message:

```
✨ (aa-core): Add AgentId newtype wrapper

Signed-off-by: Jane Doe <jane@example.com>
```

The easiest way is to pass `-s` (or `--signoff`) to `git commit`:

```bash
git commit -s -m "✨ (aa-core): Add AgentId newtype wrapper"
```

Sign-off is currently advisory: please include the trailer on every commit so the history is ready when the DCO GitHub App is enabled (tracked as a follow-up under Epic AAASM-13). At that point unsigned commits will block merge.

## Code Quality

Pre-commit hooks enforce these automatically on every `git commit`:

| Check | Command | Config |
|---|---|---|
| Formatting | `cargo fmt --all -- --check` | [`rustfmt.toml`](rustfmt.toml) |
| Linting | `cargo clippy --all-targets -- -D warnings` | [`clippy.toml`](clippy.toml) + `[workspace.lints.clippy]` in [`Cargo.toml`](Cargo.toml) |
| Dependencies | `cargo deny check` | [`deny.toml`](deny.toml) |

On `git push`, documentation is also checked: `cargo doc --workspace --no-deps`.

The workspace-level clippy lints (`correctness = deny`, `suspicious = deny`, others `warn`) live in `[workspace.lints.clippy]` of the top-level `Cargo.toml` — do not override them per-crate.

### Which CI jobs block a merge

`ci-success` is the aggregate check; membership in its `needs:` list is what makes a job blocking. When you add a CI job, choose its status by applying this rule:

> **Does the job assert *behaviour*, or produce a *metric*?**
> Jobs asserting functional behaviour — does it compile, do the tests pass, does the rendered app still work — are members of `ci-success` and **block**. Jobs producing quality or acceptance *metrics* — coverage percentages, Sonar findings — are excluded and are **advisory**.

A job's status is chosen by applying that rule, **never inherited from whichever job it was copied from**. Coverage and Sonar are advisory because they are metrics, not because advisory is a safe default: an advisory job that asserts behaviour is a check nobody acts on, which is indistinguishable from not having written it.

Note that `ci-success` treats a **skipped** need as passing, so a job behind a `dorny/paths-filter` router is only as sound as its filter. If your job can be broken by a change outside its own filter, it needs a different guard.

Because a filter's soundness is what the gate reduces to, the filter's *shape* is itself something to get right — and there are two ways to get it wrong, in this repo and org-wide:

- **Too broad a filter.** A path filter must allow-list by **file extension or exact filename** — never by a bare `dir/**` or `dir/*` with no type qualifier. A directory wildcard matches every future non-code addition under that tree (screenshots, generated reports, fixtures, docs) as though it were a source change that must re-run the gated job. Enumerate instead the file types or exact filenames that constitute a real change to the gated surface — e.g. `dashboard/**/*.{ts,tsx,css}`, or `paths-ignore: ['**/*.md', 'docs/**']`. Qualify every entry before merging rather than deferring it to a follow-up; `e2e-private/preview-e2e.yml` and `python-sdk`'s core CI are the in-org examples of a compliant shape.
- **No filter at all.** Every job whose cost is non-trivial — e2e/integration suites, native builds, Docker builds — must have *some* form of change-based gating. An unconditional full-suite run on every push/PR is equally out of policy, just reached by omission rather than by a wrong pattern, and a job is not exempt merely because it currently has no filter. Add the gating when you introduce the job, not after a wasted-minutes complaint forces it retroactively.

These trade against each other, so neither is an escape from the other: leaving an expensive job unfiltered to sidestep getting the file-type qualifier right swaps one violation for the other. Writing a compliant filter requires knowing which file types genuinely affect the gated job, which is marginally more work than typing `dir/**` — that is the intended trade, since the failure mode being closed is exactly "wildcard now, discover the gap later".

**One exception**, so the rule is not miscited: a repo whose entire purpose *is* non-code content — a docs site where `docs/**` / `*.md` legitimately *is* the source, such as `internal-docs` — needs no file-type qualification. There the content directory itself is the correct trigger surface, and over-qualifying its filter would exclude legitimate changes.

## Performance and Latency Tests

Latency and performance tests assert absolute timing thresholds (e.g. p99 < 15 ms). They **must not run under `cargo llvm-cov`** or any other coverage/instrumentation tool, because instrumentation adds 2–10× overhead per instruction and makes timing guarantees unreliable on shared CI runners.

**Rule:** every `cargo llvm-cov` invocation that covers the workspace must pass `-- --skip <test-name>` for each timing-sensitive test.

Example (`ci.yml` and `sonar.yml`):

```yaml
cargo llvm-cov --no-report --all-features --workspace \
  --exclude aa-ebpf \
  -- --skip sustained_load_p99_under_5ms
```

Latency tests run in the dedicated **Benchmark** CI job (`cargo test -p aa-gateway --test policy_latency_test`) which uses an unmodified binary with no instrumentation.

## Build docs locally

Contributor documentation is an [mdBook](https://rust-lang.github.io/mdBook/) rooted at `docs/`. To build or preview it:

```bash
# One-time install (pin matches CI)
cargo install --locked --version 0.5.2 mdbook
cargo install --locked --version 0.17.0 mdbook-mermaid

# Build static HTML into docs/book/
mdbook build docs

# Live-reload preview at http://localhost:3000
mdbook serve docs --open
```

Mermaid diagrams use the `mdbook-mermaid` preprocessor, which is wired in `docs/book.toml`. The `Docs` GitHub Actions workflow runs `mdbook build docs` on every PR that touches `docs/**`, `README.md`, or `CONTRIBUTING.md` and fails the build on errors.

## Linking to another repository

Every active repo in the org defaults to `main` (see [ADR 0016](docs/src/adr/0016-default-branch-master-to-main-migration.md)). When you write a link, ref, or automation target pointing at **another `ai-agent-assembly` repository**, use the **default-branch-tracking `HEAD` form** — `…/blob/HEAD/…`, `raw.githubusercontent.com/<org>/<repo>/HEAD/…` — rather than hardcoding a branch name, so the reference survives any future rename. This rule is scoped to repos in this org: a link into a third-party repository is that project's business, and its branch names are not ours to track.

A rename's redirect is not a safety net for all of these: `github.com` web `blob`/`commits` links do redirect, but **`raw.githubusercontent.com/…/<branch>/` does not** (it 404s), and neither does `git fetch <branch>` or an action pinned with `uses: <org>/<action>@<branch>`. Those break outright, so write them against `HEAD` from the start. The same rule applies to a workflow that opens a PR into another repo: its `base:` must name that repo's current default branch, which `scripts/check-release-completeness.sh` checks for the release fan-out.

## Version metadata: single source of truth & drift gate

Per [ADR 0013](docs/src/adr/0013-version-metadata-source-of-truth-and-drift-gate.md), every version-bearing value in this repo has exactly one source of truth (SoT) and propagates one direction only — SoT → generator → checked-in consumer. Nothing outside a SoT (or its generated output) may carry a version literal.

- **Anchors (the SoT):** the core/runtime version is `Cargo.toml [workspace.package].version`; the mdBook/tool pins live in `metadata/docs.yaml`. The mdBook install commands just above are *stamped from that SoT* — edit the SoT, not these lines.
- **To change a version-bearing value:** edit the anchor, then run `python3 scripts/propagate_versions.py` (Python 3.11+) to restamp every consumer (README install/status lines, `docs/src/quick-start/installation.md`, the `Docs` workflow pins, these CONTRIBUTING commands, and the `docs/src/generated/` snippets). Commit the SoT edit and the regenerated files together.
- **The gate:** the `Docs` workflow's `version-drift` job runs `python3 scripts/propagate_versions.py --check` on every PR/push touching a version-bearing path and **fails the build** if any consumer is stale (mirrors `examples`' `example-metadata-check.yml`). Never hand-edit a stamped line or restate a version literal in prose.

## Reporting Issues

Use the GitHub issue templates:
- **Bug report** — reproducible steps, expected vs actual behaviour, environment.
- **Feature request** — motivation, proposed solution, alternatives considered.

For security issues, see [SECURITY.md](SECURITY.md).
