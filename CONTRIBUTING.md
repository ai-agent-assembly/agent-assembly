# Contributing to agent-assembly

Thank you for your interest in contributing! This guide explains how to set up your environment and submit changes.

By participating in this project you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

For the fastest path from a fresh clone to a verified local environment, follow
the [Quickstart in the README](README.md#quickstart) (`make dev-setup` +
`make dev-verify`). The sections below cover the manual setup and the
day-to-day contribution workflow in more detail.

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

# Install git hooks (runs fmt, deny on commit; doc on push)
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

Commit messages follow [Gitmoji](https://gitmoji.dev/)-prefixed
[Conventional Commits](https://www.conventionalcommits.org/):

```
<emoji> (<scope>): <imperative summary>
```

- `<emoji>` — a [Gitmoji](https://gitmoji.dev/) marking the change category
  (see the table below)
- `<scope>` — the affected crate or area (e.g. `aa-core`, `ci`, `docs`)
- `<imperative summary>` — imperative mood, under 72 characters

| Emoji | Category | Conventional type |
|---|---|---|
| ✨ | New feature | `feat` |
| 🐛 | Bug fix | `fix` |
| ♻️ | Refactor (no behaviour change) | `refactor` |
| ✅ | Tests | `test` |
| 📝 | Documentation | `docs` |
| 🔧 | Configuration / CI | `config` / `ci` |
| ⬆️ | Dependency upgrade | `deps` |
| 🗑️ | Deletion / removal | `remove` |
| 🚨 | Lint / type-error fix | `style` |

**One commit per logical unit** — one new file, one property change, one function. Keep commits small and bisectable so a reviewer can follow each step.

Examples:

- `✨ (aa-core): Add AgentId newtype wrapper`
- `🐛 (aa-gateway): Fix policy evaluation order for overlapping rules`
- `🔧 (ci): Add matrix build for MSRV check`

### Every commit must build (enforced)

"Bisectable" above is a hard requirement, not an aspiration: **every commit that
lands on `main` must compile on its own**. The `Every commit in the range builds`
CI job enforces it on each PR by walking `git rev-list HEAD^1..HEAD` over the
merge result and running `cargo check --workspace --all-targets --all-features
--exclude aa-ebpf` at each commit. It names the first commit that fails.

Precisely what that does and does not assert: it checks that each commit
**compiles**, not that its tests pass, that it is lint-clean, or that it is
formatted — the tip is separately held to all of those. `aa-ebpf` is excluded
and covered by `ebpf-build`.

Run it yourself before pushing:

```bash
.ci/verify-range-builds.sh <base> <head>     # e.g. remote/main HEAD
```

Same script, but **a weaker guarantee than CI's**, and the difference is the
one this gate was built for. `remote/main..HEAD` contains no merge commit, so
locally you are checking only your own commits. CI runs it over
`refs/pull/N/merge`, whose range ends in the synthetic merge commit — so the
**merge result** is checked only by CI. A clean-but-broken merge (below) is
invisible locally by construction.

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
rarely need new entries now that the CI gate runs on every PR that triggers CI.
One residual gap: `ci.yml`'s `on.pull_request.paths` is evaluated against a PR's
*net* diff, so a PR whose net diff touches no listed path never starts CI at
all — and its intermediate commits go unchecked even if they break the build.
Closing that would mean dropping path-based CI gating repo-wide, which is a
separate cost decision; until then, a new entry here is possible.

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
| Dependencies | `cargo deny check` (only when `Cargo.toml`/`Cargo.lock` changed) | [`deny.toml`](deny.toml) |

On `git push`, documentation is also checked: `cargo doc --workspace --no-deps` (scoped to
Rust-affecting pushes — see the `lefthook.toml` comment on `pre-push.commands.doc`).

**Linting** (`cargo clippy --all-targets -- -D warnings`, [`clippy.toml`](clippy.toml) +
`[workspace.lints.clippy]` in [`Cargo.toml`](Cargo.toml)) is **not** a pre-commit hook
(AAASM-5838 — a full-workspace clippy invocation on every commit was too slow on this
repo's shared-`CARGO_TARGET_DIR` convention). Run it explicitly before opening a PR,
scoped to only the crates your diff touches:

```bash
scripts/clippy-changed-crates.sh          # diff = working tree vs HEAD
scripts/clippy-changed-crates.sh origin/main  # diff = working tree vs a given base
```

CI's `clippy` job runs the full, unscoped `--workspace --all-targets --all-features`
invocation as a required check before merge — that remains the authoritative gate; the
script above is a fast local pre-flight, not a substitute for it.

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

### Which CI checks are governance-bearing

The rule above decides whether a job inside `ci.yml` blocks. This one decides something different and is asked at the level of a **whole workflow**: whether its check must be a **required status check** on `main`, and therefore whether it is allowed to be path-filtered at all.

> **If this gate fails, is the honest description "a published statement about the product is false" or "we would distribute something we did not declare" — rather than "a test broke"?**
> If yes, the workflow is **governance-bearing**.

Three questions make it decidable rather than a matter of taste. A workflow is governance-bearing when all three hold:

1. **Object.** It asserts over a *claim, declaration, or evidence record* — a manifest, a coverage matrix, a metadata registry, published documentation, a contact surface, a distribution boundary — not over program behaviour.
2. **Failure meaning.** A red run means we are telling someone something untrue, or would ship something we did not declare. It does not mean the code stopped working.
3. **Silence is indistinguishable from truth.** If the gate never runs, nothing else detects the same defect. This is the question that does the real work. A broken test also breaks at runtime later, and something eventually notices; a false claim never breaks anything. It simply stays false. Nothing in the tree except `scripts/validate_capability_manifest.py` reads `governance/capability-manifest.yaml`.

Question 3 is also why the criterion is not "everything important". `Crate Pinnability Smoke` asserts a distribution-shaped property, but what it asserts is that code *compiles* in an external-consumer shape — behaviour, question 1 — and it belongs with the `ci-success` family. `CodeQL` produces findings, which is a metric.

`Claude Code conformance` is the closest call and should be recorded as such rather than waved past: one of its jobs is literally named *"Native CLI suite (evidence report)"*, and an evidence record is question 1's own object type. It is excluded on questions 2 and 3 — a red run there means the integration stopped working, which is a behaviour failure that surfaces elsewhere, not a false published claim that nothing else would ever notice. If that job's output ever becomes a *published* evidence artefact rather than a CI report, the answer flips and it belongs in `governance/ci-coverage.yaml`.

**A governance-bearing workflow must not path-filter `on.pull_request`.** This is not a style preference. A path-filtered workflow that does not trigger produces **no check run at all** — not a pending one, an absent one — so it cannot be a required check: a required check that never arrives blocks the pull request forever, and the natural unblock is an administrative override, which is exactly what the merge policy forbids. Put the selection in a `dorny/paths-filter` router job instead and gate the real jobs on `needs.changes.outputs.*`, so the check always reports a conclusion.

Two consequences that are easy to get wrong:

- **Route `pull_request` only; leave the backstops unconditional.** A workflow's `push` or `schedule` trigger is what makes its evidence a standing property rather than a PR-time opinion (ADR 0034: a path-filtered gate with no backstop "is not evidence of a standing property at all"). If its `on.push` carries no paths filter, gate the router job itself with `if: github.event_name == 'pull_request'` — otherwise the router silences the backstop too. If `on.push` *does* carry a paths filter, every router glob needs a matching entry in it, or the gate never runs on the merge that breaks it.
- **Disclose the cost, because the trade is real.** Dropping the `pull_request` path filter means the workflow starts on every pull request, so its router job runs unconditionally. Across the five governance-bearing workflows that is five extra runner starts, plus five aggregate jobs — roughly a minute of runner time per pull request, none of it a build. That is the price of a check that always reports, and #2014 set the precedent of stating added unconditional work rather than letting someone discover it in a billing report. The gated jobs themselves still skip: on a pull request matching none of their paths, 44 of them concluded `skipped`.

  One class *is* a build, so the "none of it a build" line above does not cover it: bringing `verification-reports/**/*.md` inside `docs.yml`'s router means a pull request touching only a verification report now runs the whole gated docs set, including `Verify documented commands`, at roughly 841 s. Measured frequency before deciding it was acceptable: **1 of the last 60 merged pull requests** touched that path. The alternative — a second workflow carrying only the pure-script drift gates — buys back ~14 minutes on one PR in sixty and adds a seventh required context to keep in step, so it is not worth it yet. Revisit if verification reports become a routine part of the workflow.
- **Name the required context separately from the job it aggregates.** Each governance-bearing workflow ends in an `if: always()` aggregate — `Capability Manifest Success`, `Docs Success`, and so on — and *that* is what branch protection names. Requiring an internal job's name means a rename silently drops the requirement, with no error anywhere.

### Path filters, triggered workflows and required checks

These three are one contract, and a change to any of them can silently remove coverage from the other two. The relationship is recorded in **`governance/ci-coverage.yaml`** and enforced by **`scripts/check_governance_ci_coverage.py`**, which runs as the blocking `Governance CI coverage` job in `ci.yml`.

| Layer | Decides | Failure if wrong |
|---|---|---|
| `on.<event>.paths` | whether the workflow runs at all | no check run — reads as *absent*, not *failing* |
| router filter (`dorny/paths-filter`) | which jobs run | job skips; `ci-success` counts a skip as a pass |
| branch protection contexts | which checks must pass to merge | a red gate does not block the merge |

**Adding a new governance-bearing path is therefore a four-part change**, and the gate fails until all four agree:

1. add the path to the covering workflow's router filter;
2. add it to that workflow's `on.push.paths`, if it has one (a router filter with no matching trigger entry is a dead trigger);
3. add it to the relevant `coverage[].paths` entry in `governance/ci-coverage.yaml`;
4. if it needs a *new* covering workflow, drop that workflow's `on.pull_request` paths filter, give it an `if: always()` aggregate, and add the aggregate to branch protection as a required context.

#### Turning a new aggregate into a required check

Requiring a context is **not** a single settings edit, and getting the order wrong blocks every open pull request rather than gating them. The steps are ordered by what each one makes true:

1. **Merge the workflow change first.** Until the workflow that produces the check is on `main`, no pull request based on `main` can produce it.
2. **Force a new event on every open pull request** — `gh pr update-branch`, or an empty push. Merging does **not** retroactively create check runs on an existing head SHA; only a new event does, and with `strict=false` GitHub will not force the update for you. A pull request last built before the merge still has no run for the new context.
3. **Verify per head SHA, reading the pull requests and not `main`.** For every open pull request, confirm each candidate context has a check run on *its* head SHA. `Release Completeness Success` cannot be confirmed on `main` at all — `release-completeness.yml` has only `pull_request` and `workflow_dispatch` triggers, no `push` — so a check phrased as "confirm the contexts appear on `main`" silently comes back 5-of-6 and reads as success.
4. **Only then add the contexts** to branch protection, via the `required_status_checks` sub-endpoint so review requirements and `enforce_admins` cannot be altered as a side effect.
5. **Confirm merge-blocking, not configuration.** Read the setting back with an independent `GET`, then run `gh pr checks <n> --required` on a live pull request. A configuration read-back is not evidence that a merge is blocked.

The failure this ordering exists to prevent has a live example: **PR #1053** was last updated before #2014 merged and has **no `CI Success` run today**, so it is already unmergeable on an absent required context. Note the discriminator carefully — **#1050 was updated the same day and does have one**. Staleness is not the cause; whether the pull request's paths matched the filter is. That is the mechanism, and it scales with the number of required contexts.

Run the gate locally before pushing:

```bash
python3 scripts/check_governance_ci_coverage.py --verbose   # lists the files every declared glob selects
python3 scripts/check_governance_ci_coverage.py --selftest  # proves the gate can still go red
```

`--verbose` exists because the failure mode is quiet: a glob that matches nothing looks exactly like a glob that matches everything you meant. Read the counts.

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

## Where a piece of content belongs

Product content is published across a company site, a product website, the Docs Hub, this book, the SDK and Arena docs, the examples gallery, and a README per repository. Before you add or correct a public statement, check [Content-layer ownership](docs/src/development/content-ownership.md): it records which layer owns each content type, how an outer layer may summarise or quote a source it does not own, when a duplicate is allowed and when it is not, and where a correction lands first. Its pre-PR checklist is the short form.

The two rules it exists to protect: **fix the canonical source before the page you noticed the problem on**, and **an outer layer may drop detail but never a bound** — a platform, a precondition, or an [ADR 0033 §6](docs/src/adr/0033-canonical-governance-and-enforcement-architecture.md) claim term.

## Linking to another repository

Every active repo in the org defaults to `main` (see [ADR 0016](docs/src/adr/0016-default-branch-master-to-main-migration.md)). When you write a link, ref, or automation target pointing at **another `ai-agent-assembly` repository**, use the **default-branch-tracking `HEAD` form** — `…/blob/HEAD/…`, `raw.githubusercontent.com/<org>/<repo>/HEAD/…` — rather than hardcoding a branch name, so the reference survives any future rename. This rule is scoped to repos in this org: a link into a third-party repository is that project's business, and its branch names are not ours to track.

A rename's redirect is not a safety net for all of these: `github.com` web `blob`/`commits` links do redirect, but **`raw.githubusercontent.com/…/<branch>/` does not** (it 404s), and neither does `git fetch <branch>` or an action pinned with `uses: <org>/<action>@<branch>`. Those break outright, so write them against `HEAD` from the start. The same rule applies to a workflow that opens a PR into another repo: its `base:` must name that repo's current default branch, which `scripts/check-release-completeness.sh` checks for the release fan-out.

## Version metadata: single source of truth & drift gate

Per [ADR 0013](docs/src/adr/0013-version-metadata-source-of-truth-and-drift-gate.md), every version-bearing value in this repo has exactly one source of truth (SoT) and propagates one direction only — SoT → generator → checked-in consumer. Nothing outside a SoT (or its generated output) may carry a version literal.

- **Anchors (the SoT):** the core/runtime version is `Cargo.toml [workspace.package].version`; the mdBook/tool pins live in `metadata/docs.yaml`. The mdBook install commands just above are *stamped from that SoT* — edit the SoT, not these lines.
- **To change a version-bearing value:** edit the anchor, then run `python3 scripts/propagate_versions.py` (Python 3.11+) to restamp every consumer (README install/status lines, `docs/src/quick-start/installation.md`, the `Docs` workflow pins, these CONTRIBUTING commands, and the `docs/src/generated/` snippets). Commit the SoT edit and the regenerated files together.
- **The gate:** the `Docs` workflow's `version-drift` job runs `python3 scripts/propagate_versions.py --check` on every PR/push touching a version-bearing path and **fails the build** if any consumer is stale (mirrors `examples`' `example-metadata-check.yml`). Never hand-edit a stamped line or restate a version literal in prose.

## Reporting Issues

File issues through the GitHub issue templates so they capture the detail
maintainers need to act:

- [**Bug report**](.github/ISSUE_TEMPLATE/bug_report.md) — reproducible steps, expected vs actual behaviour, environment.
- [**Feature request**](.github/ISSUE_TEMPLATE/feature_request.md) — motivation, proposed solution, alternatives considered.

Search [existing issues](https://github.com/ai-agent-assembly/agent-assembly/issues) before opening a new one to avoid duplicates.

**Do not** open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for the private disclosure process.
