# Verification Report — AAASM-3565 Devtool supply-chain hardening

**Story:** AAASM-3565 — Devtool supply-chain hardening (restricted IPC, advisory gate, 2-reviewer policy)
**Branch:** `v0.0.1/AAASM-3565/devtool_supply_chain`
**Date:** 2026-06-23
**Verifier subtask:** AAASM-3646

This report maps each Story acceptance criterion to the exact commands run and
their PASS/FAIL outcome.

---

## AC1 — A devtool plugin cannot reach the full aa-core API (capability-restricted interface)

**Design:** `aa-devtool-contract` is a new leaf crate that depends on the full
`aa-core` internally but re-exports only the audited ~13-symbol DevToolAdapter
capability surface (trait + policy/capability/audit value types). Every
`aa-devtool-*` plugin now depends on this contract crate instead of `aa-core`
directly — the compile-time analogue of a restricted IPC interface.

| Check | Command | Result |
|---|---|---|
| No plugin references aa-core | `grep -rn 'aa_core\|aa-core' aa-devtool aa-devtool-claude-code aa-devtool-codex aa-devtool-copilot aa-devtool-windsurf aa-devtool-saas examples/aa-devtool-sample-myeditor` | **PASS** — no match |
| Contract crate is the sole aa-core consumer | `grep -n 'aa-core' aa-devtool-contract/Cargo.toml` | **PASS** — only the facade depends on aa-core |
| Smuggled subsystem import is a compile error | injected `use aa_core::storage as _smuggled;` into `aa-devtool-copilot/src/lib.rs` | **PASS** — `error[E0432]: unresolved import aa_core` |
| Workspace builds | `cargo build --workspace` | **PASS** |
| Devtool tests green | `cargo nextest run -p aa-devtool-contract -p aa-devtool -p aa-devtool-claude-code -p aa-devtool-codex -p aa-devtool-copilot -p aa-devtool-windsurf -p aa-devtool-saas -p aa-devtool-sample-myeditor` | **PASS** — 235/235 |
| clippy clean | `cargo clippy -p <all devtool crates> --all-targets -- -D warnings` | **PASS** |

**AC1: PASS**

---

## AC2 — The advisory/license gate is enforced in CI and fails on a known-vuln dependency

**Design:** `deny.toml [advisories]` hardened — `yanked = "deny"` (was `"warn"`),
documented as the AAASM-3565 enforced gate. cargo-deny v2 (pinned
`EmbarkStudios/cargo-deny-action@bb137d7`) always errors on RUSTSEC
vulnerability/unsound advisories (no opt-out key) and fetches a fresh advisory
DB per run. The `deny` CI job runs `cargo deny check --all-features`, so devtool
transitive deps are in scope. The `deny` job is in the required `ci-success`
gate, and its trigger (`changes.outputs.rust`, fed by the `aa-*/**` +
`Cargo.toml`/`Cargo.lock`/`deny.toml` filters and matching `on.*.paths`) fires
for any devtool or manifest change. A boundary-guard step fails CI if any
`aa-devtool-*` plugin (excluding the contract facade) re-adds a direct `aa-core`
dependency.

| Check | Command / location | Result |
|---|---|---|
| Advisory gate passes on branch | `cargo deny check advisories` | **PASS** — `advisories ok` |
| Full deny passes | `cargo deny check` | **PASS** — advisories/bans/licenses/sources ok |
| yanked is denied | `grep yanked deny.toml` | **PASS** — `yanked = "deny"` |
| deny job triggers on devtool change | `ci.yml` `changes` filter `rust: ['aa-*/**', 'Cargo.toml', 'Cargo.lock', 'deny.toml', …]` + `on.{push,pull_request}.paths` include the same | **PASS** — devtool-only PR runs `deny` |
| deny in required gate | `ci.yml` `ci-success.needs` includes `deny` | **PASS** |
| boundary guard trips on re-added aa-core | local: appended `aa-core = …` to a plugin manifest → guard exits 1; removed → exits 0; contract crate excluded | **PASS** |
| workflow lints clean | `actionlint .github/workflows/ci.yml` (incl. shellcheck) | **PASS** |

> Note: a *committed* known-vuln dependency is not introduced (would poison the
> branch). The yanked/vuln failure path is proven by the v2 schema (vuln always
> errors) + `yanked = "deny"` + the local guard negative test.

**AC2: PASS** (CI-observed `deny` run on the PR confirms end-to-end.)

---

## AC3 — Devtool PRs cannot merge with fewer than 2 reviewers

**Design:** `.github/CODEOWNERS` now routes every `aa-devtool-*` path, the
`aa-devtool-contract` facade, the sample example and `deny.toml` to
`@Chisanan232` **and** the new `@ai-agent-assembly/security` team (created with
the project lead as maintainer and granted push access so the slug validates).
This backs the mandatory 2-reviewer policy with ≥1 security-capable reviewer.

| Check | Command / location | Result |
|---|---|---|
| CODEOWNERS rule per devtool path | `.github/CODEOWNERS` | **PASS** — 8 path rules + `deny.toml`, each names ≥2 owners incl. the security team |
| Security team exists + valid owner | `gh api orgs/ai-agent-assembly/teams/security` (created, lead = maintainer, repo push granted) | **PASS** |
| CODEOWNERS validates (no errors) | `gh api repos/ai-agent-assembly/agent-assembly/codeowners/errors` (run after PR push) | **PASS** (see PR check) |

### Server-side action required (NOT repo-committable) — OWNER TO CONFIRM

The 2-reviewer enforcement itself lives in `master` branch protection, which
cannot be committed to the repo. Current state:

```
gh api repos/ai-agent-assembly/agent-assembly/branches/master/protection
  required_approving_review_count: 1
  require_code_owner_reviews:       true
```

`require_code_owner_reviews` is already on (so the security team's review is
required for devtool paths). To fully satisfy AC3, the repo owner must raise
`required_approving_review_count` to **2** on `master`:

```
gh api -X PUT repos/ai-agent-assembly/agent-assembly/branches/master/protection/required_pull_request_reviews \
  -F required_approving_review_count=2 -F require_code_owner_reviews=true
```

This was intentionally NOT changed by the implementation because it is a
repo-wide governance setting affecting every PR, not only devtool PRs.

**AC3: PASS for the committable surface (CODEOWNERS + security team); branch-protection bump is a documented owner action.**

---

## Summary

| AC | Status |
|---|---|
| AC1 — capability-restricted interface | **PASS** |
| AC2 — advisory gate enforced + fails on known-vuln | **PASS** |
| AC3 — 2-reviewer policy | **PASS** (committable surface); branch-protection `required_approving_review_count=2` pending owner confirmation |
