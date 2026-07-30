# DevTool Current-State & Reconciliation Report — AAASM-5274

**Ticket:** AAASM-5274 — \[DevTool\] Reconcile current implementation, Jira status and duplicate adapter sources
**Branch:** `v0.0.1/AAASM-5274/refactor/devtool_reconciliation`
**Base:** `main` @ `aae32497`
**Date:** 2026-07-30

This report is the evidence base for the consolidation carried out on this
branch. Every `file:line` below refers to the base commit unless it is marked
*(after)*, which refers to the branch tip.

---

## 1. Current-state matrix (as of base `aae32497`)

### 1.1 Adapter implementations per tool

| Tool | Detection | Managed settings (generate / apply) | Launch | MCP (list / govern) | Governance level | Tests | Actual consumers |
|---|---|---|---|---|---|---|---|
| **Claude Code — minimal** `aa-devtool/src/adapters/claude_code.rs:19` | `:23` PATH + `~/.claude` marker | `:49`, `:55` — both `Err("not yet fully implemented (AAASM-201)")` | `:62` — `Err` | `:74` `Ok(vec![])` / `:78` `Ok(())` (no-ops) | **`L3Native`** `:83` | 6 unit tests, all asserting the stub's `Err` | `DiscoveryService::new()` `aa-devtool/src/discovery.rs:28-36` → `aasm tools list` |
| **Claude Code — dedicated** `aa-devtool-claude-code/src/lib.rs:68` | `:228` `which claude` + `MIN_VERSION` 1.0.0 gate | `:262` / `:267` — real; merges only the 4 AASM-managed keys (`apply.rs:59-97`) | `:272` — real, proxy + identity env | `:292` / `:313` — real | **`L2Enforce`** `:319` | 53 unit + `tests/settings_merge.rs`, `tests/claude_code_bypass_permissions.rs` | **none** |
| **Codex — minimal** `aa-devtool/src/adapters/codex.rs:19` | `:23` PATH + `~/.npm/bin` | `:49` / `:55` — `Err` | `:62` — `Err` | no-ops | `L2Enforce` `:83` | 6 stub tests | `DiscoveryService::new()` |
| **Codex — dedicated** `aa-devtool-codex/src/lib.rs:149` | `:203` | `:219` / `:234` — real (`config.toml`, approval + sandbox policy) | `:281` — real | `:306` / `:312` | `L2Enforce` `:319` | 40 unit + `tests/wrapper.rs` | `aasm run codex` (`aa-cli/src/commands/run.rs:453`) |
| **Copilot — minimal** `aa-devtool/src/adapters/copilot.rs:16` | `:46` `~/.vscode/extensions/github.copilot-*` | `:59` / `:65` — `Err` | `:72` — `Err` | no-ops | **`L1Observe`** `:93` | 8 stub tests | `DiscoveryService::new()` |
| **Copilot — dedicated** `aa-devtool-copilot/src/lib.rs:94` | `:300` | `:316` / `:335` — real (VS Code settings alignment) | `:347` — real | `:366` / `:403` — real | **`L2Enforce`** `:423` | 24 unit tests | **none** |
| **Windsurf — minimal** `aa-devtool/src/adapters/windsurf.rs:19` (`WindsurfAdapter`) | `:23` PATH / `.app` / `~/.local/share` | `:66` / `:72` — `Err` | `:79` — `Err` | no-ops | **`L1Observe`** `:100` | 6 stub tests | `DiscoveryService::new()` |
| **Windsurf — dedicated** `aa-devtool-windsurf/src/lib.rs:175` (`WindsurfCascadeAdapter`) | `:250` | `:263` / `:287` — real (admin settings sync) | `:295` — real | `:317` / `:332` — real (MCP registry control) | **`L2Enforce`** `:372` | 34 unit + `tests/contract.rs` | `aasm run windsurf` (`run.rs:455`) |
| **SaaS** `aa-devtool-saas/src/adapter.rs:28` | `:58` — config/secret presence, not a local install | `:75` / `:85` — `Err` **by design** | `:93` — `Err` **by design** (nothing local to launch) | `:106` / `:115` — no-ops | `L1Observe` `:122`, structurally capped | 38 unit + 2 integration suites | `aa-api/src/routes/devtools/**` webhook ingest (not via `DevToolAdapter`) |

### 1.2 Consumer wiring (the divergence)

| Consumer | Claude Code | Codex | Copilot | Windsurf |
|---|---|---|---|---|
| `aasm tools list` → `DiscoveryService::new()` (`aa-cli/src/commands/tools.rs:30`) | minimal stub → reports **`L3Native`** | minimal stub | minimal stub → `L1Observe` | minimal stub → `L1Observe` |
| `aasm run <tool>` → `resolve_adapter()` (`aa-cli/src/commands/run.rs:449-460`) | `PlaceholderAdapter` (`run.rs:124-166`, **`L0Discover`**, every method `Err`) | real `aa-devtool-codex` | `PlaceholderAdapter` | real `aa-devtool-windsurf` |
| `GET /api/v1/tools` → `AppState.discovery` | `DiscoveryService::with_adapters(vec![])` — `aa-api/src/state.rs:370`, the only assignment ⇒ always `[]` | same | same | same |

Consequences on base:

* **Three** "Claude Code" adapters existed and the only complete one had no
  caller. `aasm tools list` advertised `L3Native` governance while
  `aasm run claude` resolved an adapter that could not generate settings or
  launch anything.
* `aa-devtool-claude-code` and `aa-devtool-copilot` had **zero consumers** in the
  workspace — dead code by wiring, not by intent.
* Root cause of the CLI half: `aa-cli/Cargo.toml:16-26` — the
  `# strip-for-publish:begin devtool` region only listed `aa-devtool`,
  `aa-devtool-codex`, `aa-devtool-windsurf`, so the other two crates were not
  even linkable from `aa-cli`.
* Root cause of the duplication itself: AAASM-205 (PR #206) created the thin
  detection-only adapters + `DiscoveryService` in parallel with AAASM-201–204,
  which were building the full per-tool crates. Neither side was retired.
* Stale marker: `aa-devtool/src/adapters/mod.rs:1-2` claimed the full
  implementations were "tracked in AAASM-201–204" long after those crates landed.

---

## 2. Disposition of every duplicate

| Implementation | Disposition | Where it lives now |
|---|---|---|
| `aa-devtool::adapters::claude_code::ClaudeCodeAdapter` (stub) | **Delegated** — implementation deleted, module re-exports the dedicated crate | `aa-devtool/src/adapters/claude_code.rs` *(after)* |
| `aa-devtool::adapters::codex::CodexAdapter` (stub) | **Delegated** | `aa-devtool/src/adapters/codex.rs` *(after)* |
| `aa-devtool::adapters::copilot::CopilotAdapter` (stub) | **Delegated** | `aa-devtool/src/adapters/copilot.rs` *(after)* |
| `aa-devtool::adapters::windsurf::WindsurfAdapter` (stub) | **Delegated**, name preserved via `pub use … WindsurfCascadeAdapter as WindsurfAdapter` | `aa-devtool/src/adapters/windsurf.rs` *(after)* |
| `aa-cli::commands::run::PlaceholderAdapter` | **Removed** — after rewiring no tool resolves to it and no other path needs it; an unregistered tool is now an error, not an inert adapter | — |
| `aa-devtool-{claude-code,codex,copilot,windsurf}` | **Authoritative** — unchanged by this ticket | their own crates |
| `aa-devtool-saas::SaasCodingAgentAdapter` | **Capped by design** — not a duplicate. Its `DevToolAdapter` impl is a formality: a hosted agent has nothing local to detect, configure or launch, so `L1Observe` is the ceiling. Its real surface is the webhook/audit path in `aa-api/src/routes/devtools/`. Deliberately **not** added to the registry — `aasm run saas` is meaningless | unchanged |
| `aa-devtool/src/adapters/util.rs` | **Retained, marked** — `find_on_path` / `probe_version` now have no in-tree caller (each dedicated crate does its own detection). Kept as dependency-free helpers for out-of-tree adapters; module doc records this | unchanged, doc note added |

No file was deleted.

---

## 3. Claude Code governance-level resolution

**Canonical value: `L2Enforce`.** (Stub said `L3Native`; dedicated crate said
`L2Enforce`; the dedicated crate wins.)

`governance_level()` is the tool's *overall* declaration, not a per-capability
one — per-capability tiers belong in the governance capability matrix. The
precedent is Codex: `aa-devtool-codex/src/lib.rs:319` declares `L2Enforce`
overall while achieving L3-grade control on individual capabilities.

Claude Code writes **native** managed settings (`aa-devtool-claude-code/src/apply.rs`),
which is an L3-ish capability, but it cannot natively enforce exec, file or
network policy — those still require `aa-proxy` (layer 2) or eBPF (layer 3). A
tool-wide `L3Native` therefore over-claims: it told operators via
`aasm tools list` that Claude Code was natively governed when the enforcing
paths were external. `L2Enforce` is the truthful overall value.

Copilot and Windsurf are resolved the same way, in favour of the dedicated
crate: **`L2Enforce`** for both (`aa-devtool-copilot/src/lib.rs:423`,
`aa-devtool-windsurf/src/lib.rs:372`). The `L1Observe` values in the minimal
adapters were placeholders that never matched what those crates actually do
(VS Code settings alignment + MCP governance; admin settings sync + MCP registry
control + terminal allow/deny).

No adapter's declared level was edited: normalisation happened by deleting the
duplicate declarations, so the surviving value is the one the working code
already backed.

---

## 4. Jira reconciliation

Evidence-based verdicts only. **No historical ticket was reopened, closed,
transitioned or reparented as part of this work** — this section is a
recommendation for a human to action.

| Key | Jira status | Code evidence | Verdict |
|---|---|---|---|
| AAASM-196 (Epic 14) | In Progress | tracked via children | **Still valid** — correctly open, because child AAASM-201 is not closed |
| AAASM-199 | Done | `aa-core/src/dev_tool.rs` (types + `DevToolAdapter`), sample plugin, `docs/devtools/plugins.md` | **Complete** |
| AAASM-200 | Done | `aa-cli/src/commands/run.rs`; subtasks 927/932/935/937/942 Done | **Complete** |
| **AAASM-201** | **To Do** | all 6 implementation subtasks (939/946/952/956/959/964) Done; a real, tested `aa-devtool-claude-code` crate is on `main`; verification subtask **AAASM-1112 still To Do** | **Partially complete — Jira disagrees with code.** Implementation merged long ago; verification never ran; the Story was never transitioned. Recommend: run AAASM-1112 against the wiring delivered here, then transition 201. Do **not** close it on implementation evidence alone |
| AAASM-202 | Done | `aa-devtool-codex` + bug AAASM-1179 (placeholder → real adapter) | **Complete** |
| AAASM-203 | Done | `aa-devtool-copilot`, 22 unit tests | **Complete** — but note the crate had **no consumer** until this ticket; "Done" described the crate, not the integration |
| AAASM-204 | Done | PR #216, `aa-devtool-windsurf` | **Complete** |
| AAASM-205 | Done | PR #206 — created the thin detection-only adapters + `DiscoveryService` | **Complete, and superseded.** This is the origin of the duplication; its adapters are the ones delegated away here. Recommend a comment linking AAASM-5274 rather than any status change |
| AAASM-918 | Done | PR #218, `aa-devtool-saas` | **Complete** |
| AAASM-1064 | Done | PR #562, `docs/src/governance/capability-matrix.md` | **Complete** — the Claude Code row is still `TBD`; filling it with the `L2Enforce` resolution from §3 belongs to whoever owns that file (deliberately untouched here to avoid a merge conflict) |
| AAASM-3565 | Done (parent AAASM-3560, not 196) | `deny.toml`, `.github/CODEOWNERS`, `verification-reports/AAASM-3565.md`, `aa-devtool-contract` | **Complete** — the restricted boundary is intact; see §6 |

---

## 5. Recommended source-of-truth design (implemented)

```
aa-devtool-contract  ← restricted capability facade (unchanged)
        ▲
        │
aa-devtool-{claude-code,codex,copilot,windsurf}   ← authoritative adapters
        ▲
        │  aa-devtool/src/registry.rs   ← THE table: tool token → adapter + kind
        │
   ┌────┴─────────────────────────────┐
DiscoveryService::new()          resolve_adapter()
 (aasm tools list, aa-api)        (aasm run)
```

`aa-devtool` is now a registry / discovery / orchestration layer and contains no
adapter implementation of its own.

**What changed**

| File | Change |
|---|---|
| `aa-devtool/src/registry.rs` | **New.** `SUPPORTED_TOOLS`, `adapter_for(tool)`, `kind_for(tool)`, `built_in_adapters()`. No fallback stub — an unregistered tool yields `None`, never a non-functional adapter |
| `aa-devtool/src/discovery.rs` | `new()` → `with_adapters(registry::built_in_adapters())`; added `adapters()` accessor so a caller can prove another path resolved the same set |
| `aa-devtool/src/adapters/{claude_code,codex,copilot,windsurf}.rs` | Implementations replaced by `pub use` of the dedicated crate + a module doc recording why |
| `aa-devtool/src/adapters/{mod,util}.rs` | Docs updated; `util` marked as having no in-tree caller |
| `aa-devtool/Cargo.toml` | Added the 4 per-tool crates; dropped `dirs`/`serde`/`serde_json`, `async-trait` → dev-dependency |
| `aa-cli/src/commands/run.rs` | `resolve_adapter` delegates to the registry; `PlaceholderAdapter` removed; tool list derived from `SUPPORTED_TOOLS` |
| `aa-cli/Cargo.toml` | Dropped the direct `aa-devtool-codex` / `aa-devtool-windsurf` deps — the per-tool crates are reached **through** `aa-devtool`, so adding a tool needs no `aa-cli` manifest change and the `strip-for-publish` region shrinks to one line |

**Publish safety.** `aa-devtool`, `aa-devtool-contract`, all five
`aa-devtool-*` adapter crates and `aa-api` are `publish = false`. Only `aa-cli`
publishes, and its single remaining devtool dep sits inside the existing
`# strip-for-publish:begin devtool` region (`.ci/strip-for-publish.sh`). Adding
path deps between these crates therefore has no crates.io impact.

**Behaviour change (accepted, user-visible).** `aasm run claude` and
`aasm run copilot` previously accepted the tool and then failed. They now run
the real adapters, which means `aasm run claude` generates and applies managed
settings into `~/.claude/settings.json`, merging only the four AASM-managed keys
(`permissions`, `permissionMode`, `enabledMcpjsonServers`,
`disabledMcpjsonServers`) and preserving every other user key
(`aa-devtool-claude-code/src/apply.rs:59-97`). This is exactly what
`aasm run codex` and `aasm run windsurf` already do to their tools' configs.
Durable install receipts / backups are AAASM-5278's scope, not this ticket's.

**Regression test.** `aa-cli commands::run::tests::discovery_and_run_resolve_the_same_adapter_metadata`
asserts, for every supported tool, that the adapter `resolve_adapter()` returns
and the adapter `DiscoveryService::new()` holds report the same
`governance_level()` and the same detected `DevToolKind`.
`registry_tool_tokens_map_to_expected_dev_tool_kinds` pins each CLI token to its
kind on any host (installed tools or not), and
`no_tool_resolves_to_a_placeholder_adapter` now covers every tool rather than
codex alone. All three were confirmed load-bearing by planting divergences and
observing the failures before reverting the plants.

---

## 6. Constraints honoured

* `aa-devtool-contract` untouched — **no re-export was added**. The dedicated
  adapter crates already implement `aa_devtool_contract::DevToolAdapter`, which
  is a re-export of the same `aa_core::DevToolAdapter` trait `aa-cli` uses, so
  the registry's `Box<dyn DevToolAdapter>` crosses the boundary with no new
  symbols. The CODEOWNERS-gated surface is unchanged.
* No plugin gained access to `aa-core`. `aa-devtool` is not a plugin; it is the
  layer above them and depends on the contract crate exactly as before.
* No dynamic library loading.
* `docs/src/SUMMARY.md` and `docs/src/governance/capability-matrix.md` were left
  alone (owned by concurrent tickets).

---

## 7. Known remaining gaps

1. **`GET /api/v1/tools` always returns `[]` — out of scope here, needs a
   ticket.** `aa-api/src/state.rs:370` hard-codes
   `DiscoveryService::with_adapters(vec![])`, and that is the *only* assignment
   of `AppState.discovery` (`state.rs:83`). The endpoint therefore reports no
   dev tools regardless of what is installed on the gateway host. Already
   self-documented as a known divergence in
   `aa-integration-tests/tests/api_tools.rs:9-19`. The fix is now a one-line
   change (`DiscoveryService::new()`), but it alters live API behaviour and
   several harness expectations, so it is deliberately not made here.
2. **No lifecycle or receipt machinery.** There is no install/verify/repair
   state, no record of what a previous `aasm run` wrote into a tool's config,
   and no backup before merge. This is the input AAASM-5278 needs.
3. **`aa-devtool-saas`'s `DevToolAdapter` impl is a formality** (see §2). If the
   trait ever grows lifecycle methods, SaaS agents will need a separate
   abstraction rather than more `Err` arms.
4. **`docs/src/governance/capability-matrix.md` Claude Code row is `TBD`** and
   should be filled from §3 by whoever owns that file.
5. **`aa-devtool/src/adapters/util.rs` has no in-tree caller.** Retained
   deliberately; a future ticket may either promote it to the registry (shared
   probing) or drop it once out-of-tree adapters are proven not to need it.
