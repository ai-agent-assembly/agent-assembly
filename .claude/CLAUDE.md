# CLAUDE.md — agent-assembly

Guidance for Claude Code (and humans) working in this repository. This file holds
**repo-specific** context only; general engineering policy lives in the global
config. When a fact here duplicates `CONTRIBUTING.md`, the `Makefile`, or
`Cargo.toml`, treat those as the source of truth and update them, not just this file.

## What this repo is

The **core Rust monorepo** for AI Agent Assembly — the product that evaluates what
an AI agent does against policy and records the outcome. It contains the gateway
("the brain"), the policy engine, the interception mechanisms, the FFI shims the
language SDKs bind to, and the operator CLI. The language SDKs (`python-sdk`,
`node-sdk`, `go-sdk`) and the cloud control plane live in **separate repos**; this
one is the source of truth for the protocol, policy semantics, and the shared
`aa-*` crates they pin.

## Architecture: the interception mechanisms

Governance is assembled from independently-deployable mechanisms, and a deployment
runs whichever subset it installs. They are not a fallback chain and not a ranking:
each reaches a different ADR 0033 §6 claim level, and an absent one is reported as
absent rather than picked up by the next. Listed lowest-latency first:

1. **SDK layer (in-process)** — language SDKs call a thin Rust shim (`aa-ffi-*` in
   the SDK repos) over **`aa-sdk-client`**, which emits events and asks the runtime
   for a decision on a wrapped framework tool call. Fastest path; requires SDK
   adoption *and* an explicit initializer call *and* a reachable runtime. In this
   repo it reaches *Evaluated* (advisory) — `aa-sdk-client` is not an enforcement
   point here, and *denied before execution* depends on the out-of-repo shim
   honouring the answer. Advisory only — see ADR 0002.
2. **Sidecar proxy (`aa-proxy`)** — MitM of outbound HTTPS using per-host certificates
   minted from a local root CA; refuses or redacts a request before it leaves the
   machine, without changing the *agent's* own code. Requires the process to honour
   `HTTP_PROXY`/`HTTPS_PROXY` and trust the CA
   (on macOS *attempted* at proxy start via `security add-trusted-cert`, which needs
   admin authorization — a refused prompt fails proxy startup, `aa-proxy/src/lib.rs:64-69`
   + `tls/keychain.rs:16`; on Linux `sudo aasm proxy install-ca`,
   `aa-cli/src/commands/proxy/ca.rs:150-188`; Windows unsupported). HTTP/1.1 only on
   MitM'd hosts, and `llm_only` defaults to `true`, so only the built-in LLM hosts
   are decrypted.
3. **eBPF (`aa-ebpf*`)** — kernel uprobes on OpenSSL + exec/file syscall hooks.
   **Observe-only**: the probes emit telemetry and return no verdict, so this layer
   detects, it does not block. **Linux only**; there is no `cfg(target_arch)` gate —
   TLS uprobes and exec tracepoints work on x86_64 and aarch64, but the file-I/O
   kprobes are x86_64-only (hardcoded `__x64_sys_*`). It fails open if it cannot
   attach. It is one possible host mechanism, not a general enforcement layer.

<!-- truth-exempt: negative-example - the AAASM-5528 wording, quoted to show what is prohibited -->
> **Do not restate these as absolutes.** Public copy derived from this file was the
> source of the AAASM-5528 truthfulness bug ("catches everything, including bypass
> attempts"). Every claim above must name its boundary; see
> `verification-reports/AAASM-5528-public-claim-inventory.md` for the evidence and
> `docs/src/devtools/limitations.md` for the measured limits.
<!-- /truth-exempt -->

The **gateway (`aa-gateway`)** is the brain: agent registry, policy engine
(`src/policy/`), per-team budgets (`src/budget/`), gRPC for SDKs + HTTP/OpenAPI
(via `aa-api`) for the dashboard. The **runtime (`aa-runtime`)** is the authoritative
chokepoint, but split the two things it does: the allow/deny/pending gate is
`handle_policy_query` (`aa-runtime/src/pipeline/mod.rs:407`), while `RuntimeScanner`
(`aa-runtime/src/pipeline/enforcement.rs:182`) is the scan/redact/normalize stage —
authoritative *versus the untrusted SDK's own scan*, not the policy gate. The
**CLI (`aa-cli`)** ships the `aasm` binary (`aasm topology` / `policy` / `dashboard`).

### Crate map (flat at repo root, not under `crates/`)

| Crate | Role |
|---|---|
| `aa-core` | Wire types (`aa_core::types`), storage traits (`aa_core::storage`), conformance harnesses |
| `aa-proto` | Protobuf/tonic definitions (committed generated code) |
| `aa-gateway` / `aa-api` | Gateway brain + HTTP/OpenAPI surface |
| `aa-runtime` | Authoritative chokepoint: policy gate (`handle_policy_query`) + scan/redact stage (`RuntimeScanner`) |
| `aa-sdk-client` | FFI-agnostic client the SDK shims pin by git SHA |
| `aa-security` | Credential scanner + redaction (leaf crate) |
| `aa-proxy` / `aa-ebpf*` / `aa-sandbox` | Interception mechanisms: transport mediation, Linux host-level, WASM tool sandbox |
| `aa-cache` / `aa-storage*` | L1 cache + storage drivers |
| `aa-cli` | `aasm` operator binary |
| `aa-devtool*` | Per-tool governance adapters (claude-code, codex, copilot, windsurf, saas) |
| `dashboard/` | React/Vite operator UI (token-driven theming) |

## Build, test, lint

See `CONTRIBUTING.md` and the `Makefile` for the full list. Common commands:

```bash
lefthook install                       # one-time: fmt/clippy/deny on commit, doc on push
cargo build --workspace
cargo nextest run --workspace          # full suite
cargo nextest run -p aa-core           # one crate
cargo nextest run -p aa-gateway budget::types::tests::provider_variants_are_distinct  # one test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo doc --workspace --no-deps        # checked on push by hooks
```

- Some setups need `RUSTUP_TOOLCHAIN=stable` + an explicit toolchain path (normal on
  this machine; see `.claude/settings.local.json` allow-list).
- eBPF crates (`aa-ebpf*`) use target-specific toolchains; `cargo check -p aa-ebpf`
  suffices on non-Linux.
- `aa-cli` smoke-test: `./target/debug/aasm <subcommand>`.

## Conventions (see `CONTRIBUTING.md` — don't duplicate)

- **Commits:** `<emoji> (<scope>): <imperative summary>` (gitmoji.dev). One logical
  unit per commit; bisectable. Utils/mocks/tests are separate preceding commits.
- **Branch:** `<release-or-phase>/<ticket>/<type>/<short_summary>`
  (`<type>` = feat/fix/refactor/test/docs/config/deps/remove/lint;
  e.g. `v0.0.1/AAASM-42/feat/add_agent_registry`).
- **PR title:** `[<ticket>] <emoji> (<scope>): <summary>`; base branch **always
  `main`**; body follows the repo PR template; ≥1 Pioneer-team approval.

## Repo-specific gotchas

- **Push remote is `remote`** (→ `ai-agent-assembly/agent-assembly`, canonical), not
  `origin` (a personal fork). Scope changes against `remote/main`, which is often
  far ahead of a fork checkout.
- **Pre-push runs `cargo doc` with no path glob**, so it fails on eBPF/macOS even for
  docs-only changes. For Markdown/`.claude`-only branches that can't satisfy it,
  publish granular history via the GitHub Git Data API replay rather than `git push`.
  **Never `--no-verify`; never force-push.**
- **Org GitHub Actions is billing-blocked** on private repos and intermittently
  org-wide — jobs abort in ~2–11s with a payments message. Check run **annotations**
  before triaging as a code bug; **validate locally** instead of waiting on CI.
- **CI router:** `ci.yml` has a two-layer model — workflow `on.paths` (whether CI
  runs) + a `dorny/paths-filter` `changes` router (which jobs). Every router area
  filter needs a matching `on.*.paths` entry or it's a dead trigger.

## Project policy

- **JIRA:** project AAASM; set the native **Components** field to the repo
  (`ai-agent-assembly/agent-assembly`) — it is the native `components` field, not
  `customfield_10041` (which is null; per the `.github` registry `jira` section /
  ADR 0014); Team (`customfield_10001`) = Pioneer.
  For **feature work**: Epic → Story → Subtask (one Subtask ≈ one commit) + a `Verify …` subtask per Story.
  For a **dedicated QA / verification Epic** (e.g. AAASM-4522 *user-smoke*, AAASM-5020
  *design-QA*): **one verification item = one Story directly under the Epic**
  (the `[Journey NN]` style) — no middle "checklist" Task, no Subtasks. Each such
  Story is verified by **operating the live product as a real user** (real running
  server, live API, real browser through the real login flow); CI / unit tests /
  mocked e2e (`page.route`, injected tokens) **never** substitute for real-user
  verification, even when they already cover the case. File a Bug only after
  reproducing through the genuine end-to-end path.
- **Self-hosted deployment is out of scope** product-wide — don't propose
  Helm/Terraform/air-gapped/migration work even if the spec mentions it.
- **The Protocol Specification stays in this monorepo** — do not move spec work to a
  separate `agent-assembly-spec` repo (that repo is archived by design).

## Documentation conventions — document the WHY, not the WHAT

Comments and docstrings exist to capture intent that the code cannot: rationale,
constraints, invariants, and non-obvious decisions. Restating what the code already
says is noise that rots out of sync — avoid it.

- **Crate / module (`//!`):** yes — its role in the architecture, key invariants,
  and which ADR 0033 element it implements. Do not write the superseded three-layer
  model into a new `//!`; forbidden design 1 names code comments explicitly.
- **Public items (`///` on `pub` fn/struct/trait):** yes — the contract: behavior,
  errors returned, units, side effects, and any threading/async/`unsafe`/ordering
  constraints. Especially the surprising ones (e.g. "built inside `run()` so both
  paths share it", "fail-closed on oversized input").
- **Inline `//` why-comments:** for workarounds, perf-sensitive code, security
  rationale, and version pins (the `Cargo.toml` pin comments are the gold standard —
  e.g. *why* a crate is pinned, not just that it is).
- **Skip:** private trivial helpers, getters, type-restating, and anything a reader
  infers from the signature. No per-variable docstrings.
- **Big architectural decisions → ADRs**, not scattered docstrings. Link code to the
  ADR. Design specs already live in `.ai/spec/` and `design/vN/` — reference them.

> Net: a new contributor (human or LLM) should be able to read a module's `//!` and
> a public item's `///` and understand *why it is the way it is* without reverse-
> engineering it. If a comment only says *what*, delete it.
