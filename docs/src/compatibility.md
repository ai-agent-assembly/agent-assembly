# Version Compatibility Matrix

This document tracks which versions of `aa-runtime` are compatible with each SDK version. Update this file whenever any component version changes — see [CI enforcement](#ci-enforcement) below.

> **CI enforcement for SDK version changes is pending cross-repo CI integration.** Until then, SDK version bumps must be accompanied by a manual update to this file.

<!-- AAASM-2526: normalized root LICENSE to canonical Apache-2.0 and removed the
     redundant `license-file` key from root Cargo.toml (kept the SPDX
     `license = "Apache-2.0"`). License-metadata only — no version change to
     aa-runtime or any SDK; this comment satisfies the compatibility-matrix CI gate. -->

<!-- AAASM-1602: workspace.exclude = ["node-sdk"] added to root Cargo.toml so
     the sibling `node-sdk/` checkout used by e2e_sdk_node tests doesn't get
     claimed by the agent-assembly workspace. No version change introduced
     by that PR; this comment satisfies the compatibility-matrix CI gate. -->

<!-- AAASM-2357: added the `aa-storage` crate to root Cargo.toml workspace
     members (pure-interface storage trait crate). It inherits the workspace
     version and introduces no version change to aa-runtime or any SDK; this
     comment satisfies the compatibility-matrix CI gate. -->

<!-- AAASM-2367: added the `aa-storage-memory` crate to root Cargo.toml
     workspace members (in-memory storage driver for tests / local dev). It
     inherits the workspace version and introduces no version change to
     aa-runtime or any SDK; this comment satisfies the compatibility-matrix
     CI gate. -->

<!-- AAASM-2379: added the `aa-cache` crate to root Cargo.toml workspace
     members (in-process L1 cache wrapper over the storage traits). It inherits
     the workspace version and introduces no version change to aa-runtime or any
     SDK; this comment satisfies the compatibility-matrix CI gate. -->

<!-- AAASM-2374: added the `aa-storage-sqlite-buffer` crate to root Cargo.toml
     workspace members (local SQLite event-buffer driver). It inherits the
     workspace version and introduces no version change to aa-runtime or any
     SDK; this comment satisfies the compatibility-matrix CI gate. -->

<!-- AAASM-2590: added the `aa-security` crate to root Cargo.toml workspace
     members (leaf crate owning the credential scanner, redaction, and
     audit-normalization primitives moved out of aa-core). It inherits the
     workspace version and introduces no version change to aa-runtime or any
     SDK; this comment satisfies the compatibility-matrix CI gate. -->


---

## Compatibility Matrix

| `aa-runtime` | Python SDK (`aa-ffi-python`) | Node.js SDK (`aa-ffi-node`) | Go SDK (`aa-ffi-go`) | Protocol Version |
|---|---|---|---|---|
| v0.0.1-alpha.1 | v0.0.1-alpha.1 (PyPI `0.0.1a1`) ✓ | v0.0.1-alpha.1 ✓ | v0.0.1-alpha.1 ✓ | protocol/v1 |
| v0.0.1-alpha.2 | v0.0.1-alpha.2 (PyPI `0.0.1a2`) ✓ | v0.0.1-alpha.2 ✓ | v0.0.1-alpha.2 ✓ | protocol/v1 |
| v0.0.1-alpha.3 | v0.0.1-alpha.3 (PyPI `0.0.1a3`) ✓ | v0.0.1-alpha.3 ✓ | v0.0.1-alpha.3 ✓ | protocol/v1 |
| v0.0.1 | v0.0.1 ✓ | v0.0.1 ✓ | v0.0.1 ✓ | protocol/v1 |

**Legend:**
- ✓ Compatible — fully supported
- ⚠️ Partial — works with known limitations (see notes)
- ✗ Incompatible — do not use together

---

## Minimum Supported Runtime Version per SDK

| SDK | Minimum `aa-runtime` Version |
|---|---|
| Python SDK (`aa-ffi-python`) v0.0.1 | aa-runtime v0.0.1 |
| Node.js SDK (`aa-ffi-node`) v0.0.1 | aa-runtime v0.0.1 |
| Go SDK (`aa-ffi-go`) v0.0.1 | aa-runtime v0.0.1 |

---

## Supported Protocol Versions per Runtime

A runtime version may support multiple protocol versions to allow SDK upgrades without simultaneous runtime upgrades.

| `aa-runtime` Version | Supported Protocol Versions |
|---|---|
| v0.0.1-alpha.1 | protocol/v1 |
| v0.0.1-alpha.2 | protocol/v1 |
| v0.0.1-alpha.3 | protocol/v1 |
| v0.0.1 | protocol/v1 |

---

## CI Enforcement

A CI check (`compat-matrix-check`) enforces that this file is updated whenever version-carrying files change in a pull request.

**Currently enforced (monorepo scope):**
- `Cargo.toml` (workspace root)
- `crates/*/Cargo.toml` (all crate manifests)

**Deferred — pending cross-repo CI integration:**
- `sdk/python/pyproject.toml` (Python SDK)
- `sdk/node/package.json` (Node.js SDK)
- `sdk/go/go.mod` (Go SDK)

Until cross-repo CI exists, SDK version bumps require a **manual update** to this file before merging.

---

## How to Update This File

When bumping a component version:

1. Add a new row to the [Compatibility Matrix](#compatibility-matrix) table for the new version combination.
2. Update the [Minimum Supported Runtime Version](#minimum-supported-runtime-version-per-sdk) table if the minimum changes.
3. Update the [Supported Protocol Versions](#supported-protocol-versions-per-runtime) table if the runtime adds or drops protocol version support.
4. Commit the change in the same PR as the version bump.

See [versioning.md](versioning.md) for the full versioning and deprecation policy.

---

## Workspace changes (non-version bumps)

| PR / Ticket | Change | Compatibility impact |
|---|---|---|
| AAASM-107 | Added `conformance` workspace crate (test infrastructure, not shipped) | None — internal tooling only |
| AAASM-39 | Added `aa-ebpf-common` workspace crate (shared eBPF types, not shipped standalone) | None — internal shared types only |
| AAASM-37  | Added `aa-ebpf-common` workspace crate (no_std shared eBPF event types, not shipped as a public API) | None — internal kernel/userspace bridge only |
| AAASM-39 (impl) | Added exec tracepoint BPF programs, ProcessLineageTracker, ShellDetector, ExecLoader in `aa-ebpf` | None — kernel-level monitoring, not a public API |
| AAASM-64 | Added `aa-ffi-go` workspace crate (Go C-ABI staticlib bindings) | None — new FFI crate, no existing API changes |
| AAASM-936 | Added `examples/aa-devtool-sample-myeditor` workspace crate (sample `DevToolAdapter` impl + plugin authoring reference; `publish = false`) | None — example only, not shipped, depends on existing `aa-core` API surface |
| AAASM-971 | Added `aa-devtool-codex` workspace crate (OpenAI Codex CLI `DevToolAdapter` implementation; `detect()` + `governance_level()` wired in this PR; `generate_managed_settings`, `apply_settings`, `build_launch_command` land in AAASM-978/983/988) | None — new adapter crate, no changes to existing public APIs |
| AAASM-204 | Added `aa-devtool-windsurf` workspace crate (`DevToolAdapter` for Windsurf Cascade; L2 governance via admin settings + MCP registry control; `publish = false`) | None — new adapter crate, no changes to existing public API surface |
| AAASM-997 | Added `aa-devtool-copilot` workspace crate (`DevToolAdapter` for GitHub Copilot — VS Code extension detection, `publish = false`); added `semver` v1 dependency for latest-version selection | None — new adapter crate, no changes to existing public API surface |
| AAASM-1006 | Implemented MCP governance in `aa-devtool-copilot`: `list_mcp_servers()` reads `chat.mcp.servers` from VS Code `settings.json`; `apply_mcp_governance()` filters the server set (keep allowed, remove denied) and sets `chat.mcp.requireApproval: "always"` when deny list is non-empty; `build_launch_command()` returns `LaunchFailed` (Copilot is IDE-resident, not CLI-launchable) | None — implementation only within existing `aa-devtool-copilot` crate; no new crates, no existing public API changes |
| AAASM-946 | Added `aa-devtool-claude-code` workspace crate (`ClaudeCodeAdapter` — detection layer for Claude Code CLI; `publish = false` pending AAASM-201 completion) | None — new crate, no existing API surface changed; depends on existing `aa-core::DevToolAdapter` trait |
| AAASM-918 | Added `aa-devtool-saas` workspace crate (SaaS coding-agent `DevToolAdapter` for Claude.ai, ChatGPT, Cursor cloud; L1Observe governance; HMAC-SHA256 webhook signature verification; MCP allowlist advisory overlay for Claude.ai; `publish = false`) | None — new adapter crate, no changes to existing public APIs |
| AAASM-205 | Added `aa-devtool` workspace crate (`DiscoveryService` + built-in adapters for Claude Code, Codex, GitHub Copilot, Windsurf) | None — new crate, no existing API changes; `aa-api` and `aa-cli` gain a new optional dependency on it |
| AAASM-949 | Added RBAC role enforcement on `POST /api/v1/policies`: `CallerRole` + `MutationKind` + `PolicyScopeKind` enums and `required_role_for()` in `aa-gateway/src/policy/rbac.rs`; `PolicyWriteAuth` extractor + `PolicyAuthorizationDenied` error in `aa-api/src/auth/policy_auth.rs`; optional `scope` field on `CreatePolicyRequest`; auto-generated `docs/src/policy-rbac.md` + `.ci/check-policy-rbac-doc.sh` | `POST /api/v1/policies` now requires authentication (401 when unauthenticated) and returns 403 when the caller's role is insufficient for the target scope; `CreatePolicyRequest` gains an optional `scope` field (defaults to `global`). Read-only endpoints unchanged. |
| AAASM-956 | Restored `aa-devtool`, `aa-devtool-claude-code`, `aa-devtool-codex`, `aa-devtool-saas`, and `aa-devtool-windsurf` to workspace `members` (dropped by a prior merge conflict resolution); implemented `apply_settings()` and `apply_mcp_governance()` in `aa-devtool-claude-code` via new `apply.rs` module (`SettingsPathResolver` trait, atomic write, unmanaged-key merge) | None — workspace member restoration only; `apply_settings`/`apply_mcp_governance` are internal adapter implementations with no changes to existing public API surfaces |
| AAASM-1206 | Added `[profile.release]` to workspace `Cargo.toml` (`opt-level="z"`, `lto=true`, `codegen-units=1`, `strip=true`, `panic="abort"`) — build profile change only, no version bump | None — affects binary size of release builds only; no API, protocol, or ABI changes |
| AAASM-1076 | Added `aa-topology-integration-tests` workspace crate (in-process end-to-end test harness for the topology pipeline; `publish = false`, dev-dependencies only) | None — test-only crate, no shipped artifacts; depends on existing `aa-api` / `aa-gateway` / `aa-runtime` public surfaces with no API changes |
| AAASM-1448 | Renamed `aa-topology-integration-tests` workspace crate to `aa-integration-tests` (in preparation for AAASM-1258 CLI subcommand coverage). Renamed `.github/workflows/topology-integration.yml` to `integration-tests.yml`. | None — test-only crate, no shipped artifacts; dev-dependencies only; no public API change |
| AAASM-1419 | Added `CallStackNode` proto message + `repeated CallStackNode call_stack = 28` field on `AuditEvent`; added `CallStackNode` to `aa-api` `ViolationPayload::Audit` (utoipa schema regenerated); wired through dashboard `useLiveOpsStream.mapEvent` | None on `protocol/v1` — non-breaking proto field addition (default empty). SDK regeneration for `aa-ffi-python` / `aa-ffi-node` / `aa-ffi-go` tracked as separate follow-up Tasks against this revision; older SDKs continue to interoperate (the new field is ignored on decode). |
| AAASM-2015 | Added `aa-sandbox` workspace crate (wasmtime + wasmtime-wasi host runtime scaffold for F116 ST-W tool-execution sandbox; doc-only modules `error`, `policy`, `runtime` — real WASI host wiring lands in AAASM-2017, fuel + memory-store limits in AAASM-2018) | None — new internal crate, no public API or protocol change; `aa-wasm` browser-target stub untouched |
| AAASM-2340 | Workspace prepared for crates.io publish via `cargo-workspaces` topological order. Per-crate `publish` flags set: publishable (default) for `aa-core`, `aa-proto`, `aa-runtime`, `aa-ebpf`, `aa-ebpf-common`, `aa-proxy`, `aa-sandbox`, `aa-gateway`, `aa-cli`; `publish = false` for all `aa-devtool*` (dev-tool subsystem held back from this alpha — not yet feature-complete), all `aa-ffi-*` + `aa-wasm` (SDK FFI scaffolding — each language SDK repo carries its own copy and ships via PyPI / npm / Go module proxy), and `aa-api` / `conformance` / `aa-integration-tests` / `examples/*` (cloud/enterprise consumers + workspace-internal tooling). All publishable crates' path-deps gained explicit `version = "0.0.1-alpha.3"` literals so `cargo publish` manifest verification passes. `release.yml` `publish-crate` job replaced with `publish-crates` (cargo-workspaces). Sibling content bundled into crate tarballs via `_embedded/` mirrors so `cargo install aasm` ships the full product — `aa-cli/_embedded/dashboard/dist/` (real SPA, not stub), `aa-proto/_embedded/proto/` (gRPC contract), `aa-ebpf/_embedded/aa-ebpf-probes/` (BPF source, compiled at install time when nightly + bpfel target are present, otherwise graceful stubs). New `aasm sandbox run` / `aasm sandbox info` subcommands expose the WASI tool-execution sandbox (highlight ④ of the product spec) to OSS users. Source tree keeps the full `aasm` surface including `run` and `tools`; the `.ci/strip-for-publish.sh` script removes the held-back `aa-devtool*` deps and the two consuming source files from the working tree right before `cargo workspaces publish` runs (driven by `strip-for-publish:begin` / `:end` markers in `aa-cli/Cargo.toml` and `aa-cli/src/commands/mod.rs`). Restores `cargo install aasm` as a supported install path. Resolves AAASM-2094 the right way (supersedes the closed AAASM-2338 / PR #840). | **Behavior delta** — published `aasm` binary on crates.io omits the `run` and `tools` subcommands. Local source builds (`cargo build -p aa-cli`) expose the full surface unchanged. To restore the subcommands on crates.io once dev-tool ships, remove the strip step from `release.yml` and flip the three `aa-devtool*` crates' `publish` flags. No public Rust API, protocol, or ABI changes; new `aasm sandbox` CLI surface is additive. At 0.x.y SemVer, internal crates carry no API stability commitment; READMEs note 'internal use only'. |
| AAASM-2343 | Bumped workspace + 22 path-dep version literals from `0.0.1-alpha.3` to `0.0.1-alpha.4`. Fourth pre-release in the v0.0.1 dry-run series. Verifies AAASM-2340 (cargo-workspaces topological publish — first `cargo install aasm` ever), AAASM-2339 (curl smoke channel gated with `if: false`), and AAASM-2336 (notify-downstream → node-sdk + python-sdk repository_dispatch, supersedes AAASM-2328 retry workaround). Companion python-sdk listener AAASM-2342 lands in the same release cycle. | None — pre-release version bump; AAASM-2340 behaviour delta (held-back `aasm run` / `aasm tools` on crates.io) carries forward unchanged. |
| AAASM-2461 | Bumped workspace + 22 path-dep version literals from `0.0.1-alpha.4` to `0.0.1-alpha.5`. Fifth pre-release in the v0.0.1 dry-run series. Validates the full release pipeline end-to-end with all alpha-4 recovery fixes baked in: AAASM-2346 (`cargo workspaces publish --allow-dirty`), AAASM-2455 / AAASM-2457 (smoke matrix restructure), AAASM-2456 (RUNBOOK + `release-readiness.sh` + per-channel aggregator), plus SDK companions node-sdk#67 (AAASM-2344) and python-sdk#74/#75/#76 (AAASM-2345 / AAASM-2459 / AAASM-2460). On crates.io, `aa-core` re-publishes at `0.0.1-alpha.5` alongside its existing `0.0.1-alpha.4` row from the partial alpha-4 publish; the other 8 crates publish for the first time. | None — pre-release version bump; AAASM-2340 behaviour delta (held-back `aasm run` / `aasm tools` on crates.io) carries forward unchanged. |
| AAASM-2372 | Added `aa-storage-redis` workspace crate (Redis L2 shared-cache driver implementing `SessionStore`, `RateLimitCounter`, and `PolicyStore` from `aa-core::storage`; `redis` 1.2 + `deadpool-redis` 0.23 pooling; `RateLimitCounter` uses an atomic Lua `INCRBY`+`EXPIRE` script). No version change. | None — new driver crate, no changes to existing public API surface. `xxhash-rust` BSL-1.0 (transitive via `redis`) is already allow-listed in `deny.toml`. |
| AAASM-2369 | Added `aa-storage-postgres` workspace crate (L3 primary PostgreSQL storage driver — ships sqlx migrations for the four MVP tables `orgs`/`agents`/`policies`/`audit_logs` and a `[storage.postgres]` connection-pool config; `publish = false` until the storage-driver subsystem is feature-complete). The `aa_core::storage` trait impls (`PgPolicyStore` / `PgAuditSink` / `PgCredentialStore` / `PgLifecycleStore`) land in AAASM-2370. No version change. | None — new internal driver crate; no existing public API, protocol, or ABI change |
| AAASM-2575 | Split the default `[profile.release]` into a fast build (`opt-level=2`, `lto="thin"`, `codegen-units=16`; `strip` + `panic="abort"` unchanged) and added a size-optimized `[profile.dist]` (inherits `release`; `opt-level="z"`, fat `lto`, `codegen-units=1`). `release.yml` now ships the binary with `--profile dist`. Build-profile change only, no version bump. | None — affects build speed and which profile produces the shipped binary; `dist` reproduces the previous size-optimized output. No API, protocol, or ABI change. |
| AAASM-2555 | Added a `[workspace.dependencies]` table to the root `Cargo.toml` centralizing third-party crates shared by ≥2 members, and converted those members to `dep = { workspace = true }` (single source of version truth). Pure manifest refactor — `Cargo.lock` byte-for-byte unchanged and `cargo tree -d` identical to the prior revision (108 duplicate nodes); no version bump. Single-member and intentionally-pinned crates (e.g. `rusqlite` per AAASM-2374) stay declared locally. | None — no version, protocol, or ABI change; resolved dependency graph is identical, so runtime behavior is unchanged |
| AAASM-2588 | Added `[profile.dev]` (`debug="line-tables-only"`) and `[profile.dev.package."*"]` (`opt-level=1`, `debug=false`) to tune dev/test build time, plus an opt-in (commented) `.cargo/config.toml` faster-linker template and a `CONTRIBUTING.md` section. Raised the `integration-tests` job `timeout-minutes` 20→30 to absorb the slightly heavier optimized-deps build. Build-config change only, no version bump. | None — affects local/CI build speed and dev-build debuginfo verbosity only; no API, protocol, or ABI change. |
| AAASM-2623 | Added `aa-sdk-client` workspace crate (Story AAASM-2570 — the shared, FFI-agnostic SDK runtime-client: UDS transport, IPC wire codec, `AssemblyClient` lifecycle, and advisory non-authoritative credential preflight, extracted from `aa-ffi-python`). Scaffold only in this PR (`publish = false` until AAASM-2559 makes the shared crates pinnable); modules land in AAASM-2624/2625/2626. `aa-ffi-python` is untouched — its migration onto this crate is AAASM-2561. | None — new internal crate, no existing public API, protocol, or ABI change |
