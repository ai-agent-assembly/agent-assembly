# AAASM-2363 — In-memory aa-storage driver Acceptance Verification

| | |
|---|---|
| **Story** | [AAASM-2363](https://lightning-dust-mite.atlassian.net/browse/AAASM-2363) — in-memory `aa-storage` driver for tests / local dev |
| **Epic** | [AAASM-2348](https://lightning-dust-mite.atlassian.net/browse/AAASM-2348) — OSS concrete storage drivers |
| **Verifier** | Automated via `aa-storage-memory/tests/{conformance,integration}.rs` (AAASM-2368) |
| **Date** | 2026-06-03 |
| **Commit** | This PR's HEAD, rebased onto `master` after the AAASM-2367 implementation (PR #882) merged |

---

## Implementation PR verified

| PR | Sub-ticket | Scope |
|---|---|---|
| [#882](https://github.com/AI-agent-assembly/agent-assembly/pull/882) | AAASM-2367 | `aa-storage-memory` crate (six DashMap/parking_lot impls) + 5 shared conformance harnesses in `aa-core` |

## Design alignment

The OSS storage **driver registry** (`aa_storage::Registry`, factory traits, `StorageConfig`, `register_builtin_drivers`) is owned by **AAASM-2361 (PR #876)**, and sibling driver crates (e.g. `aa-storage-redis`, PR #879) ship only their concrete stores without adding a registry or registering themselves. `aa-storage-memory` follows that same pattern: it provides the six `Memory*` stores and is tested directly; binding the driver name `"memory"` into the registry and booting from `agent-assembly.toml` is the registry/boot layer's job (see deferred ACs below).

---

## AC bullets

| # | Bullet | Evidence | Status |
|---|---|---|---|
| 1 | `aa-storage-memory` ships impls for all six traits | `MemoryPolicyStore`, `MemoryAuditSink`, `MemorySessionStore`, `MemoryCredentialStore`, `MemoryRateLimitCounter`, `MemoryLifecycleStore`; six `*_conformance` tests pass through `&dyn _` | ✅ PASS |
| 2 | Registers itself with the storage registry as `name = "memory"` | Registry + factory live in PR #876; per the established sibling pattern (redis #879) the driver crate does **not** self-register. Binding `"memory"` into `aa_storage::Registry` is boot/registry wiring | ⚠️ DEFERRED¹ |
| 3 | Trait-conformance suite passes against the memory driver | `cargo nextest run -p aa-storage-memory` → 7 passed, 0 skipped (6 conformance + 1 integration) | ✅ PASS |
| 4 | Zero external deps beyond `dashmap`, `parking_lot`, `aa-storage`, `aa-core` | `cargo tree -p aa-storage-memory -e normal --depth 1` → exactly those four + `async-trait` | ✅ PASS² |
| 5 | All-memory `agent-assembly.toml` boots end-to-end and serves a policy lookup | All-memory wiring verified at the crate level by `all_memory_lifecycle_policy_and_audit_round_trip`. The TOML boot path itself is registry/CLI wiring | ⚠️ DEFERRED¹ |

¹ Both AC #2 (name registration) and AC #5 (TOML boot) depend on the `aa_storage::Registry` + `StorageConfig` infra from PR #876 and the boot dispatch that resolves a configured driver name through it. Tracked as follow-up subtask **AAASM-2464** under this Story.

² `async-trait` is a required proc-macro: the six storage traits are declared `#[async_trait]`, so any implementor must depend on it. No `sqlx`/`redis`/server runtime crates are pulled in. `tokio` is a dev-dependency only (test runtime).

**Result:** 3 / 5 ACs fully verified (driver impls, conformance suite, minimal deps); AC #2 and AC #5 deferred to AAASM-2464, which carries the registry/config infra. No bugs found in the driver.

---

## Verification commands

```bash
cd agent-assembly
cargo nextest run -p aa-storage-memory               # 7 passed, 0 skipped
cargo tree -p aa-storage-memory -e normal --depth 1  # aa-core, aa-storage, async-trait, dashmap, parking_lot
```

Output (summaries):

```
Summary 7 tests run: 7 passed, 0 skipped

aa-storage-memory v0.0.1-alpha.5
├── aa-core v0.0.1-alpha.5
├── aa-storage v0.0.1-alpha.5
├── async-trait v0.1.89 (proc-macro)
├── dashmap v6.2.1
└── parking_lot v0.12.5
```
