# AAASM-2358 — Verify `aa-storage` trait crate acceptance criteria

Parent Story: **AAASM-2354** · Epic: **AAASM-2347** · Implementation: **AAASM-2357** (PR #851)
Verified against branch `v0.0.1/AAASM-2358/test/verify_aa_storage_acs` (stacked on the impl branch).

## Acceptance criteria results

| # | Acceptance criterion | Result | Evidence |
|---|---|---|---|
| 1 | `aa-storage` compiles standalone with **no backend dependencies** | ✅ Pass | `cargo tree -p aa-storage -e normal` shows only `aa-core`, `async-trait`, `thiserror` as direct deps. No `sqlx`, `redis`, or `tonic`. |
| 2 | All six traits documented with rustdoc examples + runnable conformance stub | ✅ Pass | 7 doctests pass (`cargo test -p aa-storage --doc`); `conformance::assert_policy_store_conformance` + `tests/conformance.rs` run green. |
| 3 | `cargo deny check` passes | ✅ Pass | `advisories ok, bans ok, licenses ok, sources ok`. |
| 4 | Re-exported under `aa_core::storage::*` so call sites import from one path | ⚠️ **Infeasible — see finding** | Cargo dependency cycle; single import path delivered via `aa_storage::*` instead. Bug subtask filed. |
| 5 | Trait-conformance stub can be parameterized by a `dyn PolicyStore` | ✅ Pass | `tests/conformance.rs` passes `&MemoryPolicyStore` as `&dyn PolicyStore`; `tests/object_safety.rs` constructs `Box<dyn _>` for all six traits. |

## Commands run

```
cargo check -p aa-storage                              # clean
cargo deny check                                       # advisories/bans/licenses/sources ok
cargo test -p aa-storage                               # 1 conformance + 1 object-safety + 7 doctests pass
cargo doc -p aa-storage --no-deps                      # renders six trait pages
cargo tree -p aa-storage -e normal                     # only aa-core/async-trait/thiserror direct
```

`target/doc/aa_storage/` renders all six trait pages:
`trait.PolicyStore.html`, `trait.AuditSink.html`, `trait.SessionStore.html`,
`trait.CredentialStore.html`, `trait.RateLimitCounter.html`, `trait.LifecycleStore.html`.

## Finding — AC #4 `aa_core::storage::*` re-export is infeasible (Cargo cycle)

The traits use the **concrete** shared types from `aa-core` (`get_policy(&AgentId) -> PolicyDocument`,
`emit(AuditEntry)`, …), so `aa-storage` must depend on `aa-core`. Re-exporting the traits back out of
`aa-core` as `aa_core::storage::*` would make `aa-core` depend on `aa-storage`, forming a cycle
`aa-storage → aa-core → aa-storage`, which Cargo rejects.

This is a contradiction inside the Story's own ACs (concrete-types vs. re-export-from-aa-core), not an
implementation defect. The single-import-path intent is satisfied via **`aa_storage::*`**, which
re-exports `AgentId`, `SessionId`, `PolicyDocument`, and `AuditEntry` alongside the six traits, so call
sites import the contract and its types from one path. The chosen layering keeps the concrete signatures
the downstream Postgres/Redis/Enterprise drivers (Epic B/E) need.

Filed as a Bug subtask under AAASM-2354 per this ticket's instruction #4 (do not patch silently).

## Conclusion

All implementable ACs pass. The lone exception (AC #4) is infeasible-by-cycle and recorded as a Bug
subtask with the agreed resolution (`aa_storage::*` as the single import path). No code defects found.
