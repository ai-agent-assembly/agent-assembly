# Verification Report — AAASM-2567

**Story:** ♻️ (agent-assembly): Extract `aa-security` crate (scanner/redaction/normalization out of `aa-core`)
**Epic:** AAASM-2552 — SDK security boundary + FFI consolidation
**Implementation subtasks:** AAASM-2590 (create crate + move) → PR #916; AAASM-2591 (repoint consumers) → PR #921
**Verification subtask:** AAASM-2592 (this report)
**Branch state verified:** combined `AAASM-2590` + `AAASM-2591` (stacked, base `master`)

---

## Acceptance criteria

### AC1 — `aa-security` owns scanner + redaction + normalization; `aa-core` holds only wire types/traits (with a temporary compat re-export)

**PASS.**

`aa-security` now owns the primitives:

```
$ ls aa-security/src/
lib.rs   redaction.rs   scanner.rs

$ grep -nE "pub use" aa-security/src/lib.rs
21: pub use redaction::Redaction;
22: pub use scanner::{CredentialFinding, CredentialKind, CredentialScanner, ScanResult, ScannerConfig};
```

`aa-core` keeps only temporary migration re-exports (no security logic of its own):

```
$ grep -nE "pub use aa_security" aa-core/src/lib.rs aa-core/src/audit.rs
aa-core/src/lib.rs:44:   pub use aa_security::scanner;     # keeps aa_core::scanner::… + aa_core::CredentialScanner resolving
aa-core/src/audit.rs:199: pub use aa_security::Redaction;  # keeps aa_core::Redaction / aa_core::audit::Redaction resolving
```

`aa-core/src/scanner.rs` no longer exists (moved); `aho-corasick` was dropped from `aa-core`'s dependencies along with the scanner.

### AC2 — `aa-runtime`/`aa-gateway`/`aa-proxy`/`aa-sdk-client` depend on `aa-security` directly; `aa-security` is a leaf

**PASS** (for the consumers that exist today).

`aa-security` is a **leaf** — its forward dependency graph contains no `aa-core`:

```
$ cargo tree -p aa-security --all-features -e normal
aa-security v0.0.1-alpha.5
├── aho-corasick v1.1.4
│   └── memchr v2.8.0
└── serde v1.0.228
    └── …
# no aa-core anywhere → leaf invariant holds
```

The dependency edge is one-way (`aa-core → aa-security`, no cycle):

```
$ cargo tree -p aa-core --all-features -e normal -i aa-security
aa-security v0.0.1-alpha.5
└── aa-core v0.0.1-alpha.5
```

Every real consumer declares a direct `aa-security` dependency and imports from it:

| Crate | direct `aa-security` dep | imports `aa_security::…` |
|---|---|---|
| `aa-gateway` | ✔ (`serde`) | engine, alerts, audit, policy_service |
| `aa-proxy` | ✔ (`serde`) | audit_jsonl, intercept |
| `aa-api` | ✔ (`serde`) | alerts/store, routes/audit |
| `aa-cli` | ✔ (`serde`) | audit/models |
| `aa-ffi-python` | ✔ | handle |
| `conformance` | ✔ (dev) | tests/credential_detection |
| `aa-integration-tests` | ✔ (dev) | e2e_secret_interception, cli_audit_compliance_export |

> `aa-runtime` and `aa-sdk-client` are **not** repointed: `aa-runtime` does not consume the scanner yet (runtime enforcement is the gated Story AAASM-2568) and `aa-sdk-client` does not exist yet (Story AAASM-2566). The temporary `aa-core` re-export remains for migration compatibility, exactly as the AC requires.

### AC3 — `conformance/tests/credential_detection.rs` passes against `aa-security`; full workspace builds; `cargo deny check` clean

**PASS.**

```
$ cargo build --workspace
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 22s

$ cargo nextest run -p conformance --test credential_detection
    Starting 4 tests across 1 binary
        PASS all_vectors_have_correct_finding_kinds
        PASS all_vectors_have_correct_finding_offsets
        PASS all_vectors_redact_correctly
        PASS all_vectors_have_correct_finding_count
     Summary [0.016s] 4 tests run: 4 passed, 0 skipped

$ cargo deny check
    advisories ok, bans ok, licenses ok, sources ok
```

---

## Additional validation (beyond the AC)

| Check | Result |
|---|---|
| `cargo clippy --all-targets --all-features -- -D warnings` (workspace) | clean |
| `cargo fmt --all -- --check` | clean |
| `cargo doc --workspace --no-deps` | builds (only pre-existing `aa-cli`/`aa-api` warnings) |
| `cargo nextest run -p aa-core -p aa-security --all-features` | 264 passed |
| `cargo nextest run -p conformance -p aa-proxy -p aa-cli -p aa-gateway --all-features` | 1823 passed, 3 skipped |
| Scanner unit tests (moved to `aa-security`) | 49 passed |
| `aa-core` redaction/hash-chain tests (against the re-export) | passed |

---

## Defects found & resolved during verification

1. **Benchmark CI job referenced the old bench location** — `.github/workflows/ci.yml` still ran `cargo bench -p aa-core --bench scanner_bench`, but the bench moved to `aa-security`. Fixed in the AAASM-2590 PR (`🔧 (ci): Point scanner_bench at aa-security after the move`) rather than filing a separate bug subtask, since it is a direct consequence of the move within that subtask's scope.

## Known-flaky (not a regression)

- `aa-gateway storage::migrations::tests::apply_good_succeeds_and_is_idempotent_on_postgres` failed once on PR #916's `Test` job with *"failed to start postgres testcontainer (is Docker running?) … PullImage … bytes remaining on stream"* — a Docker image-pull infra flake, unrelated to this change (the test exercises Postgres migrations, not the scanner). Resolution: re-run the job.

---

## Conclusion

All three acceptance criteria are satisfied. `aa-security` is an independently-reviewable leaf crate owning the scanner, redaction, and normalization primitives; `aa-core` retains only temporary compat re-exports; the real consumers depend on `aa-security` directly; the conformance vectors pass, the workspace builds, and `cargo deny` is clean. **AAASM-2567 verified.**
