# Verification Report — AAASM-2570

**Story:** ♻️ (agent-assembly) Extract `aa-sdk-client` (UDS/proto/lifecycle/event shipping + advisory preflight)
**Epic:** AAASM-2552 — SDK security boundary + FFI consolidation (Story 6 of 9)
**Component / repo:** `agent-assembly`
**Date:** 2026-06-06

## Summary

Created a new workspace crate, `aa-sdk-client`, as the single, FFI-agnostic home
for the SDK runtime-client logic that was previously reimplemented per language
(1,357 lines in `aa-ffi-python`; a separate 178-line reimplementation in
`node-sdk`). The crate owns the UDS transport, the IPC wire codec, the
`AssemblyClient` lifecycle, and event capture/shipping, plus an **advisory,
non-authoritative** credential preflight.

The work was delivered as 5 stacked subtasks, one PR each (all base `master`):

| Subtask | PR | Scope |
|---|---|---|
| AAASM-2623 | #954 | Scaffold the crate (manifest, lib root, workspace member, compat-matrix doc) |
| AAASM-2624 | #955 | Port socket config + IPC wire codec |
| AAASM-2625 | #956 | Port UDS transport / background IPC thread |
| AAASM-2626 | #957 | `AssemblyClient` lifecycle + event shipping + advisory preflight |
| AAASM-2627 | (this) | Acceptance tests + this report |

This change is **purely additive**. `aa-ffi-python` is untouched; rewiring the
Python/Node shims onto `aa-sdk-client` (and removing their duplicate copies) is
deliberately deferred to Stories 7–9 (AAASM-2560 / AAASM-2561 / AAASM-2562), per
the Epic's boundary-first gating. The runtime-enforcement gate (AAASM-2568) and
the `aa-security` extraction (AAASM-2567) are both already merged, so this
extraction was unblocked.

## Acceptance criteria

### AC1 — `aa-sdk-client` is the single implementation of the SDK transport/codec/lifecycle

**Met (as the canonical implementation).** The crate now contains the complete,
language-agnostic runtime-client: `config` (socket resolution), `codec` (wire
protocol, byte-compatible with `aa-runtime`'s codec), `ipc` (UDS background
thread), and `client` (`AssemblyClient` lifecycle + event shipping). The public
API (`AssemblyClient`, `AssemblyConfig`, `SdkClientError`, `Preflight`) is a
clean, `pyo3`/`napi`/`cgo`-free surface ready for thin shims to wrap. The actual
migration of the existing shims onto this crate is tracked by AAASM-2561 (Python)
/ AAASM-2560 (Node) / AAASM-2562 (remove fat bindings) — until those land the old
copies coexist, by design.

### AC2 — Preflight is advisory only; no path makes it authoritative and no trust marker is emitted

**Met.**
- `preflight.rs` is documented as non-authoritative and only ever *removes* data
  (redacts); it never adds a `clean` / `already_scanned` / pre-scanned signal.
- The `preflight` cargo feature (default on) gates the entire `aa-security`
  dependency: `--no-default-features` drops it and events still ship, proving the
  runtime — not the SDK — is the authority.
- Test `advisory_preflight_redacts_and_emits_no_trust_marker`
  (`tests/advisory_preflight_no_marker.rs`) asserts the shipped `AuditEvent`
  carries exactly two labels (`event_type`, `details`) and none of
  `clean` / `scanned` / `already_scanned` / `preflight` / `__aa_scanned__` /
  `__aa_clean__`.
- Test `preflight_disabled_passes_text_through_without_marker`
  (`tests/preflight_disabled_passthrough.rs`) confirms that with preflight
  disabled raw text passes through locally and still no marker is attached.

### AC3 — The crate builds standalone and is ready for the thin Node/Python shims to depend on

**Met (in-workspace).** `cargo build -p aa-sdk-client` and
`cargo build -p aa-sdk-client --no-default-features` both succeed. The crate
exposes a minimal, FFI-agnostic Rust API returning `Result<_, SdkClientError>`
(no language-runtime coupling), which is exactly what the shims wrap. Making the
crate consumable from an **external** checkout (git-SHA pin / publish) is the
separate Story AAASM-2559.

## Tests

`cargo nextest run -p aa-sdk-client`

- Default features: **26 passed, 0 skipped** (incl. 3 integration tests).
- `--no-default-features`: **20 passed, 0 skipped** (preflight-gated tests excluded; the e2e lifecycle test still runs).

Integration tests (`aa-sdk-client/tests/`):

| File | Asserts |
|---|---|
| `advisory_preflight_no_marker.rs` | redaction happens locally; no trust marker on the wire; only expected labels present |
| `preflight_disabled_passthrough.rs` | preflight optional; disabled ⇒ raw passes through locally, still no marker |
| `lifecycle_e2e.rs` | full session vs a mock `UnixListener`: connect → heartbeat → report event → shutdown |

## Quality gates

- `cargo fmt --all -- --check` — clean
- `cargo clippy -p aa-sdk-client --all-targets --all-features -- -D warnings` — clean
- `cargo clippy -p aa-sdk-client --all-targets --no-default-features -- -D warnings` — clean
- `cargo deny check` — advisories / bans / licenses / sources ok
- `cargo doc --workspace --no-deps` — builds
- `compat-matrix-check` — satisfied via the `docs/src/compatibility.md` row added in AAASM-2623

## Follow-ups (out of scope here)

- AAASM-2559 — make the shared crates pinnable/publishable for external SDK repos.
- AAASM-2560 / AAASM-2561 — thin Node / Python shims on `aa-sdk-client`.
- AAASM-2562 — remove the fat `aa-ffi-*` runtime-client copies from the workspace.
