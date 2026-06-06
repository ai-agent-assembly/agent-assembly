# Verification Report — AAASM-2569

**Story:** ✅ (agent-assembly) SDK-bypass resistance test suite — *runtime enforcement cannot be bypassed*
**Epic:** AAASM-2552 — SDK security boundary + FFI consolidation (runtime is the enforcement authority)
**Component / repo:** `agent-assembly` (Rust monorepo)
**Verified at:** ST-3 (AAASM-2636), stacked on AAASM-2634 → AAASM-2635.

## Summary

This Story is the **proof obligation** for the runtime-enforcement gate (AAASM-2568,
merged). It proves that **a bypassed, malicious, or absent SDK cannot bypass runtime
enforcement**: every secret-bearing event is scanned and redacted at the trusted
boundary regardless of what the SDK did or claims.

The suite spans the two homes named in the Story, mapping cleanly to the
SDK-vs-runtime trust split:

- **`conformance/tests/credential_detection.rs`** — the `CredentialScanner` *primitive*
  that the runtime runs authoritatively: catches secrets hidden by nesting / unknown
  keys / surrounding text that a key-name-based banned-key strip would miss.
- **`aa-integration-tests/tests/e2e_secret_interception.rs` → `mod runtime_bypass`** —
  the *runtime boundary* itself, driving `aa_runtime::pipeline::enforcement::RuntimeScanner::enforce()`
  directly with crafted `EnrichedEvent`s.

Local results:

| Suite | Command | Result |
|---|---|---|
| Conformance | `cargo nextest run -p conformance` | **46 passed, 0 skipped** (42 existing + 4 new) |
| Integration | `cargo nextest run -p aa-integration-tests --test e2e_secret_interception` | **18 passed, 0 skipped** (12 existing + 6 new) |

## Implementation map

| Subtask | PR | Home | What |
|---|---|---|---|
| AAASM-2634 | #964 | `conformance/tests/credential_detection.rs` | `nested_json_secret_is_redacted`, `unknown_key_secret_is_redacted`, `embedded_in_surrounding_text_is_redacted`, `multiple_nested_secrets_all_redacted` |
| AAASM-2635 | #967 | `aa-integration-tests/tests/e2e_secret_interception.rs` (`mod runtime_bypass`) | the 5 runtime-boundary cases (6 tests) |
| AAASM-2636 | (this) | `verification-reports/` | full-suite run + this report |

## Story case → test mapping

| Story case | Test(s) | Boundary asserted |
|---|---|---|
| **1. Missing SDK scanner** | `runtime_bypass::missing_sdk_scanner_secret_is_redacted_at_runtime` | preflight-disabled SDK ships a raw secret → runtime redacts in place before forward/audit; findings surfaced (the signal a deny-on-credential policy keys off); the forward/audit path never carries the raw secret |
| **2. Forged "clean" assertion** | `runtime_bypass::forged_clean_label_is_ignored_and_rescanned` (behavioral) + `runtime_bypass::tool_call_detail_carries_no_trust_marker_field` (compile-time) | a `clean`/`prescanned` claim stuffed into the `labels` map is ignored and re-scanned; the exhaustive struct literal proves no honored trust marker exists on the wire |
| **3. Encoded / nested payload** | `runtime_bypass::nested_payload_in_tool_args_is_redacted_at_runtime` (boundary) + conformance `nested_json_secret_is_redacted`, `unknown_key_secret_is_redacted`, `embedded_in_surrounding_text_is_redacted`, `multiple_nested_secrets_all_redacted` (primitive) | secret nested / under unknown keys / embedded in surrounding text → runtime normalization (utf-8-lossy) + scan catches it; **raw-secret-absence** asserted, not label equality |
| **4. SDK absent entirely** | `runtime_bypass::cross_layer_parity_redacts_identically_regardless_of_source` | identical secret via `EventSource::{Sdk, Proxy, EBpf}` redacted byte-for-byte identically — removing the SDK never reduces enforcement |
| **5. Preflight-equivalence** | `runtime_bypass::preflight_equivalence_yields_identical_authoritative_outcome` | same payload ± a forged preflight label → identical `EnforcementOutcome` and identical redacted bytes |

## Acceptance criteria → evidence

### AC1 — All five cases pass and run in CI

- **Pass:** local results above (46 + 18). All five Story cases are covered (case 3 in
  both homes; case 2 in two complementary forms).
- **Run in CI:** the `Test` job runs `cargo nextest run --workspace --no-tests=pass --exclude aa-ebpf`
  (`.github/workflows/ci.yml`), which executes both `conformance` and `aa-integration-tests`.
  The `changes` router's `rust` filter matches both touched paths
  (`conformance/**` and `aa-*/**` → `aa-integration-tests/**`), so the rust jobs trigger
  on this Story's PRs.

### AC2 — Each case asserts raw-secret-absence at the trusted boundary (not SDK-reported status)

- Every runtime-boundary test reads back the post-`enforce()` `args_json` via
  `tool_args_text()` — i.e. exactly what the runtime would forward/audit — and asserts
  `!contains(<raw secret>)`. No test trusts an SDK-reported status: there is none on the
  wire (see AC3).
- Conformance tests assert `!ScanResult::redact(..).contains(<raw secret>)`. Per the known
  scanner-overlap quirk (one secret can trip several detectors), assertions are on
  **raw-secret-absence**, never finding-count or label equality.

### AC3 — Suite fails loudly if a future change reintroduces an SDK-honored trust marker or removes runtime scanning

- **No trust marker on the wire:** `proto/audit.proto` has no `clean` / `already_scanned` /
  pre-scanned field on `AuditEvent`, `ToolCallDetail`, `FileOpDetail`, or `ProcessExecDetail`.
- **Loud failure on reintroduction (compile-time):** `tool_call_detail_carries_no_trust_marker_field`
  builds `ToolCallDetail` with an **exhaustive struct literal** (no `..Default::default()`).
  Adding any field — e.g. a `bool already_scanned` — makes this test fail to compile, forcing triage.
- **Loud failure on honoring a marker (behavioral):** `forged_clean_label_is_ignored_and_rescanned`
  fails if the runtime ever starts honoring a `labels`-borne claim.
- **Loud failure on removing scanning:** every case asserts the secret is gone after
  `enforce()`; deleting or short-circuiting the runtime scan turns all five runtime-boundary
  tests red. `preflight_equivalence_*` additionally pins outcome-independence from SDK signals.

## Notes

- Case 1's "a deny-on-credential policy still denies" lives at the gateway `PolicyEngine`
  layer, already covered by the detection slice at the top of `e2e_secret_interception.rs`
  (`aws_access_key_in_tool_args_is_detected_and_redacted` et al.). This Story's runtime-boundary
  test asserts the runtime surfaces the findings a deny rule keys off and strips the raw secret
  before forward/audit — the gate's responsibility.
- The suite adds layers only; it changes no production code and removes nothing. The
  gateway banned-key sanitizer and the SDK advisory preflight are both untouched.
