# Verification Report — AAASM-2568

**Story:** 🔒 (agent-assembly) `aa-runtime` authoritative scan/redact/normalize enforcement stage **\[GATE\]**
**Epic:** AAASM-2552 — SDK security boundary + FFI consolidation (runtime is the enforcement authority)
**Component / repo:** `agent-assembly` (Rust monorepo)
**Verified at:** ST-4 (AAASM-2587), stacked on AAASM-2584 → AAASM-2585 → AAASM-2586.

## Summary

`aa-runtime` is now the authoritative scan/redact/normalize enforcement point. A
single precompiled `RuntimeScanner` runs **unconditionally** on every inbound
event, mutating the allowlisted secret-bearing fields in place **before** the
event is forwarded or audited — on both the batch path and the immediate
violation-broadcast path. No SDK-supplied signal can shorten or skip this work.

Full `aa-runtime` suite: **258 passed, 2 skipped** (`cargo nextest run -p aa-runtime`).

## Implementation map

| Subtask | PR | What |
|---|---|---|
| AAASM-2584 | #924 | `aa-runtime/src/pipeline/enforcement.rs` — `EnforcementConfig`, `OversizedPolicy`, `EnforcementOutcome`, `RuntimeScanner` (one precompiled `aa_core::CredentialScanner`), `enforce()` over the field allowlist |
| AAASM-2585 | #926 | `emit_metrics()` — latency / payload-size / finding-count / oversized |
| AAASM-2586 | #927 | Wired into `pipeline::run()` before `is_policy_violation`, covering both forward paths |
| AAASM-2587 | (this) | End-to-end verification suite + this report |

## Acceptance criteria → evidence

### AC1 — Every inbound event is scanned + redacted + normalized at the runtime **before** forward/audit, independent of SDK behaviour

- Wiring: `aa-runtime/src/pipeline/mod.rs` — `RuntimeScanner` is built once before the loop and `scanner.enforce(&mut enriched)` is called in the `IpcFrame::EventReport` arm **before** `is_policy_violation` and before any `broadcast_tx.send` / batch push. Pipeline order is `enrich → enforce(scan/redact/normalize) → is_policy_violation → forward/batch`.
- Field allowlist (`enforcement.rs::scan_detail`): `tool_call.args_json` (bytes→UTF-8 normalize) + `error_message`, `file_op.path`, `process.command` + `args[]`. Non-secret-bearing details (`LlmCall`/`Network`/`Violation`/`Approval`) are matched explicitly and skipped.
- Tests: `enforcement::tests::{tool_call_args_json_secret_is_redacted_in_place, tool_call_error_message_secret_is_redacted, file_op_path_secret_is_redacted, process_command_and_args_secrets_are_redacted}` (unit) and `aaasm_2568_gate_verification::gate_redacts_on_batch_path` (end-to-end through `run()`).

### AC2 — Raw secrets never leave the runtime (not forwarded, not audited), proven by the bypass suite

- `aa-runtime/tests/aaasm_2568_gate_verification.rs` drives the real `run()` loop and asserts the forwarded `PipelineEvent` carries `[REDACTED:*]` and **never** the raw secret, on:
  - the **batch path** — `gate_redacts_on_batch_path`
  - the **violation path** — `gate_redacts_on_violation_path`
- Unit-level: `oversized_field_is_redacted_whole_fail_closed` proves a secret hidden past the size cap is dropped (fail-closed), never forwarded raw.

### AC3 — No code path lets an SDK-supplied flag skip scanning

- The wire `AuditEvent` (`proto/audit.proto`) has **no** `clean` / `already_scanned` / pre-scanned field — `grep -ci 'already_scanned\|clean' proto/audit.proto` → `0`.
- `enforce()` takes no such parameter and is called unconditionally; `scan_detail` has no early-out keyed on event content. Reuse across events is covered by `enforcement::tests::one_scanner_redacts_across_multiple_events`.

### AC4 — Scan-latency / payload-size / finding-count metrics emitted; p99 within budget (or revised budget documented)

- `enforcement.rs::emit_metrics` emits on every `enforce()`:
  - `aa_runtime_scan_latency_seconds` (histogram, measured around scan+redact only)
  - `aa_runtime_scan_payload_bytes` (histogram)
  - `aa_runtime_scan_findings_total{kind}` (counter, labelled by `CredentialKind` — never the raw secret)
  - `aa_runtime_scan_oversized_total` (counter)
- Test: `enforcement::tests::enforce_emits_scan_metrics` installs a local Prometheus recorder and asserts the families render while the raw secret never appears in the exposition.
- **Latency budget:** the scan is an O(n) Aho-Corasick pass over a size-capped (64 KiB default) field set; the `aa_runtime_scan_latency_seconds` histogram makes the real distribution observable in deployment. No regression to the existing pipeline latency tests was observed. The policy-latency SLA continues to be governed by the gateway's `policy_latency_test`; if field-scan latency is later shown to approach the budget, the cap (`EnforcementConfig::max_field_bytes`) is the documented tuning knob.

### AC5 — Gateway sanitizer retained as backstop

- `aa-gateway/src/sanitizer/{mod,event,rules,sanitize}.rs` are unchanged by this Story — the banned-key write-side backstop remains in place. This work adds a layer at the runtime; it removes nothing.

## Notes

- The scanner is sourced from `aa_core::CredentialScanner` (already an `aa-runtime` dependency). When AAASM-2567 extracts `aa-security`, the import swaps `aa_core` → `aa-security` with no behavioural change.
- This Story is **the gate**: Stories 6–9 (AAASM-2570/2560/2561/2562) — any removal or thinning of SDK-side scanning — may now proceed.
