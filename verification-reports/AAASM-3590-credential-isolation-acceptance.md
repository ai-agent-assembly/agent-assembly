# Verification Report — AAASM-3590

**Story:** AAASM-3562 — 🔒 (aa-proxy) Credential isolation & egress allowlist — agents never see real provider keys
**Verification subtask:** AAASM-3590
**Date:** 2026-06-23
**Branch:** `v0.0.1/AAASM-3562/proxy_credential_isolation`
**Scope:** crate `aa-proxy` at the Story's integrated tip
**Verifier:** Claude Code

## Summary

All three Story acceptance criteria are verified GREEN against the integrated
change set, and the full `aa-proxy` quality suite passes. No gaps found; no Bug
subtasks filed.

## Acceptance criteria

### AC1 — An agent can never read a real provider credential

**Verified.** Defended by:

- `aa-proxy/src/credentials.rs` — `CredentialStore` holds keys in a zeroizing,
  non-`Debug`/non-`Display` `Secret`; loaded only from `AA_PROXY_PROVIDER_KEYS`,
  never from agent input.
- `aa-proxy/src/proxy/http.rs::serialize_http_request_with_auth` +
  `aa-proxy/src/proxy/mod.rs::handle_llm_mitm` — the real `Authorization` is
  injected at EGRESS only; the agent's own `Authorization`/`x-api-key` are
  stripped, so the agent runtime never receives a real key.

Executable proof:
`attacker::credential_heist_agent_never_sees_real_key_and_upstream_gets_injected`
drives CONNECT → TLS MitM → in-tunnel request against a TLS mock upstream and
asserts (a) the upstream received `Bearer sk-REAL-…` (the injected key, not the
agent's bogus one), and (b) the real key never appears in any client-visible
response byte. `attacker::proxy_never_echoes_configured_key_to_the_client`
re-confirms (b) on a normal allowed request.

### AC2 — Any non-allowlisted egress is rejected even when the agent forges host/headers

**Verified.** Defended by
`aa-proxy/src/proxy/mod.rs::in_tunnel_deny_reason` /
`effective_request_host`, wired into both `handle_llm_mitm` and
`handle_non_llm_with_gateway`: the egress allowlist is re-checked against the
in-tunnel `Host` / absolute request target after TLS MitM, not just the CONNECT
line.

Executable proof:
`attacker::forged_in_tunnel_host_is_rejected_and_evil_host_never_dialed` —
CONNECT to the allowlisted `api.openai.com`, then forge
`Host: evil.attacker.com`; asserts a 403 to the client and that the mock
upstream is never dialed. This test was confirmed **load-bearing**: with the
`in_tunnel_deny_reason` guard disabled it fails (the forged request reaches the
upstream and a 200 is returned).

### AC3 — A forced crash / core dump contains no plaintext secret

**Verified (by construction + unit checks).** Defended by:

- `aa-proxy/src/hardening.rs::harden_process` — `prctl(PR_SET_DUMPABLE, 0)` on
  Linux, called early in `crate::run` before any credential is loaded, so a
  crash produces no core dump and same-uid processes cannot ptrace. No-op off
  Linux (macOS dev path stays buildable).
- `aa-proxy/src/credentials.rs` — `mlock` of the secret pages (best-effort,
  `#[cfg(unix)]`) keeps plaintext out of swap; `zeroize` on drop bounds the
  in-RAM lifetime.

Unit proof: `hardening::tests::harden_process_does_not_panic_and_reports_outcome`
(on Linux asserts `/proc/self/status` shows non-dumpable),
`credentials::tests::mlocked_secret_constructs_and_exposes_without_leaking`,
`credentials::tests::dropping_secret_runs_zeroize_on_its_buffer`,
`credentials::tests::debug_never_contains_key_material`.

Note: `PR_SET_DUMPABLE`/`mlock` are Linux/Unix syscalls. This verification ran
on macOS (the Linux-specific paths are no-ops there); their effect is asserted
on Linux CI via the `/proc/self/status` check above.

## Quality suite (aa-proxy)

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt -p aa-proxy -- --check` | PASS (exit 0) |
| Lint | `cargo clippy -p aa-proxy --all-targets -- -D warnings` | PASS (no warnings) |
| Tests | `cargo nextest run -p aa-proxy` | PASS — 135 run, 0 failed, 3 skipped |
| Supply chain | `cargo deny check` | PASS — advisories/bans/licenses/sources ok |

## TTL & rotation (AAASM-3586)

`CredentialStore::rotate(host, new_secret, ttl)` swaps a credential in place
(old secret zeroized) and expired entries are refused at injection time —
verified by `credentials::tests::{expired_entry_is_not_injected,
rotate_replaces_secret_and_serves_the_new_one,
rotate_installs_credential_for_a_new_host}`. Dynamic Vault leasing is documented
as out of OSS scope (relates AAASM-242); the rotation hook is the seam the
enterprise plane drives.

## Conclusion

All acceptance criteria hold; the attacker scenarios in the Story description are
closed and regression-guarded. No gaps; no Bug subtasks required.
