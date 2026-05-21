# AAASM-1575 — E17 S-A Acceptance Verification

| | |
|---|---|
| **Story** | [AAASM-1575](https://lightning-dust-mite.atlassian.net/browse/AAASM-1575) — GatewayConfig deployment mode config schema |
| **Epic** | [AAASM-1568](https://lightning-dust-mite.atlassian.net/browse/AAASM-1568) — Gateway Deployment Architecture |
| **Verifier** | Automated via `aa-core/tests/config_acceptance.rs` |
| **Date** | 2026-05-21 |
| **Commit** | This PR's HEAD |

---

## Implementation PRs verified

| PR | Sub-ticket | Scope |
|---|---|---|
| [#643](https://github.com/AI-agent-assembly/agent-assembly/pull/643) | AAASM-1689 | `DeploymentMode` enum + config module scaffold |
| [#645](https://github.com/AI-agent-assembly/agent-assembly/pull/645) | AAASM-1690 | Sub-structs (`LocalModeConfig` / `RemoteModeConfig` / `TlsConfig` / `AgentConnectConfig`) |
| [#648](https://github.com/AI-agent-assembly/agent-assembly/pull/648) | AAASM-1691 | `GatewayConfig` + YAML loader + `~` expansion |
| [#649](https://github.com/AI-agent-assembly/agent-assembly/pull/649) | AAASM-1692 | Env-var override layer + invalid-value errors |

---

## AC bullets

| # | Bullet | Test | Status |
|---|---|---|---|
| 1 | `DeploymentMode` enum exported from `aa-core::config` | `ac_1_deployment_mode_exported_from_config_module` | ✅ PASS |
| 2 | `GatewayConfig` can be deserialised from a valid YAML string via `serde_yaml` | `ac_2_full_epic_example_yaml_round_trips` | ✅ PASS |
| 3 | Missing YAML file → defaults used; no error | `ac_3_missing_yaml_file_returns_default` | ✅ PASS |
| 4 | `AA_MODE=remote` env var overrides `mode: local` in the YAML | `ac_4_aa_mode_env_overrides_yaml_mode` | ✅ PASS |
| 5 | `AAASM_DATABASE_URL` env var overrides `remote.database_url` in YAML | `ac_5_aasm_database_url_env_overrides_yaml_value` | ✅ PASS |
| 6 | `~` in `storage_path` expanded to the actual home directory | `ac_6_tilde_in_storage_path_expanded_to_real_home` | ✅ PASS |
| 7 | Invalid `AA_MODE` value (`AA_MODE=foobar`) → startup fails with clear error message | `ac_7_invalid_aa_mode_returns_clear_error` | ✅ PASS |
| 8 | `cargo nextest run -p aa-core config::tests` green | `cargo nextest run -p aa-core --all-features` — 219 passed, 0 skipped | ✅ PASS |

All 8 bullets verified.

---

## Verification commands

```bash
cd agent-assembly
cargo nextest run -p aa-core --all-features          # 219 passed, 0 skipped
cargo clippy --all-targets --all-features -- -D warnings  # clean
cargo fmt --all -- --check                            # clean
```

Output (truncated to the summary line):

```
Summary [0.157s] 219 tests run: 219 passed, 0 skipped
```

---

## Deviations from the Story description

None blocking.

Two minor adjustments worth noting for the record:

1. **`expand_paths` helper split.** The Story description specifies a single
   `expand_paths(&mut self)` method. The implementation in AAASM-1691 ships
   that method plus a `pub(crate) expand_paths_in(&mut self, home: &Path)`
   helper used by the unit tests to inject a fixed home directory so
   assertions stay deterministic across CI runners with different `$HOME`
   values. The public API matches the Story exactly.
2. **`apply_env_overrides_with` injection.** Similar story for the env-var
   layer — the public `apply_env_overrides()` matches the Story signature.
   An internal `pub(crate) apply_env_overrides_with(get_env: impl Fn)` lets
   tests pass a HashMap-backed mock environment instead of mutating process
   env vars in parallel.

Neither change adds new public surface; both are testability refinements.

---

## Follow-up bugs / sub-tasks

None filed. All 8 AC bullets pass on first run against the merged sub-tickets.

---

## Next steps

- Land #649 (AAASM-1692) → #648 → #645 → #643 in stacked-PR order, then merge
  this verification PR.
- Close AAASM-1689..1693 → AAASM-1575 → consider parent Epic AAASM-1568 ready
  for the next Story (S-B local-mode bootstrap).
