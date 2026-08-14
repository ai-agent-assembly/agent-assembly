# AAASM-3561 — eBPF bytecode integrity, least-privilege & unified policy source

Verification of the three Story acceptance criteria across the implemented
subtasks (AAASM-3601 … AAASM-3609). Final acceptance subtask: AAASM-3610.

Environment note: development + validation ran on macOS. eBPF is Linux-only;
the kernel-load, daemon, and capability paths are implemented and
`cargo check -p aa-ebpf --all-targets`-clean, but the live BPF load + daemon
smoke + cap-drop-under-root assertions require Linux CI to execute.

## AC 1 — "Tampered/unsigned eBPF bytecode is rejected at deploy."

- **AAASM-3601 (CI manifest + cosign):** `release.yml` now compiles the three
  BPF probe objects (Linux x86_64), generates a dedicated `EBPF_SHA256SUMS`
  manifest over them, and cosign-signs it keyless (OIDC), uploading the
  manifest + bundle/sig/cert as release assets — mirroring the binary
  `SHA256SUMS` flow. `actionlint` clean (the one pre-existing SC2046 finding is
  in unrelated macOS keychain code).
- **AAASM-3602 (load-time digest check):** `aa-ebpf/build.rs` emits each
  object's sha256 as `cargo:rustc-env=AA_*_BPF_SHA256` (sourced from the
  compiled object, never hand-written). `aa_ebpf::integrity::verify_bytecode`
  is called by every loader before `aya::Ebpf::load`; a mismatch — or an
  empty/unverifiable stub — returns the fail-closed
  `EbpfError::IntegrityMismatch` and refuses to load.
- Evidence: `cargo nextest run -p aa-ebpf integrity::` (4 tests incl.
  `mismatched_digest_is_rejected`, `empty_expected_is_unverifiable_and_rejected`).

## AC 2 — "A process with runtime privileges cannot detach/replace the probes."

- **AAASM-3603 (loader daemon):** new `aa-ebpf-loaderd` `[[bin]]`, the sole
  CAP_BPF/CAP_PERFMON holder; owns all `aya::Ebpf` handles via `ProbeManager`;
  no SDK/IPC-client logic; sample systemd unit (AmbientCapabilities=CAP_BPF
  CAP_PERFMON) documented inline.
- **AAASM-3604 (control IPC):** `aa_ebpf::control` — typed protocol
  (LoadProbeSet/UpdatePathMap/Detach/Ping), length-prefixed JSON codec with a
  1 MiB frame cap, unprivileged client + privileged server. The server binds a
  root-owned `0600` Unix socket (`bind_hardened`), validates every request, and
  is the only component touching aya — no raw fd/handle crosses the boundary.
- **AAASM-3605 (least privilege):** `aa_runtime::privilege::enforce_least_privilege`
  drops CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN from the bounding set and asserts
  their absence from CapEff at startup (fail-fast), called first in `main()`.
  `layer.rs` no longer gates eBPF on `geteuid()==0` (the userspace
  detach/replace surface) — it gates on a reachable loader-daemon socket.
- Evidence: `cargo nextest run -p aa-ebpf control::` (9 tests incl.
  `bind_hardened_sets_owner_only_perms`, `update_path_map_without_loaded_probe_is_rejected`);
  `cargo nextest run -p aa-runtime privilege::`.
- Needs-Linux-CI: live daemon attach smoke (root) and a userspace-detach-denied
  test from a runtime-privileged context.

## AC 3 — "One policy source → gateway + eBPF rules with no detectable gap."

- **AAASM-3606 (canonical AST):** `aa-security::policy` is the single typed
  source of truth (leaf crate, no aa-core cycle); parses every
  `policy-examples/*.yaml`; the dead `aa_core::types::policy` was removed.
- **AAASM-3607 (gateway consumes it):** gateway projects its document onto the
  canonical AST via `PolicyDocument::to_canonical()` and re-exports the
  canonical types; the kernel rules are lowered from that same projection.
- **AAASM-3608 (lowering):** `lower_to_ebpf(&PolicyDocument) -> EbpfRuleSet`
  produces PathRule deny/allow + egress allowlist; L7-only carve-outs are
  enumerated in `L7_ONLY_DIMENSIONS`.
- **AAASM-3609 (cross-layer test):** for every `policy-examples` fixture,
  egress decisions agree between the gateway L7 eval and the lowered rule set,
  and every `path starts_with` predicate is reflected as a kernel Deny rule; an
  artificial-divergence test proves the check has teeth.
- Evidence: `cargo nextest run -p aa-security --features serde` (policy +
  examples parse); `cargo nextest run -p aa-gateway --test cross_layer_policy_consistency_test`.

## Workspace gate

- `cargo build --workspace` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo fmt --all --check` — clean.
- `cargo nextest run -p aa-security -p aa-gateway -p aa-runtime -p aa-core -p aa-ebpf`
  — 1836 passed, 2 skipped.

No acceptance shortfalls found that warrant a Bug subtask at the
implementation level; the remaining items are Linux-CI execution gaps noted
above, inherent to eBPF being Linux-only.
