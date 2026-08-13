# Sandbox Defense-in-Depth Verification — AAASM-3639 (Story AAASM-3563)

> **Status**: All eight implementation sub-tasks (3613, 3614, 3617, 3618,
> 3622, 3624, 3635, 3631) implemented on
> `v0.0.1/AAASM-3563/sandbox_defense_in_depth` off `remote/master`
> (071c3641, which includes the merged AAASM-3561 foundation). Built on
> AAASM-3561's relocated `aa-security` policy AST + its eBPF lowering and the
> privilege-separated loader daemon — no parallel AST, lowering, or
> in-process privileged load path was introduced. The host-side sandbox
> work (3613/3614/3617/3618/3622's helpers, 3624/3635 AST + lowering) is
> fully built + tested on macOS; the eBPF kernel-enforcement runtime
> (3631) and the cargo-fuzz run (3622) compile/typecheck here but their
> *runtime* assertions are Linux/nightly-CI-only and are flagged below.

## Sub-task roll-up

| Sub-task | Title | Status |
|---|---|---|
| AAASM-3613 | `tenant_id` + `HostFnRateLimit` on `SandboxConfig` | Done (built + tested) |
| AAASM-3614 | Host-fn input sanitization layer (`host_fn` module) | Done (built + tested) |
| AAASM-3617 | Enforce per-tenant host-fn rate-limit + audit event | Done (built + tested) |
| AAASM-3618 | Minimize WASI preopen grants (read-only default) | Done (built + tested) |
| AAASM-3622 | cargo-fuzz target for host-fn sanitization | Done (compiles; fuzz run = nightly/Linux CI) |
| AAASM-3624 | `SyscallAllowlist` node on shared `aa-security` AST | Done (built + tested) |
| AAASM-3635 | Lower syscall allowlist into `SYSCALL_ALLOWLIST` entries | Done (built + tested) |
| AAASM-3631 | seccomp-style syscall-allowlist enforcement probe | Done (host-side built + tested; kernel enforcement = Linux CI) |
| AAASM-3639 | Verify acceptance criteria (this report) | in this report |

## Acceptance criteria

### AC1 — Host-function fuzzing surfaces no escape / memory-safety issue

- The single sanctioned guest-memory read path
  (`aa-sandbox::host_fn::validate_guest_ptr_len` / `read_guest_bytes`,
  AAASM-3614) is total and panic-free: rejects oversized length, `ptr + len`
  `u64` overflow, and out-of-range regions, returning a typed `HostFnError`
  mapped to a deterministic WASI errno. Covered by 9 unit tests including an
  exhaustive "accepted range never exceeds memory" property check.
- The first cargo-fuzz target in the repo (`aa-sandbox/fuzz`,
  `host_fn_validate`, AAASM-3622) drives the helpers with arbitrary
  `(ptr, len, max_len)` against an arbitrary buffer, asserting the bounds
  invariant. It compiles on stable here; the AC's bounded run
  (`cargo +nightly fuzz run host_fn_validate -- -runs=100000`) requires the
  nightly toolchain + libfuzzer instrumentation and is a **Linux/nightly CI**
  step. **Needs-CI** for the zero-crash evidence.

### AC2 — An escaped sandbox process is still syscall-confined by the eBPF allowlist (demonstrated)

- `aa-ebpf-probes::aa-syscall-guard` (AAASM-3631) is the first *enforcing*
  (not observe-only) probe: at `raw_syscalls/sys_enter`, for any PID in
  `PID_FILTER` it default-denies any syscall not in `SYSCALL_ALLOWLIST`,
  killing the process via `bpf_send_signal(SIGKILL)`.
- Loaded/attached **only** through AAASM-3561's privileged loader daemon:
  `ProbeSet::SyscallGuard` + `UpdateSyscallAllowlist` were added to the
  existing control protocol and handled by the daemon's `ProbeManager` via the
  new `SyscallGuardLoader` — **no new in-process privileged load path**
  (`aa-runtime` holds no `CAP_BPF`, AAASM-3605). Integrity-pinned like the
  other objects (`AA_SYSCALL_GUARD_BPF_SHA256`).
- Host-side: the loader's error paths + the control-protocol round-trip are
  unit-tested on macOS. The actual kill-on-unexpected-syscall demonstration
  runs in the kernel and is a **Linux integration / aa-integration-tests
  live** step. **Needs-CI** for the live demonstration.

### AC3 — No WASI preopen grants beyond what the workload needs

- `PreopenedDir` now carries an explicit `PreopenAccess` (AAASM-3618),
  defaulting to `ReadOnly`; `run_tool` maps it to `DirPerms::READ` /
  `FilePerms::READ`, granting `::all()` only for explicit `ReadWrite` mounts —
  replacing the previous unconditional `DirPerms::all()` / `FilePerms::all()`
  over-grant.
- **Verified locally**: `read_only_preopen_denies_write` (a WASI write-probe
  against a real preopened temp dir surfaces a non-zero errno) and
  `read_write_preopen_allows_write` (clean exit) both pass. The
  empty-allowlist `EBADF` case is unchanged.

### Per-tenant host-fn rate-limit denies + audits (Story defense bullet)

- `SandboxConfig.host_fn_rate_limit` (AAASM-3613) → per-`Store`
  `HostFnCounter` seeded per invocation → counted `aa_sandbox/aa_host_noop`
  import → `SandboxError::HostFnRateLimited` → `SandboxHostFnRateLimited`
  audit event (deny posture in the audit sink). **Verified locally**:
  `run_tool_denies_host_fn_calls_over_rate_limit`,
  `run_tool_allows_host_fn_calls_within_rate_limit`, and
  `dispatch_wasm_tool_emits_started_then_host_fn_rate_limited` (asserts the
  exact `SandboxStarted → SandboxHostFnRateLimited` pair) all pass.

### Single-AST cross-layer consistency (anti-seam, AAASM-3561 goal)

- The syscall allowlist is one node on the **same** `aa-security`
  `PolicyDocument` as the path/egress rules (AAASM-3624) and is lowered inside
  the **same** `lower_to_ebpf` pipeline (AAASM-3635) — no second policy or
  lowering path. The gateway's cross-layer consistency test
  (`aa-gateway cross_layer`) still passes with the extended `EbpfRuleSet`.

## Local validation

- `cargo build -p aa-wasm -p aa-sandbox -p aa-security` — clean.
- `cargo check -p aa-ebpf` (Linux-only crate, host check) — clean.
- `cargo build --workspace` — clean.
- `cargo nextest run -p aa-wasm -p aa-sandbox -p aa-security` — 105 passed.
- `cargo fmt` (touched crates) — clean; `cargo clippy` (touched crates) — clean.

## Needs-CI (not provable on this macOS host)

1. `cargo +nightly fuzz run host_fn_validate -- -runs=100000` zero-crash run (AC1).
2. Kernel syscall-allowlist kill-on-unexpected-syscall demonstration on Linux,
   driven via the privileged daemon (AC2).
3. BPF object compilation (`aa-ebpf-probes` is a `bpfel-unknown-none` target;
   on this host `build.rs` emits an empty stub that the runtime fail-closes on).

No Bug Sub-task opened — no defect found in the implemented surfaces.
