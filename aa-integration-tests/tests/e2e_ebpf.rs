//! AAASM-1520 / F116 ST-H — E2E Layer 3 (eBPF) interception verification.
//!
//! Verifies that the kernel-level eBPF probes (`aa-tls-probes`,
//! `aa-exec-probes`, `aa-file-io`) catch outbound HTTPS traffic and
//! process exec events that bypass both the SDK shim (Layer 1) and the
//! sidecar proxy (Layer 2). This is the "defence-in-depth" leg of the
//! three-layer interception model — without these tests, AAASM-1232's
//! claim of validating "all three interception layers" is unsubstantiated
//! for Layer 3.
//!
//! ## Platform gating
//!
//! Every test in this file is gated on
//! `#[cfg(all(target_os = "linux", feature = "integration-test"))]`. eBPF
//! is Linux-only, and loading BPF programs requires `CAP_BPF` +
//! `CAP_PERFMON` (root). The feature gate keeps the suite off the default
//! `cargo nextest` run; the dedicated `e2e-ebpf-linux` CI job opts in
//! explicitly with `sudo`.
//!
//! On macOS and on Linux without the feature, the entire file is empty
//! after `cfg` evaluation — there are no `#[ignore]` markers and no
//! "ignored" line in nextest output, which matches the AC requirement
//! that "macOS CI skips them cleanly (no failures, no `#[ignore]`
//! confusion)".
//!
//! ## Test status
//!
//! | # | Name | Status |
//! |---|------|--------|
//! | 1 | `ebpf_ssl_write_uprobe_captures_plaintext` | enabled (root + libssl) |
//! | 2 | `ebpf_exec_probe_captures_subprocess_spawn` | enabled (root) |
//! | 3 | `ebpf_catches_traffic_that_bypasses_proxy` | enabled (root + libssl) |
//! | 4 | `ebpf_catches_traffic_without_sdk_init` | enabled (root + libssl) |
//! | 5 | `ebpf_event_includes_pid_and_cgroup` | enabled (root) |
//! | 6 | `ebpf_load_and_unload_clean` | enabled (root) |
//!
//! ## Why direct ring-buffer reads instead of HTTP gateway lookup
//!
//! The ticket text describes the assertion path as "query gateway for
//! events". In the current tree the gateway audit HTTP surface
//! (`aa-api::api_logs`) does not yet ingest the `aa-runtime::ebpf_bridge`
//! stream — that wiring is tracked separately under AAASM-237 /
//! AAASM-1425. Until those land, the only ground-truth view of "did the
//! kernel probe fire" is the `RingBufReader` that `aa-ebpf` already
//! exposes for its own integration suite (`aa-ebpf/tests/tls_capture.rs`).
//!
//! These tests therefore read directly from the BPF ring buffer, which
//! is what the gateway path will read once wired. When the HTTP path is
//! complete, the gateway-side assertion can be added in a follow-up
//! without changing the probe-fired half of the check.

// NOTE: The whole file is cfg-gated. There is intentionally nothing else at
// the top level — without the feature/OS combo, the test binary is empty.

#![cfg(all(target_os = "linux", feature = "integration-test"))]

// Test bodies land in subsequent commits (one per logical unit) per the
// AAASM-1520 commit shape documented on the Jira subtask.
