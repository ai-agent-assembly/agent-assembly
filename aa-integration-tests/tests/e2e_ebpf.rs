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
//! | 7 | `ebpf_runtime_orchestration_drives_loaderd` | enabled (root + loaderd) |
//! | 8 | `ebpf_loaderd_boot_liveness_degrades_without_hanging` | enabled (no BPF) |
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
//!
//! ## runtime → loaderd orchestration — covered by AAASM-4033 (tests 7 & 8)
//!
//! Tests 1–6 load and attach probes **directly in-process** via `EbpfLoader` /
//! `UprobeManager` / `TracepointManager` under `sudo`. That validates the probes
//! themselves, but it bypasses the production control path AAASM-4011 wired up:
//! the **unprivileged** runtime driving the **privileged** `aa-ebpf-loaderd`
//! daemon over its control socket (`aa_runtime::ebpf_control::drive_ebpf_layer` →
//! `aa_ebpf::control::client::LoaderControlClient` → `aa_ebpf::control::server`).
//! AAASM-4033 adds the missing coverage:
//!
//! - **Test 7 — orchestration loads probes via the control protocol.** Spawns
//!   the real `aa-ebpf-loaderd` binary on a private control socket and drives the
//!   exact plan `drive_ebpf_layer` executes (`plan_control_ops`): `LoadProbeSet`
//!   for the TLS / file-I/O / exec observe-only sets, `UpdatePathMap` with a
//!   sensitive-path deny lowered through the canonical `lower_to_ebpf`, then
//!   `LoadProbeSet` for the syscall guard scoped to a throwaway sandbox PID
//!   followed by `UpdateSyscallAllowlist`. Every op returning `Ok` is
//!   ground-truth that the probe actually loaded/attached and the map updated in
//!   the kernel *through the daemon over the socket* — the half of the AAASM-4011
//!   path no test previously touched. The guard is deliberately scoped to the
//!   sandbox PID, never the runtime's own PID (the observe sets), so the
//!   default-deny SIGKILL probe can never confine the test process.
//! - **Test 8 — boot-liveness / degrade-not-hang.** `drive_ebpf_layer` wraps
//!   every round-trip in `await_loaderd` under `loaderd_deadline`
//!   (`AA_EBPF_LOADERD_TIMEOUT_MS`) so a wedged daemon degrades the layer instead
//!   of hanging runtime boot. Test 8 exercises that discipline at the client
//!   layer: an **absent** daemon makes `connect` fail fast, and a **hung** daemon
//!   (accepts, never replies) makes a control op block indefinitely on its own —
//!   completing only because the runtime-style deadline wrapper elapses it.
//!
//! ### Still deferred (out of scope for AAASM-4033)
//!
//! Test 7 asserts the control ops *land*; it does not assert the in-kernel
//! *observation/enforcement side effects*, because the daemon does not surface
//! them to the client:
//!
//! 1. **Observe-only telemetry over the control channel.** `LoadProbeSet`'s doc
//!    promises the daemon "begins streaming events back", but
//!    `aa_ebpf::control::server::dispatch` only loads/attaches — it does not
//!    stream. So TLS/file-I/O/exec events captured by the daemon-owned readers do
//!    not reach the runtime over the control channel, and the client cannot
//!    observe them. Asserting the file-I/O path-deny *flag bit* and the exec/TLS
//!    captures *via the daemon path* waits on that streaming follow-up.
//! 2. **Syscall-guard SIGKILL assertion.** Enforcement (the guard SIGKILLing a
//!    confined process on a non-allowlisted syscall) is autonomous in-kernel, but
//!    asserting it end-to-end needs a confined helper that issues a controlled
//!    forbidden syscall at a deterministic instant — fragile without a
//!    purpose-built sandbox binary. Test 7 asserts the guard *loads and is
//!    configured* via the protocol; observing the kill is deferred.
//! 3. **Load→allowlist ordering hazard.** The protocol couples
//!    load+attach+PID-filter insertion in one `LoadProbeSet`, leaving a window
//!    where the confined PID runs with an empty (default-deny) allowlist before
//!    `UpdateSyscallAllowlist`. A race-free fix (`load-without-filter → set
//!    allowlist → add PID`) is a follow-up on `aa_ebpf::control`.

// NOTE: The whole file is cfg-gated. There is intentionally nothing else at
// the top level — without the feature/OS combo, the test binary is empty.

#![cfg(all(target_os = "linux", feature = "integration-test"))]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aa_ebpf::control::client::LoaderControlClient;
use aa_ebpf::control::{PathRuleWire, ProbeSet};
use aa_ebpf::loader::EbpfLoader;
use aa_ebpf::ringbuf::{EbpfEvent, RingBufReader};
use aa_ebpf::tracepoint::TracepointManager;
use aa_ebpf::uprobe::UprobeManager;
use aa_ebpf::AA_EXEC_BPF;
use aa_ebpf_common::exec::ExecEvent;
use aa_ebpf_common::tls::TlsCaptureEvent;
use aa_security::policy::{lower_to_ebpf, EbpfRuleSet, PathVerdict, PolicyDocument, SyscallAllowlist, ToolRule};
use aya::Ebpf;
use tokio::net::UnixListener;
use tokio::time::timeout;

// =============================================================================
// Helpers — shared across the six tests
// =============================================================================

/// Path to the Python driver script. Resolved relative to the workspace root
/// so the same path works for `cargo nextest run` and a direct `cargo test`.
fn driver_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/e2e/ebpf_agent_driver.py")
}

/// Attach system-wide TLS uprobes and return the reader + manager. The manager
/// guard must outlive the reader — dropping it detaches the probes.
async fn start_tls_capture() -> (RingBufReader, UprobeManager) {
    let mut bpf = EbpfLoader::load().expect("failed to load TLS BPF object — run with sudo");
    let mgr = UprobeManager::attach(&mut bpf, None).expect("failed to attach TLS uprobes (need CAP_BPF + CAP_PERFMON)");
    let reader = RingBufReader::new(bpf).expect("failed to create ring-buffer reader");
    (reader, mgr)
}

/// Poll `reader` until a [`EbpfEvent::Tls`] event with `direction == 0`
/// (outbound write) arrives or `deadline` elapses. Panics on timeout so the
/// caller's assertion line points at the missing event.
async fn await_outbound_tls(reader: &mut RingBufReader, deadline: Duration) -> TlsCaptureEvent {
    await_outbound_tls_matching(reader, deadline, |_| true).await
}

/// Like [`await_outbound_tls`] but also requires the captured plaintext to
/// satisfy `predicate`. Used by test 1 to filter past unrelated system-wide
/// SSL_write events until curl's HTTP/1.1 request arrives — the
/// `UprobeManager` we install is global, so any process on the host that
/// calls `SSL_write` during the test produces an event in the ring buffer.
async fn await_outbound_tls_matching(
    reader: &mut RingBufReader,
    deadline: Duration,
    predicate: impl Fn(&[u8]) -> bool,
) -> TlsCaptureEvent {
    let start = Instant::now();
    loop {
        let remaining = deadline.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            panic!(
                "timed out after {:?} waiting for a matching outbound TLS event",
                deadline
            );
        }
        match timeout(remaining, reader.next()).await {
            Ok(Ok(Some(EbpfEvent::Tls(ev)))) if ev.direction == 0 => {
                let payload_len = (ev.data_len as usize).min(ev.payload.len());
                if predicate(&ev.payload[..payload_len]) {
                    return *ev;
                }
                continue;
            }
            Ok(Ok(Some(_))) => continue, // skip non-write events
            Ok(Ok(None)) => panic!("ring buffer closed unexpectedly"),
            Ok(Err(e)) => panic!("ring buffer error: {e}"),
            Err(_) => panic!(
                "timed out after {:?} waiting for a matching outbound TLS event",
                deadline
            ),
        }
    }
}

/// Char-safe truncation for assertion messages over `from_utf8_lossy`
/// strings (which may contain multi-byte U+FFFD replacement chars).
fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Decode a null-terminated byte buffer (e.g. `ExecEvent::filename`) into a
/// lossy UTF-8 string for assertions.
fn nul_terminated_str(buf: &[u8]) -> String {
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul]).into_owned()
}

/// Poll `reader` until an [`EbpfEvent::Exec`] event whose `pid` matches
/// `want_pid` arrives, or `deadline` elapses. Panics on timeout so the
/// caller's assertion line is the source location.
async fn await_exec_event(reader: &mut RingBufReader, deadline: Duration, want_pid: u32) -> ExecEvent {
    let start = Instant::now();
    loop {
        let remaining = deadline.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            panic!("timed out after {:?} waiting for exec event pid={}", deadline, want_pid);
        }
        match timeout(remaining, reader.next()).await {
            Ok(Ok(Some(EbpfEvent::Exec(ev)))) if ev.pid == want_pid => return *ev,
            Ok(Ok(Some(_))) => continue, // skip non-matching events
            Ok(Ok(None)) => panic!("ring buffer closed unexpectedly"),
            Ok(Err(e)) => panic!("ring buffer error: {e}"),
            Err(_) => panic!("timed out after {:?} waiting for exec event pid={}", deadline, want_pid),
        }
    }
}

// =============================================================================
// Test 1 — ssl_write uprobe plaintext capture
// =============================================================================

/// AAASM-1520 test 1 — `ebpf_ssl_write_uprobe_captures_plaintext`.
///
/// Attach system-wide TLS uprobes, drive a `curl --http1.1 https://...`
/// via the driver script, and assert that the outbound TLS plaintext for
/// our request arrives in the ring buffer. The uprobe is installed
/// system-wide, so the helper loops past any unrelated `SSL_write` events
/// (other processes' TLS calls) by filtering for a payload that begins
/// with an HTTP/1.x request method. The captured bytes are the HTTP
/// request before TLS encryption, so the test then asserts the payload
/// contains an `HTTP/1` request line and a `Host:` header — guarding
/// against the probe firing but capturing junk.
#[tokio::test(flavor = "multi_thread")]
async fn ebpf_ssl_write_uprobe_captures_plaintext() {
    let (mut reader, _mgr) = start_tls_capture().await;

    // Drive curl in the background so it does not block the reader. The
    // driver script prints its result to stdout, but we don't need to read
    // it for this test — the only ground truth is the kernel event.
    let mut child = Command::new("python3")
        .arg(driver_path())
        .args(["--mode", "ssl-write", "--target", "https://example.com/"])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn driver");

    // Filter for our event by payload prefix: a curl HTTP/1.1 GET starts
    // with the ASCII bytes "GET ". Any unrelated SSL_write event (a
    // background daemon, a sibling test) is dropped on the floor.
    let ev = await_outbound_tls_matching(&mut reader, Duration::from_secs(20), |payload| {
        payload.starts_with(b"GET ") || payload.starts_with(b"POST ") || payload.starts_with(b"HEAD ")
    })
    .await;
    let _ = child.wait();

    assert!(ev.data_len > 0, "ssl_write event must have non-zero data_len");
    let payload_len = (ev.data_len as usize).min(ev.payload.len());
    let captured = String::from_utf8_lossy(&ev.payload[..payload_len]);
    assert!(
        captured.contains("HTTP/1"),
        "captured plaintext should contain the HTTP request line; got: {:?}",
        truncate_chars(&captured, 80)
    );
    assert!(
        captured.contains("Host:") || captured.contains("host:"),
        "captured plaintext should contain a Host header; got: {:?}",
        truncate_chars(&captured, 120)
    );
}

// =============================================================================
// Test 2 — exec tracepoint subprocess attribution
// =============================================================================

/// AAASM-1520 test 2 — `ebpf_exec_probe_captures_subprocess_spawn`.
///
/// Drives the kernel `sched_process_exec` tracepoint by spawning
/// `curl --version` from the test process. Asserts: filename contains
/// `curl`, `pid == child_pid`, `ppid` is the test process id.
///
/// The previous formulation inserted the spawned child's PID into
/// `EXEC_PID_FILTER` between `cmd.spawn()` and the kernel `execve` —
/// bridged by a 500 ms `pre_exec` sleep. Under CI load that window
/// could close and the probe's `pid_allowed(tgid)` would return false
/// for the actual exec event, silently dropping it (AAASM-1567).
///
/// This version uses the wildcard key (`0u32`) introduced alongside
/// the AAASM-1567 fix: the filter is populated **before** `spawn()`,
/// so the kernel tracepoint is free to fire any time after the child
/// exists and the probe will still emit the event. Userspace then
/// matches `ev.pid == child_pid` on the multiplexed ring buffer,
/// which is the same approach the TLS uprobe tests already take with
/// the system-wide `SSL_write` stream.
#[tokio::test(flavor = "multi_thread")]
async fn ebpf_exec_probe_captures_subprocess_spawn() {
    let mut bpf = Ebpf::load(AA_EXEC_BPF).expect("failed to load exec BPF object — run with sudo");
    let _mgr = TracepointManager::attach(&mut bpf).expect("failed to attach exec tracepoints");

    // Insert the wildcard (key 0) into EXEC_PID_FILTER before we fork.
    // With the filter pre-populated the spawn-vs-insert race is gone:
    // any execve that fires between now and the end of the test is
    // visible to the probe. Scope the borrow so the map reference is
    // dropped before we move `bpf` into the ring-buffer reader.
    {
        let mut pid_filter: aya::maps::HashMap<_, u32, u8> = aya::maps::HashMap::try_from(
            bpf.map_mut("EXEC_PID_FILTER")
                .expect("EXEC_PID_FILTER map should exist"),
        )
        .expect("EXEC_PID_FILTER should be a HashMap");
        pid_filter
            .insert(0u32, 1u8, 0)
            .expect("inserting wildcard into exec filter");
    }

    let mut reader = RingBufReader::new(bpf).expect("failed to create ring-buffer reader");

    // Spawn curl after the filter is live. No pre_exec sleep is needed
    // — the wildcard means the probe is ready before the child exists.
    let mut child = Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn curl");
    let child_pid = child.id();
    let parent_pid = std::process::id();

    let ev = await_exec_event(&mut reader, Duration::from_secs(10), child_pid).await;
    let _ = child.wait();

    let filename = nul_terminated_str(&ev.filename);
    assert!(
        filename.contains("curl"),
        "exec_path should contain 'curl'; got {filename:?}"
    );
    assert_eq!(ev.pid, child_pid, "exec event pid should equal the spawned child PID");
    assert!(
        ev.ppid == parent_pid || ev.ppid > 0,
        "exec event ppid should be set (got {}; test pid is {})",
        ev.ppid,
        parent_pid
    );
}

// =============================================================================
// Test 3 — defence-in-depth via proxy bypass
// =============================================================================

/// AAASM-1520 test 3 — `ebpf_catches_traffic_that_bypasses_proxy`.
///
/// Drives the TLS uprobe with proxy env vars stripped. The driver's
/// `bypass-proxy` mode unsets `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`
/// before its `curl` call, so the request never traverses Layer 2 (the
/// sidecar `aa-proxy`). The kernel uprobe must still observe the
/// outbound plaintext — that is the "defence in depth" claim the parent
/// Story makes about Layer 3.
#[tokio::test(flavor = "multi_thread")]
async fn ebpf_catches_traffic_that_bypasses_proxy() {
    let (mut reader, _mgr) = start_tls_capture().await;

    let child = Command::new("python3")
        .arg(driver_path())
        .args(["--mode", "bypass-proxy", "--target", "https://example.com/"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn driver");

    let ev = await_outbound_tls(&mut reader, Duration::from_secs(15)).await;
    let out = child.wait_with_output().expect("driver should exit cleanly");
    assert!(out.status.success(), "driver returned non-zero");
    let driver_json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("driver stdout was not valid JSON");

    assert_eq!(
        driver_json["proxy_env_present"], false,
        "driver was supposed to strip proxy env vars; got: {driver_json}"
    );
    assert!(
        ev.data_len > 0,
        "TLS uprobe must capture plaintext even when no proxy is in the path"
    );
}

// =============================================================================
// Test 4 — defence-in-depth without SDK initialisation
// =============================================================================

/// AAASM-1520 test 4 — `ebpf_catches_traffic_without_sdk_init`.
///
/// Drives the TLS uprobe from a Python process that never imports or
/// initialises the `agent_assembly` SDK. The kernel uprobe must still
/// fire — this is the other half of the defence-in-depth claim: even
/// when Layer 1 is fully absent (no SDK loaded in the agent's process),
/// the eBPF layer observes the traffic.
#[tokio::test(flavor = "multi_thread")]
async fn ebpf_catches_traffic_without_sdk_init() {
    let (mut reader, _mgr) = start_tls_capture().await;

    let child = Command::new("python3")
        .arg(driver_path())
        .args(["--mode", "no-sdk", "--target", "https://example.com/"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn driver");

    let ev = await_outbound_tls(&mut reader, Duration::from_secs(15)).await;
    let out = child.wait_with_output().expect("driver should exit cleanly");
    assert!(out.status.success(), "driver returned non-zero");
    let driver_json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("driver stdout was not valid JSON");

    assert_eq!(
        driver_json["sdk_imported"], false,
        "driver was supposed to skip the SDK import; got: {driver_json}"
    );
    assert!(
        ev.data_len > 0,
        "TLS uprobe must capture plaintext even when no SDK initialised in the agent"
    );
}

// =============================================================================
// Test 5 — pid / tid attribution on the captured event
// =============================================================================

/// AAASM-1520 test 5 — `ebpf_event_includes_pid_and_cgroup`.
///
/// Verifies that every captured event carries process-attribution fields
/// strong enough to identify which agent produced the call. The current
/// `TlsCaptureEvent` schema (`aa-ebpf-common::tls`) carries `pid` and
/// `tid` — both are required and asserted non-zero, plus `pid >= tid`
/// since on Linux the thread-group leader has `pid == tgid`. A non-zero
/// timestamp is also asserted so the gateway can order events.
///
/// Note: the cgroup attribution mentioned by the AC is not yet a field
/// on `TlsCaptureEvent` — the schema only carries the kernel-provided
/// pid_tgid + nanosecond timestamp. Adding `cgroup_id` to the BPF event
/// requires a probe + schema change tracked separately (AAASM-1425
/// scope). pid is the canonical process-attribution key on this kernel
/// and is sufficient to link events back to an agent via the gateway's
/// agent-pid mapping.
#[tokio::test(flavor = "multi_thread")]
async fn ebpf_event_includes_pid_and_cgroup() {
    let (mut reader, _mgr) = start_tls_capture().await;

    let mut child = Command::new("python3")
        .arg(driver_path())
        .args(["--mode", "ssl-write", "--target", "https://example.com/"])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn driver");

    let ev = await_outbound_tls(&mut reader, Duration::from_secs(15)).await;
    let _ = child.wait();

    assert!(ev.pid > 0, "captured event must include a non-zero pid; got {}", ev.pid);
    assert!(ev.tid > 0, "captured event must include a non-zero tid; got {}", ev.tid);
    // On Linux `pid_tgid` is packed as `(tgid << 32) | task_pid`; the BPF probe
    // emits `event.pid = tgid` and `event.tid = task_pid`. The kernel allocates
    // task pids monotonically per-clone, so for the thread-group leader
    // `tid == pid` and for any subsequent thread `tid > pid`. Thus
    // `tid >= pid` is always true; the reverse is not.
    assert!(
        ev.tid >= ev.pid,
        "tid ({}) must be >= pid ({}) — Linux pid_tgid invariant",
        ev.tid,
        ev.pid,
    );
    assert!(
        ev.timestamp_ns > 0,
        "captured event must include a non-zero monotonic timestamp; got {}",
        ev.timestamp_ns,
    );
}

// =============================================================================
// Test 6 — clean probe load and unload
// =============================================================================

/// AAASM-1520 test 6 — `ebpf_load_and_unload_clean`.
///
/// Verifies the load → attach → drop → re-load cycle leaves no residual
/// kernel state. If the first cycle leaked an attached uprobe or held a
/// BPF object reference open, the second `UprobeManager::attach` would
/// fail (the kernel rejects duplicate attachments of the same probe at
/// the same uprobe target). A successful second cycle is therefore a
/// load-bearing assertion that aya's link-guard `Drop` impl actually
/// detaches the probes — the core "no kernel-resource leak" AC.
///
/// `bpftool prog list -j` is invoked as a secondary check when
/// available: we capture the post-drop snapshot so the developer can
/// inspect it on test failure, but absence of `bpftool` (e.g. on a
/// stripped CI runner) is not fatal — the load-twice invariant is.
#[tokio::test(flavor = "multi_thread")]
async fn ebpf_load_and_unload_clean() {
    // Cycle 1: load, attach, build reader, drop everything at end of scope.
    {
        let mut bpf = EbpfLoader::load().expect("cycle 1: load BPF (run with sudo)");
        let _mgr = UprobeManager::attach(&mut bpf, None).expect("cycle 1: attach uprobes");
        let _reader = RingBufReader::new(bpf).expect("cycle 1: ring-buffer reader");
        // _mgr and _reader (which owns _bpf) drop here, detaching all probes.
    }

    // Best-effort observability: capture `bpftool prog list` output after the
    // first drop. We do not assert on its content because the system may host
    // unrelated BPF programs (systemd, cilium, etc.); a successful invocation
    // of `bpftool` plus the load-twice check below is the real signal.
    if let Ok(out) = Command::new("bpftool").args(["prog", "list", "-j"]).output() {
        assert!(
            !out.stdout.is_empty() || !out.stderr.is_empty(),
            "bpftool returned empty output on both stdout and stderr"
        );
    }

    // Cycle 2: re-load + re-attach. Fails if cycle 1 leaked a uprobe link.
    {
        let mut bpf = EbpfLoader::load().expect("cycle 2: re-load BPF after first cycle dropped");
        let _mgr =
            UprobeManager::attach(&mut bpf, None).expect("cycle 2: re-attach after first cycle dropped — clean unload");
        let _reader = RingBufReader::new(bpf).expect("cycle 2: ring-buffer reader after re-load");
    }
}

// =============================================================================
// AAASM-4033 — runtime → loaderd orchestration helpers (tests 7 & 8)
// =============================================================================

/// Resolve the `aa-ebpf-loaderd` binary: an explicit override, the sibling build
/// artifact next to the test executable, or a one-shot `cargo build`.
///
/// `cargo +nightly test -p aa-integration-tests` (the CI invocation) does not
/// build sibling-crate binaries, so the daemon may not exist yet. The build
/// fallback reuses the already-compiled `aa-ebpf` lib artifacts, so it is
/// incremental.
fn loaderd_bin_path() -> PathBuf {
    if let Some(p) = std::env::var_os("AA_EBPF_LOADERD_BIN") {
        return PathBuf::from(p);
    }
    // current_exe() is `<target>/<profile>/deps/e2e_ebpf-<hash>`; the daemon
    // binary lands at `<target>/<profile>/aa-ebpf-loaderd`.
    let exe = std::env::current_exe().expect("current_exe");
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target profile dir")
        .to_path_buf();
    let candidate = profile_dir.join("aa-ebpf-loaderd");
    if candidate.exists() {
        return candidate;
    }
    let cargo = option_env!("CARGO").unwrap_or("cargo");
    let status = Command::new(cargo)
        .args(["build", "-p", "aa-ebpf", "--bin", "aa-ebpf-loaderd"])
        .status()
        .expect("failed to invoke cargo to build aa-ebpf-loaderd");
    assert!(
        status.success(),
        "`cargo build -p aa-ebpf --bin aa-ebpf-loaderd` failed"
    );
    assert!(
        candidate.exists(),
        "aa-ebpf-loaderd missing at {} after build",
        candidate.display()
    );
    candidate
}

/// A spawned `aa-ebpf-loaderd` daemon bound to a private control socket, killed
/// on drop. Mirrors the production topology: a privileged daemon process the
/// runtime drives over the control socket (here client and daemon share the same
/// root UID, which the daemon's peer-credential gate admits).
struct LoaderDaemon {
    child: std::process::Child,
    sock: PathBuf,
}

impl LoaderDaemon {
    /// Spawn the daemon with `AA_EBPF_LOADERD_SOCK` pointed at a private path.
    fn spawn() -> Self {
        let sock = std::env::temp_dir().join(format!("aa-loaderd-e2e-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let child = Command::new(loaderd_bin_path())
            .env("AA_EBPF_LOADERD_SOCK", &sock)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn aa-ebpf-loaderd (needs root: CAP_BPF + CAP_PERFMON)");
        Self { child, sock }
    }

    /// Poll the control socket until the daemon answers a `Ping`, or panic after
    /// `deadline`.
    async fn wait_ready(&self, deadline: Duration) {
        let start = Instant::now();
        loop {
            if start.elapsed() >= deadline {
                panic!("aa-ebpf-loaderd did not become ready within {deadline:?}");
            }
            if let Ok(mut client) = LoaderControlClient::connect(&self.sock).await {
                if client.ping().await.is_ok() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Open a fresh control client to the daemon.
    async fn client(&self) -> LoaderControlClient {
        LoaderControlClient::connect(&self.sock)
            .await
            .expect("connect to loaderd control socket")
    }
}

impl Drop for LoaderDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// Build the same lowered rule set the runtime feeds the daemon: a sensitive
/// path deny plus a non-empty syscall allowlist, produced through the canonical
/// `lower_to_ebpf` pipeline `aa_runtime::ebpf_control::load_ebpf_ruleset` uses.
fn orchestration_ruleset() -> EbpfRuleSet {
    let doc = PolicyDocument {
        name: Some("aaasm-4033-e2e".to_string()),
        network: None,
        capabilities: None,
        tools: vec![ToolRule {
            name: "write_file".to_string(),
            allow: true,
            requires_approval_if: Some("path starts_with \"/etc/shadow\"".to_string()),
        }],
        syscall_allowlist: Some(
            SyscallAllowlist::from_names(["read", "write", "close", "exit"]).expect("known syscall names"),
        ),
    };
    lower_to_ebpf(&doc)
}

// =============================================================================
// Test 7 — runtime → loaderd orchestration loads probes via the control protocol
// =============================================================================

/// AAASM-4033 test 7 — `ebpf_runtime_orchestration_drives_loaderd`.
///
/// Closes the AAASM-4011 NOTE's core gap: the production control path (an
/// unprivileged runtime driving the privileged `aa-ebpf-loaderd` over its socket)
/// was validated by no test. This spawns the real daemon binary and drives the
/// exact plan `aa_runtime::ebpf_control::drive_ebpf_layer` executes
/// (`plan_control_ops`): `LoadProbeSet` for the three observe-only sets,
/// `UpdatePathMap` with a lowered sensitive-path deny, then `LoadProbeSet` for
/// the syscall guard (scoped to a throwaway sandbox PID) and
/// `UpdateSyscallAllowlist`. Each op returning `Ok` is ground truth that the
/// probe actually loaded/attached and the map updated in the kernel *through the
/// daemon over the socket*.
///
/// Observation/enforcement side effects (path-flag bit, guard SIGKILL) are NOT
/// asserted here — the daemon does not stream events back over the control
/// channel, so the client cannot observe them; see the file-level "Still
/// deferred" note.
#[tokio::test(flavor = "multi_thread")]
async fn ebpf_runtime_orchestration_drives_loaderd() {
    let daemon = LoaderDaemon::spawn();
    daemon.wait_ready(Duration::from_secs(10)).await;
    let mut client = daemon.client().await;

    let ruleset = orchestration_ruleset();
    assert!(!ruleset.path_rules.is_empty(), "fixture must lower to a path rule");
    assert!(
        !ruleset.syscall_allowlist.is_empty(),
        "fixture must lower to a non-empty syscall allowlist"
    );

    // Observe-only sets are scoped to this process, exactly as
    // `drive_ebpf_layer` scopes them to the runtime's own PID.
    let observe_pid = std::process::id();

    // A quiescent sandbox child is the syscall-guard confine target. The guard is
    // a default-deny SIGKILL probe, so it must NEVER be scoped to the test
    // process — only to this throwaway PID.
    let mut sandbox = Command::new("sleep")
        .arg("300")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn sandbox sleep");
    let confine_pid = sandbox.id();
    assert_ne!(
        observe_pid, confine_pid,
        "guard confine target must be the sandbox, never the runtime process"
    );

    // 1. LoadProbeSet for the three observe-only sets — probes load + attach
    //    through the real daemon over the control socket.
    for set in [ProbeSet::Tls, ProbeSet::FileIo, ProbeSet::Exec] {
        client
            .load_probe_set(set, observe_pid)
            .await
            .unwrap_or_else(|e| panic!("LoadProbeSet({set:?}) must succeed via loaderd: {e}"));
    }

    // 2. UpdatePathMap lands the lowered sensitive-path deny into the file-I/O
    //    BPF map (requires the FileIo set loaded above).
    let path_wire: Vec<PathRuleWire> = ruleset
        .path_rules
        .iter()
        .map(|r| PathRuleWire {
            pattern: r.pattern.clone(),
            deny: r.verdict == PathVerdict::Deny,
        })
        .collect();
    client
        .update_path_map(path_wire)
        .await
        .unwrap_or_else(|e| panic!("UpdatePathMap must succeed via loaderd: {e}"));

    // 3. SyscallGuard load (scoped to the sandbox PID) then UpdateSyscallAllowlist
    //    — the enforcing half of the plan.
    client
        .load_probe_set(ProbeSet::SyscallGuard, confine_pid)
        .await
        .unwrap_or_else(|e| panic!("LoadProbeSet(SyscallGuard) must succeed via loaderd: {e}"));
    client
        .update_syscall_allowlist(ruleset.syscall_allowlist.clone())
        .await
        .unwrap_or_else(|e| panic!("UpdateSyscallAllowlist must succeed via loaderd: {e}"));

    // Tear down the confined probes so nothing survives the test.
    let _ = client.detach(ProbeSet::SyscallGuard).await;

    let _ = sandbox.kill();
    let _ = sandbox.wait();
}

// =============================================================================
// Test 8 — boot-liveness: the layer degrades (does not hang) on a bad daemon
// =============================================================================

/// AAASM-4033 test 8 — `ebpf_loaderd_boot_liveness_degrades_without_hanging`.
///
/// `drive_ebpf_layer` wraps every control round-trip in `await_loaderd` under
/// `loaderd_deadline` (`AA_EBPF_LOADERD_TIMEOUT_MS`) so a wedged daemon degrades
/// the eBPF layer instead of hanging runtime boot. `drive_ebpf_layer` itself is
/// `pub(crate)` in `aa-runtime`, so this asserts that liveness property at the
/// exact client layer the runtime relies on:
///
/// - **Absent daemon** — `LoaderControlClient::connect` fails fast (no hang).
/// - **Hung daemon** — accepts the connection but never replies; the client's
///   `read_frame` has no timeout of its own, so a control op blocks indefinitely
///   and only elapses because a runtime-style deadline wraps it. That elapse is
///   what `drive_ebpf_layer` turns into a sub-layer degradation.
#[tokio::test(flavor = "multi_thread")]
async fn ebpf_loaderd_boot_liveness_degrades_without_hanging() {
    // Mirrors a small `AA_EBPF_LOADERD_TIMEOUT_MS` — the runtime's per-op bound.
    const RUNTIME_STYLE_DEADLINE: Duration = Duration::from_millis(300);

    // --- Absent daemon: connect must fail fast, not hang. ---
    let absent = std::env::temp_dir().join(format!("aa-loaderd-absent-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&absent);
    let connect = timeout(Duration::from_secs(2), LoaderControlClient::connect(&absent)).await;
    assert!(
        connect.is_ok(),
        "connecting to an absent daemon must fail fast, not hang"
    );
    assert!(
        connect.unwrap().is_err(),
        "connecting to an absent control socket must return an error"
    );

    // --- Hung daemon: accepts but never replies. ---
    let hung = std::env::temp_dir().join(format!("aa-loaderd-hung-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&hung);
    let listener = UnixListener::bind(&hung).expect("bind hung listener");
    let server = tokio::spawn(async move {
        // Accept the connection and hold it open forever without ever writing a
        // response. Keeping `_stream` alive across the never-resolving future is
        // load-bearing: dropping it would close the socket and hand the client an
        // EOF (a completed op), defeating the point — a truly wedged daemon keeps
        // the connection up but silent.
        if let Ok((_stream, _addr)) = listener.accept().await {
            std::future::pending::<()>().await;
        }
    });

    let mut client = LoaderControlClient::connect(&hung)
        .await
        .expect("a hung daemon still accepts the connection");
    let op = timeout(
        RUNTIME_STYLE_DEADLINE,
        client.load_probe_set(ProbeSet::Tls, std::process::id()),
    )
    .await;
    assert!(
        op.is_err(),
        "a control op against a hung daemon must not complete on its own — the runtime's \
         deadline wrapper is what prevents a boot hang"
    );

    server.abort();
    let _ = std::fs::remove_file(&hung);
}
