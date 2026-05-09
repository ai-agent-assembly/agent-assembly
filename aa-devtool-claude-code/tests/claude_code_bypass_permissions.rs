//! Integration tests proving AAASM enforcement is independent of Claude Code's
//! `--bypassPermissions` flag.
//!
//! ## Architectural invariant under test
//!
//! Claude Code's `--bypassPermissions` flag bypasses Claude's **own** permission
//! prompts — it does NOT bypass AAASM's enforcement, which operates at a lower
//! layer:
//!
//! ```text
//! Claude Code (--bypassPermissions skips Claude's own checks)
//!      │  ↕  HTTPS via HTTPS_PROXY env var (set by ClaudeCodeAdapter)
//!    aa-proxy (Layer 2 — MitM interception; policy deny returns 403)
//!      │  ↕  eBPF uprobes on SSL_write/SSL_read (Linux only)
//!    aa-ebpf (Layer 3 — kernel-level block; independent of user-space flags)
//! ```
//!
//! The non-Docker tests below assert the code invariant: `build_launch_command`
//! always wires `HTTPS_PROXY` (routing through AAASM) regardless of what flags
//! are in `tool_args`. Tests tagged `#[cfg(feature = "docker-integration")]`
//! exercise the full stack end-to-end.
//!
//! ## Running Docker integration tests
//!
//! ```bash
//! # Build the aa-proxy image first:
//! docker compose -f ci/integration/bypass-permissions/docker-compose.yml build aa-proxy
//!
//! # Run all tests including Docker:
//! cargo nextest run -p aa-devtool-claude-code \
//!   --features docker-integration \
//!   --test claude_code_bypass_permissions \
//!   --test-threads=1
//! ```
//!
//! ## Note on proxy-level deny assertion
//!
//! The Docker tests currently assert that the proxy *observes* traffic
//! (proving enforcement is independent of `--bypassPermissions`).
//! The assertion that the proxy *denies* requests requires proxy deny capability
//! (the `aa-proxy` interceptor returning 403 when policy says DENY).
//! That is tracked separately. Once implemented, remove `#[ignore]` from
//! `stub_upstream_receives_zero_requests_when_policy_denies`.

use std::path::PathBuf;

use aa_core::DevToolAdapter;
use aa_devtool_claude_code::ClaudeCodeAdapter;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Read all env vars out of a `std::process::Command` as a `HashMap`.
fn cmd_envs(cmd: &std::process::Command) -> std::collections::HashMap<String, Option<String>> {
    cmd.get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|s| s.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

/// Read all positional args out of a `std::process::Command`.
fn cmd_args(cmd: &std::process::Command) -> Vec<String> {
    cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect()
}

/// Create a stub Claude binary file in a tempdir. The file only needs to
/// exist on disk — `build_launch_command` never executes it in tests.
fn stub_binary() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("claude");
    std::fs::write(&bin, "").unwrap();
    (tmp, bin)
}

// ── Non-Docker tests (always run) ───────────────────────────────────────────
//
// These tests assert the code-level invariant: the adapter always wires
// AAASM's proxy into the Claude launch command, regardless of what
// tool_args are passed (including --bypassPermissions).

#[test]
fn https_proxy_is_set_when_proxy_addr_is_provided() {
    let (_tmp, bin) = stub_binary();
    let adapter = ClaudeCodeAdapter::with_overrides(Some(bin), None);
    let cmd = adapter
        .build_launch_command(&[], "agent-1", None, Some("http://aa-proxy:8080"))
        .unwrap();
    let envs = cmd_envs(&cmd);
    assert_eq!(
        envs.get("HTTPS_PROXY").and_then(|v| v.as_deref()),
        Some("http://aa-proxy:8080"),
        "HTTPS_PROXY must be set so traffic routes through aa-proxy"
    );
}

#[test]
fn https_proxy_is_not_set_when_proxy_addr_is_none() {
    let (_tmp, bin) = stub_binary();
    let adapter = ClaudeCodeAdapter::with_overrides(Some(bin), None);
    let cmd = adapter.build_launch_command(&[], "agent-1", None, None).unwrap();
    let envs = cmd_envs(&cmd);
    assert!(
        !envs.contains_key("HTTPS_PROXY"),
        "HTTPS_PROXY must not be injected when no proxy addr is given"
    );
}

#[test]
fn bypass_permissions_flag_is_preserved_in_launch_command() {
    // AAASM does not strip --bypassPermissions: enforcement is below Claude's
    // own permission layer. The flag is passed through as-is.
    let (_tmp, bin) = stub_binary();
    let adapter = ClaudeCodeAdapter::with_overrides(Some(bin), None);
    let args = vec!["--bypassPermissions".to_string()];
    let cmd = adapter
        .build_launch_command(&args, "agent-1", None, Some("http://aa-proxy:8080"))
        .unwrap();
    let got_args = cmd_args(&cmd);
    assert!(
        got_args.contains(&"--bypassPermissions".to_string()),
        "AAASM must pass --bypassPermissions through to Claude unchanged"
    );
}

#[test]
fn https_proxy_is_set_even_when_bypass_permissions_flag_is_present() {
    // This is the key invariant: Claude's bypass flag does not suppress
    // AAASM's enforcement wiring. Both must coexist in the command.
    let (_tmp, bin) = stub_binary();
    let adapter = ClaudeCodeAdapter::with_overrides(Some(bin), None);
    let args = vec!["--bypassPermissions".to_string()];
    let cmd = adapter
        .build_launch_command(&args, "agent-1", None, Some("http://aa-proxy:8080"))
        .unwrap();

    let envs = cmd_envs(&cmd);
    let got_args = cmd_args(&cmd);

    assert!(
        got_args.contains(&"--bypassPermissions".to_string()),
        "--bypassPermissions must be preserved in args"
    );
    assert_eq!(
        envs.get("HTTPS_PROXY").and_then(|v| v.as_deref()),
        Some("http://aa-proxy:8080"),
        "HTTPS_PROXY must still be set — enforcement is independent of Claude's permission flag"
    );
}

#[test]
fn aa_agent_id_is_always_set_for_policy_attribution() {
    // Every Claude Code process launched via the adapter must carry AA_AGENT_ID
    // so the proxy and gateway can attribute intercepted calls to the right agent.
    let (_tmp, bin) = stub_binary();
    let adapter = ClaudeCodeAdapter::with_overrides(Some(bin), None);

    // With --bypassPermissions in args.
    let args = vec!["--bypassPermissions".to_string()];
    let cmd = adapter
        .build_launch_command(
            &args,
            "claude-code-test",
            Some("pioneer-team"),
            Some("http://aa-proxy:8080"),
        )
        .unwrap();
    let envs = cmd_envs(&cmd);

    assert_eq!(
        envs.get("AA_AGENT_ID").and_then(|v| v.as_deref()),
        Some("claude-code-test"),
        "AA_AGENT_ID must always be set for policy attribution"
    );
    assert_eq!(
        envs.get("AA_TEAM_ID").and_then(|v| v.as_deref()),
        Some("pioneer-team"),
        "AA_TEAM_ID must be set when provided"
    );
}

#[test]
fn build_launch_command_errors_when_binary_not_found() {
    let adapter = ClaudeCodeAdapter::with_overrides(Some(PathBuf::from("/no/such/binary")), None);
    let result = adapter.build_launch_command(&["--bypassPermissions".to_string()], "agent-1", None, None);
    assert!(
        matches!(result, Err(aa_core::AdapterError::ToolNotFound)),
        "must return ToolNotFound when binary does not exist"
    );
}

// ── Docker integration tests ─────────────────────────────────────────────────
//
// These tests exercise the full enforcement stack:
//
//   claude-stub  --[HTTPS_PROXY]-->  aa-proxy  -->  stub-upstream (example.com)
//                                       │
//                               gateway-mock (audit events)
//
// Network isolation is enforced by Docker: claude-stub can only reach
// stub-upstream through aa-proxy, not directly.
//
// PROCESS ISOLATION NOTE: docker compose manipulates shared system state
// (containers, networks, volumes). These tests must run with --test-threads=1
// to avoid races between compose up/down across parallel test processes.

#[cfg(feature = "docker-integration")]
mod docker_tests {
    use std::process::{Command, Output};
    use std::time::Duration;

    // Absolute path to the docker-compose file, resolved at compile time from
    // the crate manifest directory (aa-devtool-claude-code/) one level up to
    // the workspace root. Using env!("CARGO_MANIFEST_DIR") avoids cwd-relative
    // path issues: cargo nextest and cargo llvm-cov both set cwd to the crate
    // directory, not the workspace root.
    const COMPOSE_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ci/integration/bypass-permissions/docker-compose.yml"
    );
    // Project name used to namespace containers so concurrent test runs don't collide.
    const COMPOSE_PROJECT: &str = "aaasm-bypass-test";

    /// Returns true when `docker compose` is available on this runner.
    ///
    /// Coverage and SonarQube jobs compile the `docker-integration` feature via
    /// `--all-features` but have no Docker daemon. This guard lets those tests
    /// exit cleanly without marking the job as failed.
    fn docker_available() -> bool {
        Command::new("docker")
            .args(["compose", "version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Run a docker compose command and return its output.
    fn compose(args: &[&str]) -> Output {
        Command::new("docker")
            .args(["compose", "-f", COMPOSE_FILE, "-p", COMPOSE_PROJECT])
            .args(args)
            .output()
            .expect("docker compose must be available in PATH")
    }

    /// Wait until a container's Docker healthcheck reports "healthy", or panic.
    fn wait_healthy(service: &str, timeout_secs: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            let out = Command::new("docker")
                .args([
                    "inspect",
                    "--format",
                    "{{.State.Health.Status}}",
                    &format!("{COMPOSE_PROJECT}-{service}-1"),
                ])
                .output()
                .expect("docker inspect must work");
            let status = String::from_utf8_lossy(&out.stdout);
            if status.trim() == "healthy" {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("service {service} did not become healthy within {timeout_secs}s; last status: {status}");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Wait until aa-proxy accepts a TCP connection on the host-mapped port.
    ///
    /// aa-proxy is built on distroless/static which has no shell or wget, so
    /// CMD-SHELL healthchecks cannot run inside that container. Instead we poll
    /// TCP connectivity from the host via the published port mapping.
    fn wait_proxy_tcp(timeout_secs: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            if std::net::TcpStream::connect("127.0.0.1:8080").is_ok() {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("aa-proxy did not accept TCP connections on 127.0.0.1:8080 within {timeout_secs}s");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Bring up the docker-compose stack and wait for all services to be ready.
    ///
    /// Returns a guard that runs `docker compose down` on drop, ensuring cleanup
    /// even if the test panics.
    struct ComposeGuard;

    impl ComposeGuard {
        fn up() -> Self {
            // Pull/build images and start all services detached.
            // Do NOT use --wait: it requires all services to pass healthchecks; aa-proxy
            // is distroless and cannot run CMD-SHELL healthchecks.
            // Service readiness is verified by the custom wait_* helpers below.
            let out = compose(&["up", "--build", "--detach"]);
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                panic!("docker compose up failed:\n{stderr}");
            }
            wait_healthy("gateway-mock", 30);
            wait_healthy("stub-upstream", 30);
            // aa-proxy is distroless — no CMD-SHELL healthcheck possible.
            // Poll TCP readiness via the host-mapped port instead.
            wait_proxy_tcp(60);
            Self
        }
    }

    impl Drop for ComposeGuard {
        fn drop(&mut self) {
            let _ = compose(&["down", "--volumes", "--remove-orphans"]);
        }
    }

    /// Read all recorded requests from the stub-upstream's probe endpoint.
    ///
    /// The stub upstream listens on host port 8181 and returns a JSON array
    /// of every HTTP request it received on port 80 (acting as example.com).
    fn stub_upstream_received_requests() -> Vec<serde_json::Value> {
        // Retry for up to 5 seconds in case the stub hasn't flushed yet.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let out = Command::new("curl").args(["-sf", "http://127.0.0.1:8181"]).output();
            if let Ok(o) = out {
                if let Ok(body) = std::str::from_utf8(&o.stdout) {
                    if let Ok(v) = serde_json::from_str::<Vec<serde_json::Value>>(body) {
                        return v;
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return vec![];
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Read all recorded audit events from the gateway-mock's probe endpoint.
    fn gateway_mock_events() -> Vec<serde_json::Value> {
        let out = Command::new("curl")
            .args(["-sf", "http://127.0.0.1:9000"])
            .output()
            .unwrap_or_else(|_| panic!("failed to query gateway-mock"));
        let body = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str(&body).unwrap_or_default()
    }

    /// Wait until the claude-stub container reaches "running" state.
    ///
    /// The container's main command starts with `apk add curl`, which takes time.
    /// For tests that exec into the container with commands that don't depend on curl
    /// being installed (e.g. wget from busybox), waiting for "running" is sufficient.
    fn wait_claude_stub_running(timeout_secs: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            let out = Command::new("docker")
                .args([
                    "inspect",
                    "--format",
                    "{{.State.Status}}",
                    &format!("{COMPOSE_PROJECT}-claude-stub-1"),
                ])
                .output()
                .unwrap();
            let status = String::from_utf8_lossy(&out.stdout);
            if status.trim() == "running" {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("claude-stub did not reach running state within {timeout_secs}s; last: {status}");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Wait until claude-stub prints its sentinel log line.
    ///
    /// claude-stub runs curl then prints "CLAUDE_STUB_DONE" and then sleeps forever
    /// (keeping the container alive so `exec_in_claude_stub` can run). Waiting for
    /// this sentinel guarantees that curl is installed and the initial request has
    /// completed before any assertion reads logs or runs exec.
    fn wait_claude_stub_done(timeout_secs: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            let logs = Command::new("docker")
                .args(["logs", &format!("{COMPOSE_PROJECT}-claude-stub-1")])
                .output()
                .unwrap();
            let combined = String::from_utf8_lossy(&logs.stdout).to_string() + &String::from_utf8_lossy(&logs.stderr);
            if combined.contains("CLAUDE_STUB_DONE") {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("claude-stub did not print CLAUDE_STUB_DONE within {timeout_secs}s;\nlogs:\n{combined}");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Execute a shell command inside the `claude-stub` container.
    fn exec_in_claude_stub(cmd: &str) -> Output {
        Command::new("docker")
            .args(["exec", &format!("{COMPOSE_PROJECT}-claude-stub-1"), "sh", "-c", cmd])
            .output()
            .expect("docker exec must work")
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[test]
    fn proxy_intercepts_https_traffic_from_claude_stub() {
        if !docker_available() {
            eprintln!("docker not available — skipping docker test");
            return;
        }
        // Proves: the proxy layer observes all outbound HTTPS from the Claude stub,
        // independent of the --bypassPermissions flag.
        //
        // The claude-stub container has HTTPS_PROXY=http://aa-proxy:8080 set (mirroring
        // what ClaudeCodeAdapter::build_launch_command produces) and AA_BYPASS_PERMISSIONS=true
        // (documenting the --bypassPermissions scenario). Despite this flag, all HTTPS
        // traffic is routed through aa-proxy.
        let _guard = ComposeGuard::up();

        // Wait for claude-stub to finish its curl attempt.
        // The container stays alive (sleep infinity) so we wait for the sentinel log line
        // rather than polling for container exit.
        wait_claude_stub_done(60);

        // The proxy should have logged something — check proxy container logs for
        // evidence that the CONNECT tunnel was established (proxy observed the attempt).
        let proxy_logs = Command::new("docker")
            .args(["logs", &format!("{COMPOSE_PROJECT}-aa-proxy-1")])
            .output()
            .unwrap();
        let log_text =
            String::from_utf8_lossy(&proxy_logs.stdout).to_string() + &String::from_utf8_lossy(&proxy_logs.stderr);

        // The proxy logs "accepted connection" for every TCP connection it handles.
        // This proves the proxy received and processed the claude-stub's CONNECT request.
        assert!(
            log_text.contains("accepted connection") || log_text.contains("CONNECT"),
            "proxy must log evidence of the intercepted connection;\nproxy logs:\n{log_text}"
        );
    }

    #[test]
    fn network_isolation_prevents_direct_access_to_stub_upstream() {
        if !docker_available() {
            eprintln!("docker not available — skipping docker test");
            return;
        }
        // Proves: the Docker network topology correctly forces all traffic from
        // claude-stub through aa-proxy. claude-stub cannot reach stub-upstream directly.
        //
        // This is the network-level equivalent of eBPF's kernel enforcement:
        // even if Claude tried to bypass the proxy (ignoring HTTPS_PROXY), it
        // would fail because the network path doesn't exist.
        let _guard = ComposeGuard::up();

        // Wait for claude-stub to enter the running state. We use wget (busybox,
        // always available in Alpine) so we don't need to wait for apk to install curl.
        wait_claude_stub_running(30);

        // Attempt a direct HTTP request from claude-stub to stub-upstream on port 80,
        // bypassing the proxy entirely. wget is always available in Alpine (busybox).
        let out = exec_in_claude_stub("wget -T 3 -q -O /dev/null http://stub-upstream:80 2>&1; echo EXIT:$?");
        let output = String::from_utf8_lossy(&out.stdout);

        // On a correctly isolated network stub-upstream is on backend-net, not proxy-net,
        // so its hostname is not resolvable from claude-stub and wget exits non-zero.
        // EXIT:0 means wget succeeded — that would be a network-isolation failure.
        assert!(
            !output.contains("EXIT:0"),
            "direct access to stub-upstream must be blocked by network isolation; wget must not succeed;\ngot: {output}"
        );
    }

    #[test]
    #[ignore = "requires proxy deny capability: aa-proxy must return 403 when policy denies the request. \
                Track implementation separately and remove #[ignore] when done."]
    fn stub_upstream_receives_zero_requests_when_policy_denies() {
        if !docker_available() {
            eprintln!("docker not available — skipping docker test");
            return;
        }
        // Once proxy deny is implemented: policy denies outbound to example.com,
        // so the request is blocked at aa-proxy and never reaches stub-upstream.
        let _guard = ComposeGuard::up();

        // Wait for claude-stub to finish.
        std::thread::sleep(Duration::from_secs(10));

        let received = stub_upstream_received_requests();
        assert!(
            received.is_empty(),
            "stub-upstream must receive 0 requests when proxy denies the policy;\ngot: {received:?}"
        );
    }

    #[test]
    #[ignore = "requires gateway-proxy audit event emission: aa-proxy must POST a policy_violation event \
                to the gateway when a request is denied. Track implementation separately."]
    fn gateway_receives_policy_violation_audit_event() {
        if !docker_available() {
            eprintln!("docker not available — skipping docker test");
            return;
        }
        // Once gateway-proxy sync is implemented: gateway-mock must receive a
        // policy_violation event with agent=claude-code and flag=--bypassPermissions.
        let _guard = ComposeGuard::up();

        std::thread::sleep(Duration::from_secs(10));

        let events = gateway_mock_events();
        let violation = events.iter().find(|e| {
            e.get("action").and_then(|a| a.as_str()) == Some("policy_violation")
                || e.get("type").and_then(|t| t.as_str()) == Some("policy_violation")
        });
        assert!(
            violation.is_some(),
            "gateway must receive a policy_violation audit event;\nevents: {events:?}"
        );
        if let Some(v) = violation {
            let agent = v.get("agent").and_then(|a| a.as_str()).unwrap_or("");
            assert!(
                agent.contains("claude-code"),
                "policy_violation event must identify the agent as claude-code; got: {agent}"
            );
        }
    }
}
