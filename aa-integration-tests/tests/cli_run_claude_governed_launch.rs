//! AAASM-1112 — executable evidence for AAASM-201 AC4.
//!
//! > `aa run claude` launches Claude Code with identity, proxy, and
//! > monitoring — end-to-end
//!
//! # Why this file exists
//!
//! The verification of AAASM-201 found AC4 to be the one acceptance criterion
//! with no test that actually demonstrates it. What existed measured pieces:
//!
//! * `aa-integration-tests/tests/cli_run.rs` drives the real `aasm` binary but
//!   only in `--dry-run`, which short-circuits before `detect()`, before
//!   registration and before any child is spawned. A printed plan is
//!   configuration, not behaviour.
//! * `aa-cli/tests/run_command.rs` does spawn a child and does exercise
//!   register/deregister, but through a hand-written stub adapter whose launch
//!   command is `echo`, with `proxy_addr: null`. Nothing about the Claude Code
//!   adapter, and nothing at all about the proxy, is established by it.
//! * `aa-cli/src/commands/run.rs`'s `build_child_env_*` unit tests assert the
//!   env **map** is built correctly, which is one function call away from
//!   asserting a launched process actually received it.
//!
//! So this test closes the loop the AC describes: the real `aasm` binary, the
//! real `ClaudeCodeAdapter` resolved through `aa_devtool::registry` (the same
//! path production takes — no override constructor), a real HTTP gateway that
//! hands back a proxy address, a real child process, and assertions made on
//! what that child *observed in its own environment* rather than on what the
//! parent intended to send it.
//!
//! # Safety
//!
//! `ClaudeCodeAdapter::new()` resolves its binary with `which claude` and its
//! settings file from `$HOME`, so a careless version of this test would rewrite
//! the developer's real `~/.claude/settings.json` and launch their real Claude
//! Code. Every root the adapter reads is therefore redirected into a temp dir on
//! the **child** `aasm` process only (`HOME`, `PATH`, `CLAUDE_CONFIG_DIR`,
//! `AASM_STATE_DIR`, `AA_CA_DIR`, `AASM_CLAUDE_MANAGED_ROOT`, and the working
//! directory); no process-global environment state in this test binary is
//! mutated. The final assertion reuses the AAASM-5283 conformance suite's
//! `RealHomeGuard`, which fingerprints the developer's settings file on length
//! and mtime and never reads its contents — that file is in daily use and may
//! hold credentials, so a byte comparison would print them into the failure
//! message and from there into the CI log.

// `common/mod.rs` carries its own inner `#![allow(dead_code)]`; only the unused
// imports need allowing here (this file uses just `common::cli::CliFixture`).
#[allow(unused_imports)]
mod common;

// `RealHomeGuard` is reused rather than reimplemented: it fingerprints the live
// settings file on length+mtime and never reads its contents, because that file
// is in daily use and may hold credentials — a byte comparison would print them
// into the failure message and therefore into CI logs.
#[allow(dead_code, unused_imports)]
mod spike_support;

#[allow(unused_imports)]
mod proxy_trust_support;

#[cfg(unix)]
mod governed_launch {
    use super::proxy_trust_support::{aasm_binary, TrustedProxy};
    use super::spike_support::RealHomeGuard;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use axum::extract::{Path as AxumPath, State};
    use axum::http::StatusCode;
    use axum::routing::{delete, post};
    use axum::{Json, Router};

    /// Identity the mock gateway issues. Distinct, obviously-synthetic values so
    /// a wrong-field mix-up in the child's environment is a failure rather than
    /// an accidental match.
    const AGENT_ID: &str = "aaasm1112-agent";
    const REGISTRATION_ID: &str = "aaasm1112-registration";
    const TRACE_ID: &str = "aaasm1112-trace";
    const SESSION_ID: &str = "aaasm1112-session";
    const TEAM_ID: &str = "aaasm1112-team";
    /// The address the gateway assigns this session. Nothing listens on it, and
    /// since AAASM-5323 nothing is supposed to route at it either: the endpoint
    /// is resolved and verified host-side, so this value is the decoy that makes
    /// the proxy assertion below mean something.
    const PROXY_ADDR: &str = "127.0.0.1:19999";

    /// What the mock gateway saw. Registration and deregistration are the
    /// monitoring half of the AC: the gateway knows the session began and knows
    /// it ended.
    #[derive(Default)]
    struct Recorder {
        registrations: Vec<serde_json::Value>,
        deregistrations: Vec<String>,
    }

    type Shared = Arc<Mutex<Recorder>>;

    async fn register(
        State(rec): State<Shared>,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        rec.lock().expect("recorder poisoned").registrations.push(body);
        (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "agent_id": AGENT_ID,
                "registration_id": REGISTRATION_ID,
                "trace_id": TRACE_ID,
                "session_id": SESSION_ID,
                "team_id": TEAM_ID,
                "proxy_addr": PROXY_ADDR,
            })),
        )
    }

    async fn deregister(State(rec): State<Shared>, AxumPath(id): AxumPath<String>) -> StatusCode {
        rec.lock().expect("recorder poisoned").deregistrations.push(id);
        StatusCode::NO_CONTENT
    }

    /// A `claude` stand-in that answers `--version` with a supported version and,
    /// when launched, writes the governance variables it can see to a file.
    ///
    /// Reporting from inside the child is the point: it is the only vantage from
    /// which "the tool was launched with identity and proxy" is an observation
    /// rather than an inference about the parent's intent.
    fn write_stub_binary(dir: &Path) -> std::io::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let bin_dir = dir.join("bin");
        std::fs::create_dir_all(&bin_dir)?;
        let bin = bin_dir.join("claude");
        std::fs::write(
            &bin,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "2.1.999 (Claude Code)"
  exit 0
fi
{
  echo "AA_AGENT_ID=$AA_AGENT_ID"
  echo "AA_TRACE_ID=$AA_TRACE_ID"
  echo "AA_SESSION_ID=$AA_SESSION_ID"
  echo "AA_REGISTRATION_ID=$AA_REGISTRATION_ID"
  echo "AA_TEAM_ID=$AA_TEAM_ID"
  echo "HTTPS_PROXY=$HTTPS_PROXY"
  echo "HTTP_PROXY=$HTTP_PROXY"
  echo "ARGV=$*"
} > "$AA_TEST_ENV_DUMP"
exit 0
"#,
        )?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        Ok(bin)
    }

    /// Parse the `KEY=value` dump the stub wrote.
    fn parse_dump(raw: &str) -> BTreeMap<String, String> {
        raw.lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// The whole of AC4 in one run: identity issued by the gateway reaches the
    /// launched tool, the proxy the gateway assigned reaches it too, and the
    /// gateway observes both the start and the end of the session.
    #[tokio::test(flavor = "multi_thread")]
    async fn run_claude_launches_the_tool_with_identity_proxy_and_a_monitored_session() -> anyhow::Result<()> {
        let real_home = RealHomeGuard::capture();

        // ── a proxy this host can vouch for ────────────────────────────────
        //
        // Without one the launch is refused outright (AAASM-5323), so AC4's
        // "launches Claude Code with identity, proxy and monitoring" has a live
        // proxy as its precondition rather than a gateway-supplied string.
        let proxy = TrustedProxy::start()?;

        // ── the gateway ────────────────────────────────────────────────────
        let recorder: Shared = Arc::new(Mutex::new(Recorder::default()));
        let app = Router::new()
            .route("/api/v1/agents", post(register))
            .route("/api/v1/agents/{id}", delete(deregister))
            .with_state(recorder.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let api_url = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        // ── a host that is entirely ours ───────────────────────────────────
        let tmp = tempfile::tempdir()?;
        let root = tmp.path();
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&project)?;
        let stub = write_stub_binary(root)?;
        let dump = root.join("child-env.txt");

        // `PATH` is prefixed rather than replaced: `build_launch_command`'s
        // `which` probe must find our stub first, while the child `aasm` keeps
        // whatever else it needs from the host.
        let path_var = match std::env::var_os("PATH") {
            Some(existing) => {
                let mut parts = vec![stub.parent().expect("stub has a parent").to_path_buf()];
                parts.extend(std::env::split_paths(&existing));
                std::env::join_paths(parts)?
            }
            None => std::env::join_paths([stub.parent().expect("stub has a parent")])?,
        };

        // ── the run ────────────────────────────────────────────────────────
        let mut cmd = std::process::Command::new(aasm_binary());
        cmd.current_dir(&project)
            .env("HOME", &home)
            .env("PATH", &path_var)
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("AASM_STATE_DIR", root.join("state"))
            .env("AA_CA_DIR", root.join("ca"))
            .env("AASM_CLAUDE_MANAGED_ROOT", root.join("managed"))
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("AA_TEST_ENV_DUMP", &dump)
            .args(["--api-url", &api_url, "run", "claude"]);
        let out = cmd.output().expect("aasm run claude should execute");

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "aasm run claude should exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}",
        );

        // ── identity, as the launched tool saw it ──────────────────────────
        let raw = std::fs::read_to_string(&dump).unwrap_or_else(|e| {
            panic!(
                "the launched tool wrote no environment dump ({e}) — nothing was launched, so \
                 nothing about AC4 is established\nstdout:\n{stdout}\nstderr:\n{stderr}"
            )
        });
        let seen = parse_dump(&raw);
        for (key, expected) in [
            ("AA_AGENT_ID", AGENT_ID),
            ("AA_TRACE_ID", TRACE_ID),
            ("AA_SESSION_ID", SESSION_ID),
            ("AA_REGISTRATION_ID", REGISTRATION_ID),
            ("AA_TEAM_ID", TEAM_ID),
        ] {
            assert_eq!(
                seen.get(key).map(String::as_str),
                Some(expected),
                "the launched tool must carry the identity the gateway issued in `{key}`; saw:\n{raw}",
            );
        }

        // ── proxy, as the launched tool saw it ─────────────────────────────
        //
        // AAASM-1112 finding (2) is resolved, and by a route the original note
        // did not anticipate: the child is routed at the endpoint *this host*
        // resolved and verified, in normalised URL form. The gateway's
        // `PROXY_ADDR` is deliberately a different, dead address — a
        // registration response is remote and unauthenticated, so it is not
        // entitled to choose where this session's traffic goes (AAASM-5323).
        let expected_proxy = proxy.expected_proxy_url();
        for key in ["HTTPS_PROXY", "HTTP_PROXY"] {
            assert_eq!(
                seen.get(key).map(String::as_str),
                Some(expected_proxy.as_str()),
                "the launched tool must be routed at the verified local proxy via `{key}`. \
                 `{PROXY_ADDR}` or `http://{PROXY_ADDR}` here would mean the gateway's response \
                 chose the route; an empty value would mean no interception at all. Saw:\n{raw}",
            );
        }

        // ── monitoring: the gateway saw the session open and close ─────────
        let rec = recorder.lock().expect("recorder poisoned");
        assert_eq!(
            rec.registrations.len(),
            1,
            "exactly one registration should have opened the session; saw {:?}",
            rec.registrations,
        );
        let body = &rec.registrations[0];
        assert_eq!(
            body.get("kind").and_then(serde_json::Value::as_str),
            Some("claude_code"),
            "the gateway must be told which tool is running; body: {body}",
        );
        assert_eq!(
            body.get("version").and_then(serde_json::Value::as_str),
            Some("2.1.999"),
            "the registration must carry the detected version, not a placeholder; body: {body}",
        );
        assert_eq!(
            rec.deregistrations,
            vec![REGISTRATION_ID.to_string()],
            "the session must be closed with the registration id the gateway issued",
        );
        drop(rec);

        // ── nothing of the developer's was touched ─────────────────────────
        real_home.assert_unchanged("cli_run_claude_governed_launch");
        assert!(
            home.join(".claude").join("settings.json").is_file(),
            "the managed settings must have landed in the redirected home",
        );

        server.abort();
        Ok(())
    }

    /// AAASM-1112 finding (1), measured against the **real** gateway rather than
    /// a mock: `aasm run` registers by `POST /api/v1/agents`, and the Agent
    /// Assembly API does not serve that. `aa-api`'s router mounts
    /// `.route("/agents", get(agents::list_agents))` and `openapi/v1.yaml`
    /// declares `get` as the only method on `/api/v1/agents`.
    ///
    /// The consequence is the whole of AC4: registration fails, so the launcher
    /// returns before `build_launch_command`, and Claude Code is never started.
    /// The passing test above establishes that identity, proxy and session
    /// monitoring flow correctly *given* a gateway that answers the call — which
    /// no shipped gateway does.
    ///
    /// Asserting the failure is deliberate. It is the honest floor: a run that
    /// cannot register must not be readable as a governed launch. If a future
    /// change adds the endpoint, this test fails and forces AC4's verdict — and
    /// this file's expectations — to be re-derived rather than silently inherited.
    #[tokio::test(flavor = "multi_thread")]
    async fn against_the_real_gateway_the_launcher_cannot_register_and_never_starts_the_tool() -> anyhow::Result<()> {
        let fixture = super::common::cli::CliFixture::start().await?;

        // A verified proxy, so the run reaches the registration call this test
        // is about instead of being refused before it (AAASM-5323).
        let proxy = TrustedProxy::start()?;

        let tmp = tempfile::tempdir()?;
        let root = tmp.path();
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&project)?;
        let stub = write_stub_binary(root)?;
        let dump = root.join("child-env.txt");

        let path_var = {
            let mut parts = vec![stub.parent().expect("stub has a parent").to_path_buf()];
            parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
            std::env::join_paths(parts)?
        };

        let out = std::process::Command::new(aasm_binary())
            .current_dir(&project)
            .env("HOME", &home)
            .env("PATH", &path_var)
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("AASM_STATE_DIR", root.join("state"))
            .env("AA_CA_DIR", root.join("ca"))
            .env("AASM_CLAUDE_MANAGED_ROOT", root.join("managed"))
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("AA_TEST_ENV_DUMP", &dump)
            .args(["--api-url", &fixture.base_url(), "run", "claude"])
            .output()
            .expect("aasm run claude should execute");

        let stderr = String::from_utf8_lossy(&out.stderr);
        println!(
            "MEASURED `aasm run claude` against the real gateway at {}: exit={:?}\nstderr:\n{stderr}",
            fixture.base_url(),
            out.status.code(),
        );

        assert!(
            !out.status.success(),
            "unexpected success: the gateway answered POST /api/v1/agents. NOTE: this pins the \
             CURRENT, DEFECTIVE behaviour on purpose — the designed behaviour is a successful \
             registration (AAASM-5323). A success here means that bug is fixed: invert this \
             assertion and re-derive the AAASM-201 AC4 verdict.\nstderr:\n{stderr}",
        );
        assert!(
            stderr.contains("gateway registration failed"),
            "the failure must be the registration call, not something incidental:\n{stderr}",
        );
        assert!(
            !dump.exists(),
            "the tool must not have been launched when registration failed — an ungoverned launch \
             is worse than no launch",
        );
        Ok(())
    }
}

/// A skip must be legible in the output; a test binary that silently contains
/// no tests is indistinguishable from a passing one.
#[cfg(not(unix))]
#[test]
fn governed_launch_is_not_measured_on_this_host() {
    println!(
        "SKIP [AAASM-201 AC4]: the governed-launch evidence needs a POSIX shell stand-in for the \
         `claude` binary; this host is {}. AC4 is NOT evidenced here.",
        std::env::consts::OS
    );
}
