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
//!   command is `echo`. Nothing about the Claude Code adapter, and nothing at
//!   all about the proxy, is established by it.
//! * `aa-cli/src/commands/run.rs`'s `build_child_env_*` unit tests assert the
//!   env **map** is built correctly, which is one function call away from
//!   asserting a launched process actually received it.
//!
//! So this test closes the loop the AC describes: the real `aasm` binary, the
//! real `ClaudeCodeAdapter` resolved through `aa_devtool::registry` (the same
//! path production takes — no override constructor), a real gateway
//! `AgentLifecycleService` the session genuinely registers with, a real child
//! process, and assertions made on what that child *observed in its own
//! environment* rather than on what the parent intended to send it.
//!
//! Since AAASM-5323 the identity in that environment is no longer whatever a
//! mock gateway put in a JSON body: `aasm run` derives a `did:key`, proves
//! possession of the matching key over a server-issued nonce, and registers over
//! gRPC. So the expectations below are *derived* the way the CLI derives them
//! rather than picked, and the monitoring claim is read off a real registry.
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

#[allow(unused_imports)]
mod grpc_gateway_support;

#[cfg(unix)]
mod governed_launch {
    use super::grpc_gateway_support::{expected_did, expected_registration_id, GrpcGateway};
    use super::proxy_trust_support::{aasm_binary, TrustedProxy};
    use super::spike_support::RealHomeGuard;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// Identity the operator names on the command line. The gateway does not
    /// issue identity any more — it *accepts* one — so these are inputs, and the
    /// values the session ends up with are derived from them below.
    const AGENT_ID: &str = "aaasm1112-agent";
    const TEAM_ID: &str = "aaasm1112-team";

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
  echo "AA_AGENT_DID=$AA_AGENT_DID"
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

    /// The whole of AC4 in one run: the session's registered identity reaches
    /// the launched tool, the proxy *this host verified* reaches it too, and the
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
        //
        // The real `AgentLifecycleService`. A launch that cannot satisfy its
        // registration gate does not happen at all, so reaching the assertions
        // below is itself evidence the handshake succeeded.
        let gateway = GrpcGateway::start().await?;

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
            // Registration is a gRPC call to `AgentLifecycleService`; `--api-url`
            // names the HTTP surface and no longer reaches this path.
            .env("AA_GATEWAY_ENDPOINT", gateway.endpoint())
            .args([
                "run",
                "claude",
                "--agent-id",
                AGENT_ID,
                "--team-id",
                TEAM_ID,
            ]);
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
        let did = expected_did(AGENT_ID);
        for (key, expected) in [
            ("AA_AGENT_ID", AGENT_ID.to_string()),
            ("AA_AGENT_DID", did.clone()),
            ("AA_REGISTRATION_ID", expected_registration_id(Some(TEAM_ID), &did)),
            ("AA_TEAM_ID", TEAM_ID.to_string()),
        ] {
            assert_eq!(
                seen.get(key).map(String::as_str),
                Some(expected.as_str()),
                "the launched tool must carry the registered identity in `{key}`; saw:\n{raw}",
            );
        }

        // `AA_TRACE_ID` / `AA_SESSION_ID` are minted by this process, not issued
        // by the gateway, so there is no constant to pin them to — but they must
        // be present and distinct, because a launch whose correlation ids are
        // absent or identical cannot be traced back to it.
        let trace = seen.get("AA_TRACE_ID").cloned().unwrap_or_default();
        let session = seen.get("AA_SESSION_ID").cloned().unwrap_or_default();
        assert!(!trace.is_empty(), "the launch must carry a trace id; saw:\n{raw}");
        assert!(!session.is_empty(), "the launch must carry a session id; saw:\n{raw}");
        assert_ne!(
            trace, session,
            "trace and session must be distinct ids, not one value copied twice",
        );

        // ── proxy, as the launched tool saw it ─────────────────────────────
        //
        // AAASM-1112 finding (2) is resolved — twice over, and the second time
        // by a route the original note did not anticipate.
        //
        // AAASM-5324 (via AAASM-5327, #1855) fixed the discard: the adapter's
        // normalised `http://host:port` now actually reaches the child, where
        // before `spawn_and_wait` threw the adapter's whole environment away.
        // AAASM-5331 then realigned this assertion, which had been left pinning
        // the pre-fix bare `host:port`.
        //
        // AAASM-5323 changes what the right answer *is*. The child is routed at
        // the endpoint **this host** resolved and verified, and nothing on the
        // registration path names a proxy any more — the field was removed from
        // the response entirely. A gateway reply is remote and unauthenticated,
        // so it is not entitled to choose where this session's traffic goes.
        // `PROXY_ADDR` survives only as a deliberately dead test-local constant,
        // so a regression that reinstated *any* remote source for the route
        // would show up here as a wrong value rather than as a silent pass.
        let expected_proxy = proxy.expected_proxy_url();
        for key in ["HTTPS_PROXY", "HTTP_PROXY"] {
            assert_eq!(
                seen.get(key).map(String::as_str),
                Some(expected_proxy.as_str()),
                "the launched tool must be routed at the verified local proxy via `{key}`; an \
                 empty value would mean no interception at all. Saw:\n{raw}",
            );
        }

        // ── monitoring: the gateway saw the session open and close ─────────
        let registrations = gateway.session().registrations();
        assert_eq!(
            registrations.len(),
            1,
            "exactly one registration should have opened the session",
        );
        let request = &registrations[0];
        assert_eq!(
            request.agent_id.as_ref().map(|id| id.agent_id.as_str()),
            Some(did.as_str()),
            "the session must be registered under the identity the tool was launched with",
        );
        assert_eq!(
            request.name, "claude_code",
            "the gateway must be told which tool is running",
        );
        assert_eq!(
            request.version, "2.1.999",
            "the registration must carry the detected version, not a placeholder",
        );
        assert!(
            !request.possession_proof.is_empty() && !request.registration_nonce.is_empty(),
            "the session must have proved key possession over a server nonce to be registered",
        );
        assert_eq!(
            gateway.session().deregistrations(),
            vec![did.clone()],
            "the session must be closed under the identity that opened it",
        );
        assert!(
            !gateway.holds(Some(TEAM_ID), &did),
            "the agent is still registered after the tool exited; the session was never closed",
        );

        // ── nothing of the developer's was touched ─────────────────────────
        real_home.assert_unchanged("cli_run_claude_governed_launch");
        assert!(
            home.join(".claude").join("settings.json").is_file(),
            "the managed settings must have landed in the redirected home",
        );

        Ok(())
    }

    /// The other half of fail-closed: a launch that cannot register starts
    /// nothing.
    ///
    /// This test used to pin the *defect* — `aasm run` registered by
    /// `POST /api/v1/agents`, a route no gateway serves, so it always failed.
    /// The route was deliberately not added (see
    /// `the_http_surface_still_offers_no_registration_route` below); the CLI was
    /// moved onto the gRPC gate instead. What survives, and is the part worth
    /// keeping, is the claim the old test made incidentally: a session the
    /// gateway never accepted must not produce a running tool.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_launch_that_cannot_register_never_starts_the_tool() -> anyhow::Result<()> {
        // A verified proxy, so the run reaches the registration call this test
        // is about instead of being refused before it (AAASM-5323).
        let proxy = TrustedProxy::start()?;

        // A gateway endpoint nothing is listening on: bound and released.
        let dead = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.local_addr()?
        };

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
            .env("AA_GATEWAY_ENDPOINT", format!("http://{dead}"))
            .args(["run", "claude", "--agent-id", AGENT_ID])
            .output()
            .expect("aasm run claude should execute");

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "a session the gateway never accepted must not exit successfully\nstderr:\n{stderr}",
        );
        assert!(
            stderr.contains("refusing to launch unregistered"),
            "the operator must be told the launch was refused and why, not left to infer it from \
             an exit code:\n{stderr}",
        );
        assert!(
            !dump.exists(),
            "the tool was launched for a session with no governed identity — an ungoverned launch \
             wearing a governed launch's name is worse than no launch",
        );
        Ok(())
    }

    /// The bypass that was considered and rejected: an HTTP registration route.
    ///
    /// `aasm run` was fixed by putting the CLI *through* the gRPC gate, not by
    /// teaching the API to accept a body with no key, no challenge and no proof.
    /// This asserts that decision is still in force — if a `POST` on this path
    /// ever starts succeeding, there is a second registration contract, and it
    /// is the weaker one.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_http_surface_still_offers_no_registration_route() -> anyhow::Result<()> {
        let fixture = super::common::cli::CliFixture::start().await?;

        let response = reqwest::Client::new()
            .post(format!("{}/api/v1/agents", fixture.base_url()))
            .json(&serde_json::json!({
                "kind": "claude_code",
                "version": "2.1.999",
                "agent_id": AGENT_ID,
            }))
            .send()
            .await?;

        assert!(
            !response.status().is_success(),
            "the API accepted a registration carrying no public key, no challenge and no \
             possession proof. That is a second, weaker registration contract reachable by \
             anything that can speak HTTP (status {})",
            response.status(),
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
