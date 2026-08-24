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
//! # The gates a governed launch passes, and why they are ordered
//!
//! `aasm run` refuses on three separate grounds, checked in order: it cannot
//! vouch for a local proxy (AAASM-5323), no effective policy resolves
//! (AAASM-5349), or the gateway will not accept the session. Every scenario here
//! therefore supplies a verified proxy, a policy, and a live gateway — except
//! the one that is *about* a gate, which supplies the other two so the refusal
//! it measures is attributable to the gate it names rather than to whichever
//! check happened to fire first.
//!
//! The policies are narrow and enforcing rather than allow-all: this file's
//! claim is about a *governed* launch, and a session running under a policy that
//! restricts nothing would make that claim untrue.
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
/// The evidence ledger (AAASM-5465), declared once per test binary.
///
/// The support modules re-export it rather than declaring their own, because a
/// binary including two of them would otherwise load the same file twice.
#[path = "evidence/mod.rs"]
pub mod evidence;

#[allow(unused_imports)]
mod common;

// `RealHomeGuard` is reused rather than reimplemented: it fingerprints the live
// settings file on length+mtime and never reads its contents, because that file
// is in daily use and may hold credentials — a byte comparison would print them
// into the failure message and therefore into CI logs.
#[allow(dead_code, unused_imports)]
mod spike_support;

// The AAASM-5326 outcome ledger and the two skip guards that write to it. The
// real-tool scenario below declares `measured` / `skipped` / `not_measured` the
// same way the conformance suite's real-tool lane does, so a run that declined
// to measure is machine-readably different from one that measured.
#[allow(dead_code, unused_imports)]
mod conformance_support;

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

    /// Write the policy this host's sessions run under and return its path.
    ///
    /// Since AAASM-5349 a governed launch refuses when no effective policy
    /// resolves, so every run here has to supply one — the same way it has to
    /// supply a gateway and a verified proxy. It is a precondition of the
    /// scenario, not part of what the scenario measures.
    ///
    /// Deliberately a **narrow, enforced** policy rather than the allow-all
    /// artifact: these tests claim to exercise a *governed* launch, and a
    /// session running under a policy that restricts nothing would make that
    /// claim untrue. One real allow and one real deny is the smallest policy
    /// that is honestly enforcing something.
    ///
    /// Passed with `--policy` rather than installed at `$HOME/.aasm/policy.yaml`
    /// so the run measures the same thing on a developer machine that happens to
    /// have an operator policy installed and on a bare CI runner.
    fn write_test_policy(dir: &Path) -> std::io::Result<PathBuf> {
        let path = dir.join("policy.yaml");
        std::fs::write(
            &path,
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n\
             \x20 name: aaasm1112-governed-launch\n\
             spec:\n\
             \x20 tools:\n\
             \x20   read_file:\n\
             \x20     allow: true\n\
             \x20   shell:\n\
             \x20     allow: false\n",
        )?;
        Ok(path)
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
        let policy = write_test_policy(root)?;
        let dump = root.join("child-env.txt");

        // `PATH` is prefixed rather than replaced: `build_launch_command`'s
        // `which` probe must find our stub first, while the child `aasm` keeps
        // whatever else it needs from the host. `proxy.proxy_bin_dir()` is
        // included too (AAASM-5863): the child `aasm run` now resolves and
        // spawns its own dedicated `aa-proxy` rather than trusting the
        // already-running one `TrustedProxy::start()` stood up, so the same
        // binary directory that command used must also be on *this* PATH, not
        // just the harness process's own.
        let path_var = match std::env::var_os("PATH") {
            Some(existing) => {
                let mut parts = vec![
                    stub.parent().expect("stub has a parent").to_path_buf(),
                    proxy.proxy_bin_dir().to_path_buf(),
                ];
                parts.extend(std::env::split_paths(&existing));
                std::env::join_paths(parts)?
            }
            None => std::env::join_paths([stub.parent().expect("stub has a parent"), proxy.proxy_bin_dir()])?,
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
                "--policy",
                &policy.to_string_lossy(),
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
        let did = expected_did(&root.join("state"), AGENT_ID);
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
        // an endpoint **this host** resolved, and nothing on the registration
        // path names a proxy any more — the field was removed from the response
        // entirely. A gateway reply is remote and unauthenticated, so it is not
        // entitled to choose where this session's traffic goes.
        //
        // AAASM-5863 changes it again: the endpoint is no longer `proxy` (the
        // standalone shared proxy this fixture stands up as this launch's
        // *registration/CA-trust* precondition, per the module doc above) — it
        // is `aasm run`'s own dedicated proxy for this one launch, bound to an
        // ephemeral port `ProxyGuard` picked, which by construction differs
        // from `proxy`'s. Asserting equality with `proxy.expected_proxy_url()`
        // would therefore be asserting the *wrong* thing on correct code; the
        // loopback-and-distinct assertion below is what actually distinguishes
        // "routed through *a* dedicated proxy" from "not routed through a proxy
        // at all" without hard-coding a port this test does not control.
        let standalone_proxy = proxy.expected_proxy_url();
        for key in ["HTTPS_PROXY", "HTTP_PROXY"] {
            let value = seen.get(key).map(String::as_str);
            assert!(
                value.is_some_and(|v| v.starts_with("http://127.0.0.1:")),
                "the launched tool must be routed at a loopback proxy via `{key}`; an empty or \
                 non-loopback value would mean no interception at all. Saw:\n{raw}",
            );
            assert_ne!(
                value,
                Some(standalone_proxy.as_str()),
                "`{key}` names the standalone shared proxy this fixture started for registration/CA \
                 trust, not this launch's own dedicated proxy (AAASM-5863) — the two must be distinct \
                 processes on distinct ports. Saw:\n{raw}",
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
        let policy = write_test_policy(root)?;
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
            .args([
                "run",
                "claude",
                "--policy",
                &policy.to_string_lossy(),
                "--agent-id",
                AGENT_ID,
            ])
            .output()
            .expect("aasm run claude should execute");

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "a session the gateway never accepted must not exit successfully\nstderr:\n{stderr}",
        );

        // Every gate ahead of registration must be *passed*, not merely present.
        //
        // `aasm run` refuses on several grounds, and they are checked in order:
        // proxy trust, then effective policy, then registration. A run that
        // tripped an earlier gate would still exit non-zero and still launch
        // nothing — so it would satisfy this test's other two assertions while
        // establishing nothing about the registration gate this test is named
        // for. Pinning the resolved policy state is what makes the refusal below
        // attributable: the run got past policy resolution, so registration is
        // the gate that stopped it.
        assert!(
            stderr.contains("policy=enforced"),
            "the run must reach registration with an effective policy in hand; if it refused on \
             policy instead, the assertion below would pass for the wrong reason and this test \
             would no longer test what it names:\n{stderr}",
        );
        assert!(
            stderr.contains("refusing to launch unregistered"),
            "the operator must be told the launch was refused and why, not left to infer it from \
             an exit code:\n{stderr}",
        );
        assert!(
            !stderr.contains("refusing to launch ungoverned"),
            "the refusal names a policy or proxy failure, not the registration failure this test \
             exists to measure:\n{stderr}",
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

/// AAASM-1112 — the join the stub-based scenario above cannot assert.
///
/// # The gap this closes
///
/// `run_claude_launches_the_tool_with_identity_proxy_and_a_monitored_session`
/// measures one half of AC4: `aasm run` launches a tool and that tool observes
/// the governance environment. The AAASM-5283 conformance suite's
/// `the_real_binary_launched_through_the_installed_environment_is_protected`
/// measures the other half: the real `claude`, given the environment an install
/// produced, is intercepted and its secret redacted. Composed, the two look like
/// AC4.
///
/// They are not AC4, because the composition rests on an unasserted premise —
/// that the environment `aasm run` hands the child is the environment the
/// install produced. Both halves call the same production
/// `installed_environment()`, so the reasoning is structural rather than
/// assumed; it is also exactly the reasoning that held while AAASM-5327 was
/// live. `spawn_and_wait` discarded the adapter's entire environment, so every
/// governed launch went out without `NODE_EXTRA_CA_CERTS` and was never
/// intercepted, and **both suites stayed green for the whole life of the
/// defect**.
///
/// So this scenario asserts the join directly: the real binary, launched by the
/// real `aasm run`, measured at the provider.
///
/// # Why this needs a proxy the shipped binary cannot be
///
/// See `proxy_trust_support::TrustedProxy::start_intercepting` and
/// `examples/proxy_with_mock_upstream.rs`. In short: `aasm run` will only route
/// at a live process named `aa-proxy` recorded by `aasm proxy start`, and the
/// shipped `aa-proxy` will only dial a real upstream. The process here is the
/// shipped `ProxyServer` with its upstream dial redirected — the interception,
/// scanning and redaction are production code; the identity check that made the
/// launcher accept it is not what this scenario measures.
#[cfg(unix)]
mod real_binary_governed_launch {
    use std::os::unix::process::CommandExt as _;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use aa_core::integration::{IntegrationRequest, ProtectionProfile, ReceiptStore, SettingsScope};
    use aa_core::DevToolKind;
    use aa_devtool_claude_code::{ClaudeCodeAdapter, ClaudeCodeIntegration, ClaudeCodePaths};
    use aa_proxy::tls::CaStore;
    use aa_runtime::devint::adapters::claude_code_registration;
    use aa_runtime::devint::{EngineLifecycle, IntegrationLifecycle};

    use super::conformance_support::{self, Measurement, SYNTHETIC_SECRET};
    use super::grpc_gateway_support::GrpcGateway;
    use super::proxy_trust_support::{aasm_binary, TrustedProxy};
    use super::spike_support::proxy_harness::{install_crypto_provider, ANTHROPIC_HOST};
    use super::spike_support::{assert_recorded_and_secret_absent, RealHomeGuard, TlsCapturingUpstream};

    /// The lane name every printed line and every ledger entry carries.
    const SCENARIO: &str = "AC4 real-tool governed launch";

    /// What the scanner writes in place of an `sk-ant-` match.
    const PLACEHOLDER: &str = "[REDACTED:AnthropicKey]";

    /// Identity the operator names on the command line.
    const AGENT_ID: &str = "aaasm1112-real-agent";

    /// How long to let the launch run before concluding no traffic is coming.
    ///
    /// Generous because the path is long — cargo build, proxy start, a real
    /// integration install, a gateway handshake and then a cold `claude`
    /// start — and because concluding "no traffic" early would turn a slow host
    /// into a false finding.
    const EVIDENCE_PATIENCE: Duration = Duration::from_secs(180);

    /// Kill an orphaned process group on the way out.
    ///
    /// `aasm run` forwards `SIGTERM` to the tool it launched, but a panicking
    /// assertion unwinds past the orderly shutdown. Without this, a real
    /// `claude` would survive the test run with every host pointed at a mock
    /// that no longer exists.
    struct GroupReaper(i32);

    impl Drop for GroupReaper {
        fn drop(&mut self) {
            // SAFETY: the group id is one this test created via `process_group`;
            // `killpg` on an already-reaped group fails harmlessly.
            unsafe { libc::killpg(self.0, libc::SIGKILL) };
        }
    }

    /// Send `signal` to the whole launch group.
    fn signal_group(pgid: i32, signal: i32) {
        // SAFETY: as `GroupReaper::drop`.
        unsafe { libc::killpg(pgid, signal) };
    }

    /// `PATH` with `first` and `second` both prepended, in that order.
    fn path_with_both(first: &Path, second: &Path) -> anyhow::Result<std::ffi::OsString> {
        let mut parts = vec![first.to_path_buf(), second.to_path_buf()];
        parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
        Ok(std::env::join_paths(parts)?)
    }

    /// The last 2 KiB of a captured stream, with the synthetic secret masked.
    ///
    /// Masking is not confidentiality — the value is a compile-time constant in
    /// this repository — but it matches `sk-ant-`, and a log carrying a
    /// credential-shaped literal trips secret scanners on every run.
    fn tail(output: &str) -> String {
        let masked = output.replace(SYNTHETIC_SECRET, "[SYNTHETIC-SECRET]");
        let start = masked.len().saturating_sub(2048);
        masked[masked.char_indices().find(|(i, _)| *i >= start).map_or(0, |(i, _)| i)..].to_string()
    }

    /// The real `claude`, launched by the real `aasm run`, must not deliver the
    /// synthetic secret to the provider.
    ///
    /// Skips visibly — and records the skip in the ledger — where there is no
    /// `claude` or the host is not macOS. Past that pair it has committed to
    /// measuring: a run that captures no traffic is a failed measurement and
    /// fails, because a green lane that answered nothing is precisely the
    /// outcome this scenario exists to rule out.
    #[tokio::test(flavor = "multi_thread")]
    async fn run_claude_launches_the_real_binary_and_the_secret_never_reaches_the_provider() -> anyhow::Result<()> {
        let Some(claude) = conformance_support::require_claude(SCENARIO) else {
            return Ok(());
        };
        if !conformance_support::require_macos(SCENARIO) {
            return Ok(());
        }
        install_crypto_provider();
        let real_home = RealHomeGuard::capture();

        // ── a host that is entirely ours ───────────────────────────────────
        let tmp = tempfile::tempdir()?;
        let root = tmp.path();
        let home = root.join("home");
        let project = root.join("project");
        let state = root.join("state");
        let ca_dir = root.join("ca");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&project)?;
        std::fs::create_dir_all(&ca_dir)?;

        // ── the policy the session runs under ──────────────────────────────
        //
        // A precondition since AAASM-5349, alongside the gateway and the
        // verified proxy: a launch that resolves no effective policy refuses,
        // and a refused launch emits no upstream traffic — so without this the
        // scenario reports NOT MEASURED rather than failing on its own subject.
        //
        // Narrow and enforcing rather than allow-all, for the same reason as in
        // the stub scenario: this file's claim is about a *governed* launch. The
        // rules name tool permissions, which the adapter renders into Claude's
        // settings file; they do not gate the provider request whose
        // interception and redaction is what this test actually measures.
        let real_policy = root.join("policy.yaml");
        std::fs::write(
            &real_policy,
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n\
             \x20 name: aaasm1112-real-governed-launch\n\
             spec:\n\
             \x20 tools:\n\
             \x20   read_file:\n\
             \x20     allow: true\n\
             \x20   shell:\n\
             \x20     allow: false\n",
        )?;

        // ── the provider, behind the proxy's own certificate authority ─────
        //
        // One CA for three roles: the mock's leaf is signed by it, the proxy
        // issues its MitM leaves from it, and the install copies it into the
        // launch environment. A harness holding three different ones would pass
        // or fail for reasons unrelated to the product.
        let ca = CaStore::load_or_create(&ca_dir)
            .await
            .map_err(|e| anyhow::anyhow!("certificate authority: {e}"))?;
        let upstream = Arc::new(TlsCapturingUpstream::start(&ca, ANTHROPIC_HOST).await?);
        drop(ca);

        // ── the proxy `aasm run` will vouch for ────────────────────────────
        let proxy = TrustedProxy::start_intercepting(&ca_dir, upstream.addr, &state, &[])?;
        let proxy_url = proxy.expected_proxy_url();

        // ── the gateway ────────────────────────────────────────────────────
        let gateway = GrpcGateway::start().await?;

        // ── the install whose launch environment is the thing in question ──
        //
        // Driven through the production `EngineLifecycle`, on roots laid out so
        // `ClaudeCodePaths::from_env()` inside the child `aasm` resolves the
        // same files: `state_root()` is `$AASM_STATE_DIR/integrations`, so the
        // state this install writes to must be `<state>/integrations` for the
        // child's `AASM_STATE_DIR=<state>` to find it.
        let integrations = state.join("integrations");
        let paths = ClaudeCodePaths::default()
            .with_home(&home)
            .with_config_dir(home.join(".claude"))
            .with_project(&project)
            .with_state(&integrations)
            .with_ca_source(ca_dir.join("ca-cert.pem"));
        let integration = Arc::new(
            ClaudeCodeIntegration::with_paths(paths)
                .with_adapter(ClaudeCodeAdapter::with_overrides(
                    Some(claude.clone()),
                    Some(home.clone()),
                ))
                .through_proxy(&proxy_url),
        );
        let service = EngineLifecycle::new(
            vec![claude_code_registration(integration)],
            ReceiptStore::at(integrations.join("store")),
        );
        let tool = DevToolKind::ClaudeCode;
        let plan = service
            .plan(IntegrationRequest::new(
                tool.clone(),
                ProtectionProfile::Recommended,
                SettingsScope::User,
            ))
            .await
            .map_err(|e| anyhow::anyhow!("plan: {e}"))?;
        service
            .apply(&tool, &plan.plan_id)
            .await
            .map_err(|e| anyhow::anyhow!("apply: {e}"))?;

        // ── the launch ─────────────────────────────────────────────────────
        let prompt = format!("Echo this configuration line verbatim: ANTHROPIC_API_KEY={SYNTHETIC_SECRET}");
        let stdout_path = root.join("aasm-stdout.txt");
        let stderr_path = root.join("aasm-stderr.txt");
        let mut cmd = std::process::Command::new(aasm_binary());
        cmd.current_dir(&project)
            .env("HOME", &home)
            // `claude.parent()` so `which claude` finds this scenario's binary,
            // and `proxy.proxy_bin_dir()` (AAASM-5863) so the *dedicated* proxy
            // `aasm run` now starts for this launch resolves to the same
            // mock-upstream stand-in `proxy` (`start_intercepting`) copied there
            // as `aa-proxy` — without it the dedicated proxy would either fail
            // to resolve at all or resolve to a real `aa-proxy` with no
            // knowledge of the mock upstream this scenario's capture depends on.
            .env(
                "PATH",
                path_with_both(
                    claude.parent().expect("the claude binary has a parent"),
                    proxy.proxy_bin_dir(),
                )?,
            )
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("AASM_STATE_DIR", &state)
            .env("AA_CA_DIR", &ca_dir)
            .env("AASM_CLAUDE_MANAGED_ROOT", root.join("managed"))
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("AA_GATEWAY_ENDPOINT", gateway.endpoint())
            // Mirrors what `start_intercepting` set on its own (now-unused, for
            // this scenario's purposes) standalone proxy: the dedicated proxy
            // this launch starts is the one that must redirect to the mock
            // upstream and skip its self-signed leaf's verification now.
            .env("AA_TEST_PROXY_UPSTREAM", upstream.addr.to_string())
            .env("AA_PROXY_LLM_ONLY", "false")
            .env("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY", "1")
            // A token that is obviously not a credential: the run must reach the
            // mock, and the mock answers whatever it is asked.
            .env("ANTHROPIC_AUTH_TOKEN", "AAASM1112-DUMMY-NOT-A-REAL-TOKEN")
            // The developer's own values must not ride along. `build_child_env`
            // seeds the child from the operator's shell environment, so an
            // ambient `NODE_EXTRA_CA_CERTS` would supply from the outside the
            // very variable this scenario exists to prove the launcher delivers,
            // and an ambient key or base URL would send this run somewhere the
            // test does not control.
            .env_remove("NODE_EXTRA_CA_CERTS")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("ANTHROPIC_BASE_URL")
            .env_remove("HTTPS_PROXY")
            .env_remove("HTTP_PROXY")
            .env_remove("https_proxy")
            .env_remove("http_proxy")
            .stdout(std::fs::File::create(&stdout_path)?)
            .stderr(std::fs::File::create(&stderr_path)?)
            // Its own group, so the tool it launches can be reaped with it.
            .process_group(0)
            .args([
                "run",
                "claude",
                "--policy",
                &real_policy.to_string_lossy(),
                "--agent-id",
                AGENT_ID,
                "--",
                "-p",
                &prompt,
            ]);
        let mut child = cmd.spawn().expect("aasm run claude should execute");
        let pgid = child.id() as i32;
        let _reaper = GroupReaper(pgid);

        // ── wait for evidence, then stop the session ───────────────────────
        //
        // With every host MitM'd onto one mock the binary never exits on its
        // own: its side channels never get the answers they expect. The evidence
        // is complete once traffic has been captured, so the session is closed
        // the way an operator closes one — `SIGTERM` to `aasm run`, which
        // forwards it to the tool.
        let started = std::time::Instant::now();
        while started.elapsed() < EVIDENCE_PATIENCE {
            if child.try_wait()?.is_some() || upstream.request_count() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if child.try_wait()?.is_none() {
            signal_group(pgid, libc::SIGTERM);
            let grace = std::time::Instant::now();
            while grace.elapsed() < Duration::from_secs(20) {
                if child.try_wait()?.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if child.try_wait()?.is_none() {
                signal_group(pgid, libc::SIGKILL);
            }
        }
        let launcher_exit = child.wait()?;
        let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        println!(
            "MEASURED governed launch: launcher_exit={:?} elapsed={:?}",
            launcher_exit.code(),
            started.elapsed(),
        );

        let observed = upstream.wait_for_requests(1, Duration::from_secs(20)).await;
        println!("MEASURED requests reaching the provider: {observed}");
        println!("MEASURED request lines: {:?}", upstream.request_lines());

        if observed == 0 {
            // Both opt-outs are behind us, so the scenario committed to
            // measuring. Zero traffic is a failed measurement — the governed
            // launch did not reach the endpoint the product routed it at — and
            // returning `Ok(())` with an explanatory line would be
            // indistinguishable from a pass to everything except a human reading
            // `--no-capture` stdout.
            let detail = format!(
                "no upstream traffic from a governed launch (launcher_exit={:?}, elapsed={:?})",
                launcher_exit.code(),
                started.elapsed(),
            );
            conformance_support::outcome::record(SCENARIO, Measurement::NotMeasured, &detail);
            println!("NOT MEASURED aasm stdout tail: {}", tail(&stdout));
            println!("NOT MEASURED aasm stderr tail: {}", tail(&stderr));
            real_home.assert_unchanged(SCENARIO);
            anyhow::bail!(
                "NOT MEASURED [{SCENARIO}]: {detail}. This is a gap in the evidence, not a pass — \
                 nothing about the governed launch was established."
            );
        }

        // ── the assertion AC4 actually names ───────────────────────────────
        //
        // On what reached the provider, not on what the launcher intended to
        // set. An environment the child never received cannot satisfy this.
        let bodies = upstream.bodies();
        assert_recorded_and_secret_absent(&bodies, SYNTHETIC_SECRET, "real binary via `aasm run`");
        let redacted = bodies
            .iter()
            .filter(|b| String::from_utf8_lossy(b).contains(PLACEHOLDER))
            .count();
        println!(
            "MEASURED bodies carrying the redaction placeholder: {redacted} of {}",
            bodies.len()
        );
        assert!(
            redacted > 0,
            "the launched binary's traffic reached the provider but nothing carried `{PLACEHOLDER}` \
             — the prompt never crossed the scanned path, so `no secret arrived` proves nothing.\n\
             aasm stdout tail: {}\naasm stderr tail: {}",
            tail(&stdout),
            tail(&stderr),
        );

        conformance_support::outcome::record(
            SCENARIO,
            Measurement::Measured,
            &format!(
                "{observed} request(s) observed from a governed launch, {redacted} of {} carried \
                 the redaction placeholder",
                bodies.len()
            ),
        );
        real_home.assert_unchanged(SCENARIO);
        Ok(())
    }
}

/// A skip must be legible in the output; a test binary that silently contains
/// no tests is indistinguishable from a passing one.
///
/// The whole `governed_launch` module is `#[cfg(unix)]`, so on any other host
/// this binary's *only* test is this one — a green result carrying no evidence
/// whatsoever about AC4. Recording it (AAASM-5465) is what lets the CI summary
/// net it out of the pass count and say so.
#[cfg(not(unix))]
#[test]
fn governed_launch_is_not_measured_on_this_host() {
    let reason = format!(
        "the governed-launch evidence needs a POSIX shell stand-in for the `claude` binary; this \
         host is {}. AC4 is NOT evidenced here.",
        std::env::consts::OS
    );
    println!("SKIP [AAASM-201 AC4]: {reason}");
    conformance_support::outcome::record(
        "aaasm-201-ac4-governed-launch",
        conformance_support::Measurement::UnsupportedPlatform,
        &reason,
    );
}
