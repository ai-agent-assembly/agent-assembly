//! AAASM-5327 — the launch environment the adapter builds reaches the process.
//!
//! # What this measures, and why nothing else did
//!
//! `ClaudeCodeAdapter::build_launch_command` sets `NODE_EXTRA_CA_CERTS` (and a
//! normalised `HTTPS_PROXY`) on the `Command` it returns. `spawn_and_wait` used
//! to rebuild that command from its program and args alone, so every one of
//! those variables was dropped on the floor. The consequence is the product's
//! defining failure mode rather than a cosmetic one: `NODE_EXTRA_CA_CERTS` is
//! the only mechanism by which Claude Code's embedded Node runtime trusts the
//! Agent Assembly CA, so without it the proxy cannot terminate TLS and the
//! session is inspected by nothing while presenting as governed.
//!
//! The tests that existed could not see it:
//!
//! * `aa-cli`'s `build_child_env_*` unit tests assert on a `HashMap`, one
//!   function call short of anything a process observes — and
//!   `build_child_env_sets_proxy` feeds in a value that already carries a
//!   scheme, so the normalisation branch that matters is never exercised.
//! * `aa-cli/tests/integrations_claude_code.rs` reads the on-disk launch-env
//!   *store*, which proves the value was written, not that a child received it.
//! * `aa-integration-tests/tests/cli_run.rs` only drives `--dry-run`, which
//!   short-circuits before any child exists.
//!
//! So the assertions here are made on the environment a **real spawned child**
//! reported about itself, via a `claude` stand-in that writes what it can see to
//! a file.
//!
//! # The dump distinguishes absent from empty
//!
//! A fixture that renders "variable missing" and "variable set to the empty
//! string" identically cannot fail for the bug it is aimed at, so the stub uses
//! `${VAR-__UNSET__}` (no colon — substitutes only when *unset*) and
//! [`fixture_can_tell_an_absent_variable_from_an_empty_one`] pins that both
//! renderings are reachable.
//!
//! # Safety
//!
//! `ClaudeCodeAdapter::new()` resolves its binary with `which claude` and its
//! settings from `$HOME`, so a careless version of this test would launch the
//! developer's real Claude Code and rewrite their real `~/.claude/settings.json`.
//! Every root the adapter reads is redirected on the **child** `aasm` process
//! only (`HOME`, `PATH`, `CLAUDE_CONFIG_DIR`, `AASM_STATE_DIR`, `AA_CA_DIR`,
//! `AASM_CLAUDE_MANAGED_ROOT`, and the working directory); no process-global
//! environment of this test binary is mutated. `RealHomeGuard` closes each test:
//! it fingerprints the developer's settings file on length and mtime and never
//! reads its contents, because that file is in daily use and may hold
//! credentials that an `assert_eq!` would print into a CI log.
//!
//! # The proxy endpoint is the one this host verified, not the one it was told
//!
//! Since AAASM-5323 a launch is refused unless `aasm run` can vouch for a local
//! proxy, so these tests stand up a real one ([`TrustedProxy`]) and assert the
//! child was routed at *that* endpoint. Nothing on the registration path names a
//! proxy any more, so there is no competing address left to confuse it with.
//!
//! The gateway is the real `AgentLifecycleService`: a launch that cannot
//! register does not happen at all, so these tests would measure nothing without
//! one. Registration itself is not this file's subject — see
//! `aa-cli/tests/run_registration_gateway.rs`.
//!
//! # The policy is a precondition too
//!
//! Since AAASM-5349 a governed launch refuses when no effective policy resolves,
//! because an unconfigured policy means nobody has said what the agent may do —
//! which is not the same as everything being permitted. So each run supplies one
//! with `--policy`, alongside the gateway and the verified proxy. It is narrow
//! and enforcing rather than allow-all: this file measures a *governed* launch,
//! and a session under a policy that restricts nothing would not be one. What
//! the policy says has no bearing on the launch environment asserted below —
//! tool permissions are rendered into Claude's settings file, not into the
//! child's environment — so it is a precondition, not a variable.

// `RealHomeGuard` is reused rather than reimplemented: it fingerprints the live
// settings file on length+mtime and never reads its contents.
/// The evidence ledger (AAASM-5465), declared once per test binary.
///
/// The support modules re-export it rather than declaring their own, because a
/// binary including two of them would otherwise load the same file twice.
#[path = "evidence/mod.rs"]
pub mod evidence;

#[allow(dead_code, unused_imports)]
mod spike_support;

#[allow(unused_imports)]
mod proxy_trust_support;

#[allow(unused_imports)]
mod grpc_gateway_support;

#[cfg(unix)]
mod launch_env {
    use super::grpc_gateway_support::{expected_did, expected_registration_id, GrpcGateway};
    use super::proxy_trust_support::{aasm_binary, TrustedProxy};
    use super::spike_support::RealHomeGuard;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use aa_devtool_claude_code::launch_env::LaunchEnvStore;
    use aa_devtool_claude_code::scope::ClaudeCodePaths;
    use aa_devtool_contract::SettingsScope;

    /// Identity the operator names on the command line. The values the session
    /// ends up with are *derived* from these the way the CLI derives them
    /// (AAASM-5323), not picked.
    const AGENT_ID: &str = "aaasm5327-agent";
    const TEAM_ID: &str = "aaasm5327-team";

    /// Written into the launch-env store the adapter reads. A path shape, since
    /// that is what `NODE_EXTRA_CA_CERTS` carries, and unmistakably this test's.
    const CA_PATH_VALUE: &str = "/aaasm5327/proxy-ca.pem";

    /// What the stub prints for a variable that is not set at all. Distinct from
    /// the empty string, which is the whole point (see the module docs).
    const UNSET: &str = "__UNSET__";

    /// A variable this test sets to the empty string on the `aasm` process, to
    /// prove the dump renders empty-but-present differently from absent.
    const EMPTY_PROBE: &str = "AASM5327_EMPTY_PROBE";

    /// Names the stub reports. Everything the merge has to get right, plus the
    /// two probes that keep the fixture honest.
    ///
    /// AAASM-5924 (ADR 0036 Test 6c) added `https_proxy`/`ALL_PROXY`/`NO_PROXY`
    /// — the original 9-name list only covered the 2-variable case this
    /// fixture was first built for; without these three, `seen.get(..)` on
    /// them is unconditionally `None` regardless of what the real child's
    /// environment actually contains, which silently passes the wrong thing.
    const REPORTED: [&str; 12] = [
        "AA_AGENT_ID",
        "AA_AGENT_DID",
        "AA_TRACE_ID",
        "AA_SESSION_ID",
        "AA_REGISTRATION_ID",
        "AA_TEAM_ID",
        "NODE_EXTRA_CA_CERTS",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "NO_PROXY",
    ];

    /// A `claude` stand-in that answers `--version` with a supported version and,
    /// when launched, writes the variables it can see to `$AASM5327_ENV_DUMP`.
    ///
    /// `${VAR-__UNSET__}` — deliberately the `-` form, not `:-` — substitutes
    /// only when the variable is unset, so an empty value is reported as an
    /// empty value. A dump that collapsed the two could not fail for the defect
    /// this file exists to catch.
    fn write_stub_binary(dir: &Path) -> std::io::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let bin_dir = dir.join("bin");
        std::fs::create_dir_all(&bin_dir)?;
        let bin = bin_dir.join("claude");
        let mut script = String::from(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "2.1.999 (Claude Code)"
  exit 0
fi
{
"#,
        );
        for name in REPORTED.iter().copied().chain(std::iter::once(EMPTY_PROBE)) {
            script.push_str(&format!("  printf '{name}=%s\\n' \"${{{name}-{UNSET}}}\"\n"));
        }
        script.push_str(
            r#"} > "$AASM5327_ENV_DUMP"
exit 0
"#,
        );
        std::fs::write(&bin, script)?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        Ok(bin)
    }

    /// A host whose every Claude Code / Agent Assembly root is inside a temp dir.
    struct GovernedHost {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        home: PathBuf,
        project: PathBuf,
        state_dir: PathBuf,
        dump: PathBuf,
        /// The effective policy every run of this host launches under.
        policy: PathBuf,
        path_var: std::ffi::OsString,
    }

    impl GovernedHost {
        fn create() -> anyhow::Result<Self> {
            let tmp = tempfile::tempdir()?;
            let root = tmp.path().to_path_buf();
            let home = root.join("home");
            let project = root.join("project");
            std::fs::create_dir_all(home.join(".claude"))?;
            std::fs::create_dir_all(&project)?;
            let stub = write_stub_binary(&root)?;

            // `PATH` is prefixed rather than replaced: `build_launch_command`'s
            // `which` probe must find our stub first, while the child `aasm`
            // keeps whatever else it needs from the host.
            let mut parts = vec![stub.parent().expect("stub has a parent").to_path_buf()];
            parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
            let path_var = std::env::join_paths(parts)?;

            // A governed launch refuses when no effective policy resolves
            // (AAASM-5349), so the host carries one — a precondition of this
            // scenario in the same way the gateway and the verified proxy are.
            //
            // Narrow and enforcing rather than allow-all: this file measures a
            // *governed* launch, and a session under a policy that restricts
            // nothing would not be one. The rules name tool permissions, which
            // the adapter renders into Claude's settings file; they have no
            // bearing on the launch environment this file actually asserts on.
            //
            // Written into the host's own temp root and passed with `--policy`
            // rather than installed at `$HOME/.aasm/policy.yaml`, so the run
            // measures the same thing on a developer machine that happens to
            // have an operator policy installed and on a bare CI runner.
            let policy = root.join("policy.yaml");
            std::fs::write(
                &policy,
                "apiVersion: agent-assembly/v1\n\
                 kind: Policy\n\
                 metadata:\n\
                 \x20 name: aaasm5327-launch-env\n\
                 spec:\n\
                 \x20 tools:\n\
                 \x20   read_file:\n\
                 \x20     allow: true\n\
                 \x20   shell:\n\
                 \x20     allow: false\n",
            )?;

            Ok(Self {
                _tmp: tmp,
                state_dir: root.join("state"),
                dump: root.join("child-env.txt"),
                policy,
                root,
                home,
                project,
                path_var,
            })
        }

        /// The launch-env store the adapter will read at user scope.
        ///
        /// Resolved through the production [`ClaudeCodePaths`] rather than by
        /// hand-joining path segments, so a change to the on-disk layout moves
        /// this test with it instead of silently pointing it at nothing.
        fn user_launch_env_store(&self) -> anyhow::Result<LaunchEnvStore> {
            let paths = ClaudeCodePaths::default().with_state(self.state_dir.join("integrations"));
            Ok(LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::User)?))
        }

        /// Run `aasm run claude` against `gateway`, routed through `proxy`, and
        /// return the child stub's self-reported environment.
        fn run(&self, gateway: &GrpcGateway, proxy: &TrustedProxy) -> anyhow::Result<BTreeMap<String, String>> {
            // `proxy.proxy_bin_dir()` is prefixed onto `self.path_var` here,
            // not baked in at `create()` time (AAASM-5863): the child `aasm
            // run` now resolves and spawns its own dedicated `aa-proxy`
            // rather than trusting the already-running one `proxy` stood up,
            // so that binary's directory must be on *this* launch's PATH too.
            let mut path_parts = vec![proxy.proxy_bin_dir().to_path_buf()];
            path_parts.extend(std::env::split_paths(&self.path_var));
            let path_var = std::env::join_paths(path_parts)?;

            let out = std::process::Command::new(aasm_binary())
                .current_dir(&self.project)
                // Where the verified proxy's state record lives. Without it the
                // launch refuses and nothing is measured.
                .env("AA_DATA_DIR", proxy.data_dir())
                .env("HOME", &self.home)
                .env("PATH", &path_var)
                .env("CLAUDE_CONFIG_DIR", self.home.join(".claude"))
                .env("AASM_STATE_DIR", &self.state_dir)
                .env("AA_CA_DIR", self.root.join("ca"))
                .env("AASM_CLAUDE_MANAGED_ROOT", self.root.join("managed"))
                .env("AASM5327_ENV_DUMP", &self.dump)
                // Present but empty on the `aasm` process, so it reaches the
                // child through `build_child_env`'s copy of the ambient
                // environment and exercises the empty rendering.
                .env(EMPTY_PROBE, "")
                // Whatever the developer running this happens to have set must
                // not stand in for what the adapter is supposed to inject.
                .env_remove("NODE_EXTRA_CA_CERTS")
                // Registration is a gRPC call; the session must be accepted
                // before anything is launched, so a run that measured nothing
                // here would be a run that never got past the gate.
                .env("AA_GATEWAY_ENDPOINT", gateway.endpoint())
                .args([
                    "run",
                    "claude",
                    "--policy",
                    &self.policy.to_string_lossy(),
                    "--agent-id",
                    AGENT_ID,
                    "--team-id",
                    TEAM_ID,
                ])
                .output()
                .expect("aasm run claude should execute");

            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            assert!(
                out.status.success(),
                "aasm run claude should exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}",
            );
            let raw = std::fs::read_to_string(&self.dump).unwrap_or_else(|e| {
                panic!(
                    "the launched tool wrote no environment dump ({e}) — nothing was launched, so \
                     nothing about the launch environment is established\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            });
            Ok(raw
                .lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect())
        }
    }

    fn render(seen: &BTreeMap<String, String>) -> String {
        seen.iter().map(|(k, v)| format!("{k}={v}\n")).collect()
    }

    /// Run `aasm run claude --no-proxy` (ADR 0036 Test 6c) — otherwise
    /// identical to [`GovernedHost::run`]. A separate method rather than a
    /// parameter on `run` because `--no-proxy` changes what preconditions the
    /// launch even needs (no dedicated-proxy resolution), not just an extra
    /// flag threaded through unchanged.
    impl GovernedHost {
        fn run_no_proxy(
            &self,
            gateway: &GrpcGateway,
            proxy: &TrustedProxy,
        ) -> anyhow::Result<BTreeMap<String, String>> {
            let mut path_parts = vec![proxy.proxy_bin_dir().to_path_buf()];
            path_parts.extend(std::env::split_paths(&self.path_var));
            let path_var = std::env::join_paths(path_parts)?;

            let out = std::process::Command::new(aasm_binary())
                .current_dir(&self.project)
                .env("AA_DATA_DIR", proxy.data_dir())
                .env("HOME", &self.home)
                .env("PATH", &path_var)
                .env("CLAUDE_CONFIG_DIR", self.home.join(".claude"))
                .env("AASM_STATE_DIR", &self.state_dir)
                .env("AA_CA_DIR", self.root.join("ca"))
                .env("AASM_CLAUDE_MANAGED_ROOT", self.root.join("managed"))
                .env("AASM5327_ENV_DUMP", &self.dump)
                .env(EMPTY_PROBE, "")
                .env_remove("NODE_EXTRA_CA_CERTS")
                // ADR 0036 Test 6c: ambient uppercase + lowercase proxy vars
                // present on the `aasm` process's own environment — `--no-proxy`
                // must leave them completely untouched at the real child, not
                // merely skip injecting a trusted value on top of them.
                .env("HTTPS_PROXY", "http://ambient.example:9999")
                .env("https_proxy", "http://ambient.example:9999")
                .env("ALL_PROXY", "socks5://ambient.example:9999")
                .env("NO_PROXY", "ambient.example")
                .env("AA_GATEWAY_ENDPOINT", gateway.endpoint())
                .args([
                    "run",
                    "claude",
                    "--policy",
                    &self.policy.to_string_lossy(),
                    "--agent-id",
                    AGENT_ID,
                    "--team-id",
                    TEAM_ID,
                    "--no-proxy",
                ])
                .output()
                .expect("aasm run claude --no-proxy should execute");

            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            assert!(
                out.status.success(),
                "aasm run claude --no-proxy should exit 0 (no receipt/managed-settings precondition \
                 is installed by this fixture, so nothing should refuse the flag)\nstdout:\n{stdout}\nstderr:\n{stderr}",
            );
            let raw = std::fs::read_to_string(&self.dump).unwrap_or_else(|e| {
                panic!("the launched tool wrote no environment dump ({e})\nstdout:\n{stdout}\nstderr:\n{stderr}")
            });
            Ok(raw
                .lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect())
        }
    }

    /// The claim: the variables the adapter put on the launch command are the
    /// ones the launched process actually has.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_adapters_launch_environment_reaches_the_launched_process() -> anyhow::Result<()> {
        let real_home = RealHomeGuard::capture();
        let gateway = GrpcGateway::start().await?;

        let proxy = TrustedProxy::start()?;
        let host = GovernedHost::create()?;
        host.user_launch_env_store()?
            .set("NODE_EXTRA_CA_CERTS", CA_PATH_VALUE)?;

        let seen = host.run(&gateway, &proxy)?;

        // ── the variable the whole product depends on ──────────────────────
        //
        // Without it the tool's Node runtime does not trust the Agent Assembly
        // CA, the proxy cannot terminate TLS, and the traffic is never
        // inspected — a launch that looks governed and is not.
        assert_eq!(
            seen.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
            Some(CA_PATH_VALUE),
            "the launched tool must receive the CA bundle the adapter injected; `{UNSET}` here \
             means the adapter's environment was discarded and TLS interception is dead. Saw:\n{}",
            render(&seen),
        );

        // ── the child is routed at a loopback endpoint this launch owns ────
        //
        // Nothing on the registration path names a proxy: a gateway response is
        // remote and unauthenticated, so letting it choose where a governed
        // session's traffic goes is the bypass AAASM-5323 closes. The value must
        // also be a URL, not a bare authority — no HTTP client routes through
        // the latter (AAASM-5324).
        //
        // AAASM-5863: the endpoint is `aasm run`'s own dedicated proxy for this
        // launch, bound to an ephemeral port `ProxyGuard` picked — not `proxy`
        // (the standalone shared proxy this fixture starts as this launch's
        // registration/CA-trust precondition), whose address is asserted
        // *distinct* below rather than equal, for the same reason as
        // `cli_run_claude_governed_launch.rs`'s equivalent assertion.
        let standalone_proxy = proxy.expected_proxy_url();
        for key in ["HTTPS_PROXY", "HTTP_PROXY"] {
            let value = seen.get(key).map(String::as_str);
            assert!(
                value.is_some_and(|v| v.starts_with("http://127.0.0.1:")),
                "`{key}` must carry a loopback endpoint as a URL. A bare `host:port` means an \
                 unusable authority reached the child; `__UNSET__` means the launch was not \
                 proxied at all. Saw:\n{}",
                render(&seen),
            );
            assert_ne!(
                value,
                Some(standalone_proxy.as_str()),
                "`{key}` names the standalone shared proxy this fixture started for registration/CA \
                 trust, not this launch's own dedicated proxy (AAASM-5863). Saw:\n{}",
                render(&seen),
            );
        }

        // ── and the session identity is still there ────────────────────────
        //
        // The merge adds a source; it must not cost the one that already worked.
        let did = expected_did(&host.state_dir, AGENT_ID);
        for (key, expected) in [
            ("AA_AGENT_ID", AGENT_ID.to_string()),
            ("AA_AGENT_DID", did.clone()),
            ("AA_REGISTRATION_ID", expected_registration_id(Some(TEAM_ID), &did)),
            ("AA_TEAM_ID", TEAM_ID.to_string()),
        ] {
            assert_eq!(
                seen.get(key).map(String::as_str),
                Some(expected.as_str()),
                "the launched tool must still carry the registered identity in `{key}`; saw:\n{}",
                render(&seen),
            );
        }
        for key in ["AA_TRACE_ID", "AA_SESSION_ID"] {
            let value = seen.get(key).map(String::as_str).unwrap_or(UNSET);
            assert!(
                value != UNSET && !value.is_empty(),
                "`{key}` is minted locally rather than issued, so there is no constant to pin — \
                 but it must reach the child, or the launch cannot be correlated. Saw:\n{}",
                render(&seen),
            );
        }

        real_home.assert_unchanged("cli_run_claude_launch_env");
        Ok(())
    }

    /// The fixture's own honesty check: "absent" and "empty" must be
    /// distinguishable in the dump, or the assertion above could pass on a child
    /// that received `NODE_EXTRA_CA_CERTS=""` and trusts nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn fixture_can_tell_an_absent_variable_from_an_empty_one() -> anyhow::Result<()> {
        let real_home = RealHomeGuard::capture();
        let gateway = GrpcGateway::start().await?;

        // No launch-env store is written, so nothing injects the CA variable.
        let proxy = TrustedProxy::start()?;
        let host = GovernedHost::create()?;
        let seen = host.run(&gateway, &proxy)?;

        assert_eq!(
            seen.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
            Some(UNSET),
            "with nothing installed, the CA variable must be reported as unset; saw:\n{}",
            render(&seen),
        );
        assert_eq!(
            seen.get(EMPTY_PROBE).map(String::as_str),
            Some(""),
            "a variable set to the empty string must be reported as empty, not as `{UNSET}` — a \
             dump that cannot tell the two apart cannot fail for the bug this file targets. \
             Saw:\n{}",
            render(&seen),
        );

        real_home.assert_unchanged("cli_run_claude_launch_env");
        Ok(())
    }

    /// ADR 0036 Test 6c: `--no-proxy` leaves ambient uppercase AND lowercase
    /// proxy vars **completely** untouched at the real spawned child —
    /// regression-tested for the pre-existing 2-variable case too, not just
    /// the 6 D6 added (ALL_PROXY/NO_PROXY and lowercase forms).
    #[tokio::test(flavor = "multi_thread")]
    async fn no_proxy_leaves_ambient_proxy_vars_completely_untouched_at_the_real_child() -> anyhow::Result<()> {
        let real_home = RealHomeGuard::capture();
        let gateway = GrpcGateway::start().await?;
        let proxy = TrustedProxy::start()?;
        let host = GovernedHost::create()?;

        let seen = host.run_no_proxy(&gateway, &proxy)?;

        for (key, expected) in [
            ("HTTPS_PROXY", "http://ambient.example:9999"),
            ("https_proxy", "http://ambient.example:9999"),
            ("ALL_PROXY", "socks5://ambient.example:9999"),
            ("NO_PROXY", "ambient.example"),
        ] {
            assert_eq!(
                seen.get(key).map(String::as_str),
                Some(expected),
                "--no-proxy must leave `{key}` completely untouched — got:\n{}",
                render(&seen),
            );
        }

        real_home.assert_unchanged("cli_run_claude_launch_env");
        Ok(())
    }

    /// Row 6c's sibling: the same ambient values, WITHOUT `--no-proxy` —
    /// proves the test above is measuring `--no-proxy`'s effect specifically,
    /// not that these vars always pass through untouched. Without the flag
    /// the dedicated per-launch proxy's own endpoint must win instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn without_no_proxy_the_dedicated_proxy_endpoint_wins_over_ambient_values() -> anyhow::Result<()> {
        let real_home = RealHomeGuard::capture();
        let gateway = GrpcGateway::start().await?;
        let proxy = TrustedProxy::start()?;
        let host = GovernedHost::create()?;

        let path_parts = {
            let mut parts = vec![proxy.proxy_bin_dir().to_path_buf()];
            parts.extend(std::env::split_paths(&host.path_var));
            std::env::join_paths(parts)?
        };
        let out = std::process::Command::new(aasm_binary())
            .current_dir(&host.project)
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("HOME", &host.home)
            .env("PATH", &path_parts)
            .env("CLAUDE_CONFIG_DIR", host.home.join(".claude"))
            .env("AASM_STATE_DIR", &host.state_dir)
            .env("AA_CA_DIR", host.root.join("ca"))
            .env("AASM_CLAUDE_MANAGED_ROOT", host.root.join("managed"))
            .env("AASM5327_ENV_DUMP", &host.dump)
            .env(EMPTY_PROBE, "")
            .env_remove("NODE_EXTRA_CA_CERTS")
            .env("HTTPS_PROXY", "http://ambient.example:9999")
            .env("ALL_PROXY", "socks5://ambient.example:9999")
            .env("AA_GATEWAY_ENDPOINT", gateway.endpoint())
            .args([
                "run",
                "claude",
                "--policy",
                &host.policy.to_string_lossy(),
                "--agent-id",
                AGENT_ID,
                "--team-id",
                TEAM_ID,
            ])
            .output()
            .expect("aasm run claude should execute");
        assert!(
            out.status.success(),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let raw = std::fs::read_to_string(&host.dump)?;
        let seen: BTreeMap<String, String> = raw
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        assert_ne!(
            seen.get("HTTPS_PROXY").map(String::as_str),
            Some("http://ambient.example:9999"),
            "without --no-proxy, the ambient value must be stripped and replaced with the \
             dedicated proxy's own endpoint — got:\n{}",
            render(&seen),
        );
        assert!(!seen.contains_key("ALL_PROXY") || seen.get("ALL_PROXY").map(String::as_str) == Some(UNSET));

        real_home.assert_unchanged("cli_run_claude_launch_env");
        Ok(())
    }

    /// ADR 0036 Test 6b: a store-written `HTTPS_PROXY` value does not survive
    /// unmodified into the real child — the runtime-pinned dedicated proxy
    /// (AAASM-5863: `aasm run claude` always starts one) wins on collision,
    /// proving the D6 strip-then-reinject resolves to the winning source
    /// rather than merging both. The ADR's literal precondition ("no runtime
    /// proxy_addr pinned") is not reachable end-to-end post-AAASM-5863 — see
    /// this file's own `the_adapters_launch_environment_reaches_the_launched_process`
    /// for the store-write-path mechanism proof at the unit level
    /// (`run.rs`'s `effective_child_env` tests), which this asserts the
    /// consequence of at the real spawned child.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_store_written_https_proxy_value_does_not_survive_over_the_dedicated_proxy() -> anyhow::Result<()> {
        let real_home = RealHomeGuard::capture();
        let gateway = GrpcGateway::start().await?;
        let proxy = TrustedProxy::start()?;
        let host = GovernedHost::create()?;
        host.user_launch_env_store()?
            .set("HTTPS_PROXY", "http://store-written.example:1234")?;

        let seen = host.run(&gateway, &proxy)?;

        assert_ne!(
            seen.get("HTTPS_PROXY").map(String::as_str),
            Some("http://store-written.example:1234"),
            "a store-written HTTPS_PROXY value must not survive over the dedicated per-launch \
             proxy's own endpoint — got:\n{}",
            render(&seen),
        );
        assert!(
            seen.get("HTTPS_PROXY")
                .is_some_and(|v| v.starts_with("http://127.0.0.1:")),
            "the dedicated proxy's own endpoint must still be what the child receives — got:\n{}",
            render(&seen),
        );

        real_home.assert_unchanged("cli_run_claude_launch_env");
        Ok(())
    }
}

/// A skip must be legible in the output; a test binary that silently contains no
/// tests is indistinguishable from a passing one.
///
/// The `launch_env` module is `#[cfg(unix)]`, so on any other host this is the
/// binary's only test and a green result establishes nothing. Recorded
/// (AAASM-5465) so the CI summary can subtract it from the pass count.
#[cfg(not(unix))]
#[test]
fn the_launch_environment_is_not_measured_on_this_host() {
    let reason = format!(
        "measuring the launched process's environment needs a POSIX shell stand-in for the \
         `claude` binary; this host is {}.",
        std::env::consts::OS
    );
    println!("SKIP [AAASM-5327]: {reason}");
    spike_support::outcome::record(
        "aaasm-5327-launch-environment",
        spike_support::Measurement::UnsupportedPlatform,
        &reason,
    );
}
