//! AAASM-5323 / AAASM-5863 — `aasm run` refuses to launch when it cannot
//! establish a governed proxy for this launch.
//!
//! # What was wrong (AAASM-5323, original scope)
//!
//! `aasm run` read its proxy address from the `proxy_addr` field of the
//! gateway's registration response and set `HTTPS_PROXY` **only if that field
//! was present**. Nothing in the tree ever populated it, so the flag-free
//! `aasm run claude` an operator actually types launched the tool with no proxy
//! at all — uninspected, unbounded by egress policy, and reporting as governed.
//! An absent value could mean "proceed anyway", which is the defining shape of a
//! silent bypass.
//!
//! # What changed (AAASM-5863)
//!
//! The fix above was a pre-existing, operator-started, *shared* `aa-proxy`
//! that `aasm run` verified via a PID/state-file trust check
//! (`aa-cli/src/commands/proxy/trust.rs`) before registering. AAASM-5863
//! replaced that model: `aasm run` now starts its **own dedicated** `aa-proxy`
//! per governed launch, after registration, configured with the launch's real
//! registered `agent_id`. There is no shared state file for it to trust or
//! distrust any more — the whole PID-reuse / symlink / permission-tampering
//! matrix this file used to drive end-to-end no longer has a code path behind
//! it in `aasm run`.
//!
//! That verification logic is not deleted — `resolve_trusted_endpoint` and its
//! `verify_state_file`/`verify_process`/`verify_identity`/`verify_listening`
//! helpers stay in `trust.rs` with their own unit-level coverage of every one
//! of those scenarios, available to a future caller (e.g. an
//! `aasm proxy status` trust check) — it is simply unreached by `aasm run`
//! today, so re-driving it here end-to-end would test dead wiring.
//!
//! # What this file measures now
//!
//! The one refusal `aasm run` still has left in this area: a governed launch
//! whose dedicated proxy cannot start refuses, names why, and never starts the
//! tool. Unlike the pre-AAASM-5863 refusal, this one is reachable only *after*
//! registration succeeds (the dedicated proxy needs the real registered
//! `agent_id` to be configured with), so this case needs a real gateway, not
//! just an unreachable one.
//!
//! The complementary claim — that a launch through a working dedicated proxy
//! proceeds and the child is routed at its bound address — is measured in
//! `cli_run_claude_governed_launch.rs` and `cli_run_claude_launch_env.rs`.

mod grpc_gateway_support;
#[allow(unused_imports)]
mod proxy_trust_support;

/// The evidence ledger (AAASM-5465). Every case in this file is `#[cfg(unix)]`,
/// so on any other host the binary reports one green test that measured nothing;
/// the ledger is what makes that legible to the CI summary rather than only to a
/// human reading stdout.
#[path = "evidence/mod.rs"]
mod evidence;

#[cfg(unix)]
mod refusals {
    use super::grpc_gateway_support::GrpcGateway;
    use std::path::{Path, PathBuf};

    const AGENT_ID: &str = "aaasm5863-agent";

    /// A host whose `claude`, home and state roots are all inside a temp dir, so
    /// nothing here can read or write the developer's own configuration.
    ///
    /// Unlike `cli_run_claude_governed_launch.rs`'s equivalent, this host's
    /// `PATH` deliberately never includes an `aa-proxy` binary — that absence
    /// is the one thing this file exists to exercise.
    struct Host {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        home: PathBuf,
        project: PathBuf,
        dump: PathBuf,
        stub_dir: PathBuf,
        policy: PathBuf,
    }

    impl Host {
        fn create() -> anyhow::Result<Self> {
            let tmp = tempfile::tempdir()?;
            let root = tmp.path().to_path_buf();
            let home = root.join("home");
            let project = root.join("project");
            std::fs::create_dir_all(home.join(".claude"))?;
            std::fs::create_dir_all(&project)?;
            let stub = write_stub_binary(&root)?;
            let policy = write_test_policy(&root)?;
            Ok(Self {
                stub_dir: stub.parent().expect("the stub has a parent").to_path_buf(),
                dump: root.join("child-env.txt"),
                _tmp: tmp,
                root,
                home,
                project,
                policy,
            })
        }

        /// Run `aasm run claude` against `gateway`, with a `PATH` that resolves
        /// the `claude` stub but never an `aa-proxy` binary.
        fn run(&self, gateway: &GrpcGateway) -> anyhow::Result<std::process::Output> {
            Ok(std::process::Command::new(super::proxy_trust_support::aasm_binary())
                .current_dir(&self.project)
                .env("HOME", &self.home)
                .env("PATH", super::proxy_trust_support::prefixed_path(&self.stub_dir)?)
                .env("CLAUDE_CONFIG_DIR", self.home.join(".claude"))
                .env("AASM_STATE_DIR", self.root.join("state"))
                .env("AA_CA_DIR", self.root.join("ca"))
                .env("AASM_CLAUDE_MANAGED_ROOT", self.root.join("managed"))
                .env("AASM5863_ENV_DUMP", &self.dump)
                .env("AA_GATEWAY_ENDPOINT", gateway.endpoint())
                .args([
                    "run",
                    "claude",
                    "--policy",
                    &self.policy.to_string_lossy(),
                    "--agent-id",
                    AGENT_ID,
                ])
                .output()?)
        }

        /// True when the `claude` stand-in ran. Absence of the dump is what
        /// "refused to launch" actually means.
        fn tool_was_launched(&self) -> bool {
            self.dump.exists()
        }
    }

    /// A `claude` stand-in: answers `--version` so `detect()` succeeds, and
    /// records the fact that it ran if it is ever launched.
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
echo ran > "$AASM5863_ENV_DUMP"
exit 0
"#,
        )?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        Ok(bin)
    }

    /// A narrow, enforcing policy — a governed launch refuses when no
    /// effective policy resolves (AAASM-5349), so this file's cases must clear
    /// that gate before reaching the one this file actually measures.
    fn write_test_policy(dir: &Path) -> std::io::Result<PathBuf> {
        let policy = dir.join("policy.yaml");
        std::fs::write(
            &policy,
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n\
             \x20 name: aaasm5863-proxy-refusal\n\
             spec:\n\
             \x20 tools:\n\
             \x20   read_file:\n\
             \x20     allow: true\n",
        )?;
        Ok(policy)
    }

    /// Assert the run refused, said why, and started nothing.
    fn assert_refused(host: &Host, out: &std::process::Output, because: &str) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "the launch must exit non-zero when its dedicated proxy cannot start\n\
             stdout:\n{stdout}\nstderr:\n{stderr}",
        );
        assert!(
            stderr.contains(because),
            "the refusal must name why (`{because}`)\nstderr:\n{stderr}",
        );
        assert!(
            !host.tool_was_launched(),
            "the tool was started anyway — an error message printed after the child exists is \
             not a refusal\nstdout:\n{stdout}\nstderr:\n{stderr}",
        );
    }

    /// The one refusal left in this area post-AAASM-5863: registration
    /// succeeds (a real gateway accepts the session), but the dedicated proxy
    /// this launch needs cannot even be resolved — no `aa-proxy` anywhere on
    /// `PATH` and no `~/.cargo/bin/aa-proxy` (`HOME` is this host's empty temp
    /// dir). The launch must refuse rather than proceed unproxied.
    #[tokio::test(flavor = "multi_thread")]
    async fn launch_refuses_when_the_dedicated_proxy_cannot_be_resolved() -> anyhow::Result<()> {
        let gateway = GrpcGateway::start().await?;
        let host = Host::create()?;

        let out = host.run(&gateway)?;

        assert_refused(&host, &out, "aa-proxy binary not found");
        Ok(())
    }
}

/// A skip must be legible in the output; a test binary that silently contains no
/// tests is indistinguishable from a passing one.
#[cfg(not(unix))]
#[test]
fn proxy_trust_refusals_are_not_measured_on_this_host() {
    let reason = format!(
        "this case needs a POSIX shell stand-in for `claude`; this host is {}.",
        std::env::consts::OS
    );
    println!("SKIP [AAASM-5863]: {reason}");
    evidence::record(
        "aaasm-5863-dedicated-proxy-refusal",
        evidence::Measurement::UnsupportedPlatform,
        &reason,
    );
}
