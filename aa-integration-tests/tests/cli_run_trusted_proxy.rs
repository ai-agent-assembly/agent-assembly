//! AAASM-5323 — `aasm run` refuses to launch when it cannot establish a proxy
//! endpoint it can vouch for.
//!
//! # What was wrong
//!
//! `aasm run` read its proxy address from the `proxy_addr` field of the
//! gateway's registration response and set `HTTPS_PROXY` **only if that field
//! was present**. Nothing in the tree ever populated it, so the flag-free
//! `aasm run claude` an operator actually types launched the tool with no proxy
//! at all — uninspected, unbounded by egress policy, and reporting as governed.
//! An absent value could mean "proceed anyway", which is the defining shape of a
//! silent bypass.
//!
//! # What this file measures
//!
//! Every case here drives the real `aasm` binary and asserts two things
//! together: the process exits non-zero, **and** the tool was never started. The
//! second is what makes the first mean something — an error message printed
//! after a child has already been launched is not a refusal.
//!
//! The refusals are distinguished by the *reason* each one gives, not merely by
//! being refusals. A test that only asserted "it failed" would pass if a single
//! early check swallowed every case, which is exactly how a matrix of guards
//! collapses into one guard wearing five names.
//!
//! The complementary claim — that a launch through a *verified* proxy proceeds
//! and the child is routed at the resolved endpoint — is measured in
//! `cli_run_claude_launch_env.rs`, which already owns the child-environment dump
//! machinery.

#[allow(unused_imports)]
mod proxy_trust_support;

#[cfg(unix)]
mod refusals {
    use super::proxy_trust_support::{aasm_binary, prefixed_path, TrustedProxy};
    use std::path::{Path, PathBuf};

    /// A host whose `claude`, home and state roots are all inside a temp dir, so
    /// nothing here can read or write the developer's own configuration.
    struct Host {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        home: PathBuf,
        project: PathBuf,
        dump: PathBuf,
        stub_dir: PathBuf,
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
            Ok(Self {
                stub_dir: stub.parent().expect("the stub has a parent").to_path_buf(),
                dump: root.join("child-env.txt"),
                _tmp: tmp,
                root,
                home,
                project,
            })
        }

        /// Run `aasm run claude` with `data_dir` as the proxy state directory.
        fn run(&self, data_dir: &Path) -> anyhow::Result<std::process::Output> {
            Ok(std::process::Command::new(aasm_binary())
                .current_dir(&self.project)
                .env("HOME", &self.home)
                .env("PATH", prefixed_path(&self.stub_dir)?)
                .env("CLAUDE_CONFIG_DIR", self.home.join(".claude"))
                .env("AASM_STATE_DIR", self.root.join("state"))
                .env("AA_CA_DIR", self.root.join("ca"))
                .env("AASM_CLAUDE_MANAGED_ROOT", self.root.join("managed"))
                .env("AA_DATA_DIR", data_dir)
                .env("AASM5323_ENV_DUMP", &self.dump)
                // A gateway address nothing can be listening on. A refusal
                // happens before registration, so this is never reached — and if
                // the refusal ever stopped happening, the run would fail here
                // instead of quietly launching.
                .args(["--api-url", "http://127.0.0.1:1", "run", "claude"])
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
printf 'HTTPS_PROXY=%s\n' "${HTTPS_PROXY-__UNSET__}" > "$AASM5323_ENV_DUMP"
exit 0
"#,
        )?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        Ok(bin)
    }

    /// Assert the run refused, said why, and started nothing.
    fn assert_refused(host: &Host, out: &std::process::Output, because: &str) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "the launch must exit non-zero when no proxy endpoint can be trusted\n\
             stdout:\n{stdout}\nstderr:\n{stderr}",
        );
        assert!(
            stderr.contains("refusing to launch ungoverned"),
            "the operator must be told the launch was refused, not left to infer it from an \
             exit code\nstderr:\n{stderr}",
        );
        assert!(
            stderr.contains(because),
            "the refusal must name the fact that failed (`{because}`); a single early check \
             standing in for every case would make this matrix meaningless\nstderr:\n{stderr}",
        );
        assert!(
            !host.tool_was_launched(),
            "the tool was started anyway — an error message printed after the child exists is \
             not a refusal\nstdout:\n{stdout}\nstderr:\n{stderr}",
        );
    }

    /// Overwrite one line of the state record the harness's `aasm proxy start`
    /// wrote, leaving everything else — including the live process it names —
    /// exactly as it was.
    fn tamper_line(path: &Path, index: usize, replacement: &str) {
        let content = std::fs::read_to_string(path).expect("state file must exist to be tampered with");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        assert!(
            index < lines.len(),
            "state record has {} lines; cannot rewrite line {index}. The record format changed \
             and this test is no longer tampering with the field it names.",
            lines.len(),
        );
        lines[index] = replacement.to_string();
        std::fs::write(path, format!("{}\n", lines.join("\n"))).expect("rewrite state file");
    }

    // ── no proxy at all ────────────────────────────────────────────────────

    /// The everyday case, and the one the old code got wrong: an operator who
    /// has not started a proxy types `aasm run claude`.
    #[test]
    fn launch_refuses_when_no_proxy_is_running() -> anyhow::Result<()> {
        let host = Host::create()?;
        let data = tempfile::tempdir()?;

        let out = host.run(data.path())?;

        assert_refused(&host, &out, "no governed proxy is running");
        Ok(())
    }

    // ── stale state ────────────────────────────────────────────────────────

    /// A record left behind by a proxy that has since exited. The PID is a real
    /// number that was a real process; it just isn't one any more.
    #[test]
    fn launch_refuses_when_the_recorded_process_is_gone() -> anyhow::Result<()> {
        let host = Host::create()?;
        let data = tempfile::tempdir()?;

        let mut child = std::process::Command::new("true").spawn()?;
        let dead_pid = child.id();
        child.wait()?;

        write_state(
            data.path(),
            &format!("{dead_pid}\n127.0.0.1:8899\nstale-token\n/usr/local/bin/aa-proxy\n"),
        )?;

        let out = host.run(data.path())?;

        assert_refused(&host, &out, "is not running");
        Ok(())
    }

    /// A record with no identity evidence at all — the two-line format that
    /// predates AAASM-5323. It names a live process (this test), so a check that
    /// stopped at liveness would accept it.
    #[test]
    fn launch_refuses_a_record_carrying_no_identity_evidence() -> anyhow::Result<()> {
        let host = Host::create()?;
        let data = tempfile::tempdir()?;

        write_state(data.path(), &format!("{}\n127.0.0.1:8899\n", std::process::id()))?;

        let out = host.run(data.path())?;

        assert_refused(&host, &out, "not a complete record");
        Ok(())
    }

    // ── an untrustworthy record ────────────────────────────────────────────

    /// A record any other account on the box could rewrite is a record any other
    /// account could use to choose where this session's traffic goes. The proxy
    /// behind it is genuinely running, so nothing but the file mode is wrong.
    #[test]
    fn launch_refuses_an_over_permissive_state_file() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let host = Host::create()?;
        let proxy = TrustedProxy::start()?;
        let state = proxy.data_dir().join("proxy.pid");
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o666))?;

        let out = host.run(proxy.data_dir())?;

        assert_refused(&host, &out, "lets group or other write to it");
        Ok(())
    }

    /// The state path replaced by a symlink. The metadata that gets vetted must
    /// be the metadata of the bytes that get read.
    #[test]
    fn launch_refuses_a_state_file_that_is_a_symlink() -> anyhow::Result<()> {
        let host = Host::create()?;
        let proxy = TrustedProxy::start()?;
        let state = proxy.data_dir().join("proxy.pid");
        let moved = proxy.data_dir().join("elsewhere.pid");
        std::fs::rename(&state, &moved)?;
        std::os::unix::fs::symlink(&moved, &state)?;

        let out = host.run(proxy.data_dir())?;

        assert_refused(&host, &out, "not a regular file");
        Ok(())
    }

    // ── PID reuse ──────────────────────────────────────────────────────────

    /// The case liveness cannot see: the recorded PID is alive and is running
    /// `aa-proxy`, but it is a *different incarnation* than the one recorded —
    /// the shape a recycled PID takes when the successor happens to be another
    /// proxy. Only the start time distinguishes them.
    ///
    /// Simulated by rewriting the recorded start token while leaving the genuine
    /// running proxy, its PID, its executable and its bound socket untouched:
    /// every other check still passes, so a failure here is attributable to the
    /// start-time comparison and to nothing else.
    #[test]
    fn launch_refuses_when_the_recorded_pid_is_a_different_incarnation() -> anyhow::Result<()> {
        let host = Host::create()?;
        let proxy = TrustedProxy::start()?;
        tamper_line(&proxy.data_dir().join("proxy.pid"), 2, "not-the-recorded-incarnation");

        let out = host.run(proxy.data_dir())?;

        assert_refused(&host, &out, "start time");
        Ok(())
    }

    /// The visible half of PID reuse: the number is alive but is running some
    /// other program. Simulated by pointing the record's executable field
    /// somewhere else while the live proxy keeps the PID.
    #[test]
    fn launch_refuses_when_the_recorded_pid_runs_a_different_executable() -> anyhow::Result<()> {
        let host = Host::create()?;
        let proxy = TrustedProxy::start()?;
        tamper_line(&proxy.data_dir().join("proxy.pid"), 3, "/opt/somewhere/else/aa-proxy");

        let out = host.run(proxy.data_dir())?;

        assert_refused(&host, &out, "executable");
        Ok(())
    }

    /// A live process this user owns is not automatically a proxy. Points the
    /// record at this very test binary — alive, signallable, and emphatically
    /// not `aa-proxy`.
    #[test]
    fn launch_refuses_a_record_naming_something_other_than_the_proxy() -> anyhow::Result<()> {
        let host = Host::create()?;
        let data = tempfile::tempdir()?;
        let me = std::env::current_exe()?;

        write_state(
            data.path(),
            &format!("{}\n127.0.0.1:8899\nany-token\n{}\n", std::process::id(), me.display()),
        )?;

        let out = host.run(data.path())?;

        assert_refused(&host, &out, "which is not `aa-proxy`");
        Ok(())
    }

    // ── the endpoint itself ────────────────────────────────────────────────

    /// A proxy bound off-loopback would carry this session's decrypted traffic
    /// off the machine, to a host none of these checks can vouch for.
    #[test]
    fn launch_refuses_a_non_loopback_endpoint() -> anyhow::Result<()> {
        let host = Host::create()?;
        let proxy = TrustedProxy::start()?;
        let port = proxy
            .addr()
            .rsplit(':')
            .next()
            .expect("addr carries a port")
            .to_string();
        tamper_line(&proxy.data_dir().join("proxy.pid"), 1, &format!("10.0.0.5:{port}"));

        let out = host.run(proxy.data_dir())?;

        assert_refused(&host, &out, "not a loopback address");
        Ok(())
    }

    /// The record's address is where the proxy was *told* to listen. A proxy
    /// that died during startup leaves a record that can pass every other check
    /// while nothing answers, and a tool routed at a closed port does whatever
    /// it likes — historically, connect directly.
    #[test]
    fn launch_refuses_when_nothing_is_listening_at_the_recorded_endpoint() -> anyhow::Result<()> {
        let host = Host::create()?;
        let proxy = TrustedProxy::start()?;

        // A port nothing holds: bound and released.
        let free_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.local_addr()?.port()
        };
        tamper_line(
            &proxy.data_dir().join("proxy.pid"),
            1,
            &format!("127.0.0.1:{free_port}"),
        );

        let out = host.run(proxy.data_dir())?;

        assert_refused(&host, &out, "nothing is accepting connections");
        Ok(())
    }

    /// Write a state record at `data_dir/proxy.pid` with the mode the trust
    /// check requires, so a test aimed at some other field is not answered by
    /// the permission check instead.
    fn write_state(data_dir: &Path, content: &str) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let path = data_dir.join("proxy.pid");
        std::fs::write(&path, content)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
    }
}

/// A skip must be legible in the output; a test binary that silently contains no
/// tests is indistinguishable from a passing one.
#[cfg(not(unix))]
#[test]
fn proxy_trust_refusals_are_not_measured_on_this_host() {
    println!(
        "SKIP [AAASM-5323]: these cases need a POSIX shell stand-in for `claude` and POSIX file \
         modes; this host is {}.",
        std::env::consts::OS
    );
}
