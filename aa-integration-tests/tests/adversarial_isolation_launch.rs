//! AAASM-5532 — isolation/runtime slice of the adversarial enforcement
//! conformance harness: the real `aasm run` launch path, driven with a real
//! `aasm` binary, real proxy-vouching and real gateway registration, wired
//! into the [`adversarial`] module's `ControlledPair`/`assert_prevented`
//! vocabulary (AAASM-5712) — its first includer. Every other test binary in
//! this suite that references `adversarial::` was written after this file to
//! reuse it; before this ticket the module had none.
//!
//! # What this file measures, and what it deliberately does not
//!
//! AAASM-5532 lists seventeen candidate attack classes. This file covers
//! three, chosen because they are **real and runnable on this host** rather
//! than gated behind a Linux-only confinement backend this suite cannot
//! exercise on macOS CI/dev machines:
//!
//! 1. **Managed vs. unmanaged launch** (`default_launch_...`) — `aasm run`'s
//!    own `--isolation` flag defaults to [`aa-cli`'s `IsolationIntent::None`]
//!    (`aa-cli/src/commands/run.rs:150`), so a default governed launch
//!    negotiates **no** process-confinement backend at all. This scenario
//!    measures that honestly rather than assuming it: a forbidden write the
//!    launched program attempts lands identically whether the launch went
//!    through `aasm run` or not, and the launch's own machine-readable
//!    isolation report (`aa_isolation::IsolationReport::machine_lines`,
//!    printed to the live launch's stderr) says so — `posture=no_boundary`,
//!    `backend_selected=false` — rather than a stronger claim the run did not
//!    earn. This is the ticket's "current documentation wording and whether
//!    it matches the result" evidence field, made executable.
//! 2. **Fail-closed on an unavailable backend** (`requesting_isolation_...`)
//!    — a real [`ControlledPair`]: requesting `--isolation process
//!    --isolation-backend sandlock` on a host where that backend cannot be
//!    selected (this crate's own doc: "There is no fallback. A launch that
//!    asked for a boundary and quietly ran without one would report as
//!    governed while being unconfined") refuses the launch outright, so the
//!    forbidden write never lands — while the same launch differing only by
//!    `--isolation none` does let it land. Sandlock's own confinement is
//!    Linux-only and therefore *not* what this measures; what it measures is
//!    whether `aasm run` degrades silently when a boundary it cannot build
//!    was asked for, which is host-independent behaviour.
//! 3. **Interruption during a managed launch** (`sigterm_during_...`) — ticket
//!    scenario 13 (kill-after-syscall side effects): a real `aasm run`
//!    forwards `SIGTERM` to its child (`spawn_and_wait`'s own doc), and this
//!    measures whether a `SIGTERM` sent well before a delayed forbidden write
//!    stops that write from landing, against a control that differs only in
//!    whether the signal was sent.
//!
//! **Not covered by this pass**, and not stubbed to look otherwise:
//!
//! * Fork/exec, detached/re-parented descendants, and filesystem escape via
//!   symlink/rename against a real confinement boundary (ticket scenarios 10
//!   and part of the filesystem-escape ask) — both need a real confinement
//!   backend to have something to escape *from*. `aa-isolation-native` is
//!   Linux-only (its own crate doc: "The AASM-native **Linux**
//!   process-isolation backend") and `aa-isolation-sandlock` requires an
//!   external Linux supervisor; neither is exercisable on this host. A test
//!   that ran these against no boundary at all would measure nothing and
//!   report a hollow pass — worse than not writing it. These belong in the
//!   Linux-privileged/nightly lane the ticket's own AC calls for, against
//!   `aa-isolation-native` directly (see `aa-integration-tests/tests/
//!   adversarial/mod.rs`'s `Scratch`/`as_grandchild`/`shell_spec_using`
//!   helpers, already shaped for exactly this).
//! * Alternate-executable-resolution / PATH tricks (ticket scenario 6) —
//!   AAASM-5979 is an active, separate lane fixing a PATH/cwd-relative
//!   resolution defect in this same launch path. Adding a conformance test
//!   here now would either duplicate that lane's own regression test or pin
//!   today's pre-fix behaviour as a silent tripwire that inverts and red the
//!   moment that lane merges, with no note explaining why. Left for a
//!   follow-up once AAASM-5979 lands.
//! * Inherited environment / ambient credentials — measured and found to be
//!   *intentional* pass-through (only `HTTP(S)_PROXY`/`ALL_PROXY`/`NO_PROXY`
//!   and their lowercase forms are stripped from the child's environment;
//!   `effective_child_env`'s own doc in `aa-cli/src/commands/run.rs` names
//!   this precisely), not a claimed boundary — the launched tool needs its
//!   own upstream credentials (e.g. `ANTHROPIC_API_KEY`) to function, so
//!   there is no protection claim here for a `ControlledPair` to test against
//!   (this is ticket scenario 15's territory, "agent possessing direct
//!   upstream credentials", not a bypass of anything advertised).
//! * Bounded concurrent runs — already covered end to end by
//!   `cli_run_concurrent_isolation.rs` (AAASM-5865) for the dimension that is
//!   actually measurable on this host: two genuinely concurrent governed
//!   launches get distinct dedicated proxies and non-cross-attributed audit
//!   trails. Filesystem-confinement concurrency has the same "no exercisable
//!   backend on this host" gap as fork/exec and symlink escape above.

#[allow(dead_code, unused_imports)]
mod grpc_gateway_support;
#[allow(dead_code, unused_imports)]
mod proxy_trust_support;

// First includer of `adversarial/mod.rs` (AAASM-5712) — every other file in
// this suite that references `adversarial::` was added after this one. It
// brings its own `evidence` submodule (`#[path = "../evidence/mod.rs"]`), so
// this file must not also declare a top-level `mod evidence;` — that would be
// the same file loaded via two `mod` paths in one binary (clippy's
// `duplicate_mod`), which is exactly why `spike_support`/`conformance_support`
// each declare it exactly once and re-export from `crate::evidence` instead.
// This file has no second declaration to collide, so it needs no re-export
// either — call sites below use `adversarial::measured`/`assert_prevented`
// directly, which already route through `adversarial::evidence` internally.
#[allow(dead_code, unused_imports)]
#[path = "adversarial/mod.rs"]
mod adversarial;

#[cfg(unix)]
mod isolation_launch {
    use std::io;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    use super::adversarial::{assert_prevented, measured, AttackFamily, ControlledPair, Effect, Scratch};
    use super::grpc_gateway_support::GrpcGateway;
    use super::proxy_trust_support::TrustedProxy;

    /// A narrow, enforcing policy — same shape `cli_run_concurrent_isolation.rs`
    /// and `cli_run_claude_governed_launch.rs` use. What it says has no bearing
    /// on anything asserted below (none of these scenarios call a policy-gated
    /// tool); it exists only to satisfy the AAASM-5349 precondition that some
    /// effective policy resolves before a governed launch proceeds at all.
    fn write_test_policy(dir: &Path, name: &str) -> io::Result<PathBuf> {
        let path = dir.join("policy.yaml");
        std::fs::write(
            &path,
            format!(
                "apiVersion: agent-assembly/v1\n\
                 kind: Policy\n\
                 metadata:\n\
                 \x20 name: {name}\n\
                 spec:\n\
                 \x20 tools:\n\
                 \x20   read_file:\n\
                 \x20     allow: true\n"
            ),
        )?;
        Ok(path)
    }

    /// A `claude`-named stub standing in for the real dev tool. `body` runs
    /// unconditionally except under `--version` (which `aa-devtool-claude-code`'s
    /// version probe calls during detection and must see a parseable reply
    /// from, or the launch never gets far enough to reach `body` at all).
    fn write_agent_stub(dir: &Path, body: &str) -> io::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let bin_dir = dir.join("bin");
        std::fs::create_dir_all(&bin_dir)?;
        let bin = bin_dir.join("claude");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"--version\" ]; then\n\
                 \x20 echo \"2.1.999 (Claude Code)\"\n\
                 \x20 exit 0\n\
                 fi\n\
                 {body}\n\
                 exit 0\n"
            ),
        )?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        Ok(bin)
    }

    /// Everything one `aasm run claude` invocation needs, laid out under `root`.
    /// Mirrors `cli_run_concurrent_isolation.rs::build_host`'s env/PATH shape —
    /// deliberately the same, so a difference in outcome between that file's
    /// scenarios and this one is attributable to what each measures, not to a
    /// harness divergence.
    struct Launch {
        cmd: Command,
    }

    #[allow(clippy::too_many_arguments)]
    fn build_launch(
        root: &Path,
        agent_id: &str,
        stub: &Path,
        policy: &Path,
        proxy: &TrustedProxy,
        gateway_endpoint: &str,
        forbidden_write: &Path,
        extra_args: &[&str],
    ) -> anyhow::Result<Launch> {
        let home = root.join("home");
        let project = root.join("project");
        let state = root.join("state");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&project)?;

        let path_var = {
            let mut parts = vec![
                stub.parent().expect("stub has a parent").to_path_buf(),
                proxy.proxy_bin_dir().to_path_buf(),
            ];
            parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
            std::env::join_paths(parts)?
        };

        let mut cmd = Command::new(proxy.aasm());
        cmd.current_dir(&project)
            .env("HOME", &home)
            .env("PATH", &path_var)
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("AASM_STATE_DIR", &state)
            .env("AA_CA_DIR", root.join("ca"))
            .env("AASM_CLAUDE_MANAGED_ROOT", root.join("managed"))
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("AA_GATEWAY_ENDPOINT", gateway_endpoint)
            // The stub reads this to know where to attempt its forbidden
            // write; never a real credential path, and never read by
            // anything other than the stub this test wrote.
            .env("AA_TEST_FORBIDDEN_WRITE", forbidden_write)
            .args(["run", "claude", "--policy", &policy.to_string_lossy(), "--agent-id", agent_id])
            .args(extra_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        Ok(Launch { cmd })
    }

    /// The last `n` lines of `s`, for a failure message that doesn't dump an
    /// entire launch's output.
    fn tail(s: &str, n: usize) -> String {
        s.lines()
            .rev()
            .take(n)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    }

    // -----------------------------------------------------------------------
    // Scenario 1: managed vs. unmanaged launch (ticket scenario 5).
    // -----------------------------------------------------------------------

    const SCENARIO_MANAGED_VS_UNMANAGED: &str = "aaasm5532_default_launch_matches_unmanaged_reality";

    /// AC: a default governed launch (`--isolation none`, the CLI default)
    /// applies no process-confinement boundary, and says so truthfully in its
    /// own machine-readable report — it never reports readiness or prevention
    /// for a boundary it did not build. The forbidden write is the same
    /// control both runs share by construction: the identical stub script,
    /// invoked either through `aasm run` or directly.
    #[tokio::test(flavor = "multi_thread")]
    async fn default_launch_provides_no_boundary_and_a_forbidden_write_lands_exactly_as_it_would_unmanaged(
    ) -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let scratch = Scratch::new("aaasm5532-managed-vs-unmanaged");

        let tmp = tempfile::tempdir()?;
        let root = tmp.path();
        let stub = write_agent_stub(root, "echo reached > \"$AA_TEST_FORBIDDEN_WRITE\"")?;
        let policy = write_test_policy(root, "aaasm5532-managed-vs-unmanaged")?;

        // ── the managed run ─────────────────────────────────────────────
        let managed_forbidden = scratch.forbidden().join("managed.txt");
        let mut managed = build_launch(
            root,
            "aaasm5532-managed-vs-unmanaged-agent",
            &stub,
            &policy,
            &proxy,
            gateway.endpoint(),
            &managed_forbidden,
            &[],
        )?;
        let managed_out = managed.cmd.output()?;
        let managed_stderr = String::from_utf8_lossy(&managed_out.stderr).into_owned();
        assert!(
            managed_out.status.success(),
            "the managed launch itself must succeed for its isolation report to mean anything\n\
             stdout tail:\n{}\nstderr tail:\n{}",
            tail(&String::from_utf8_lossy(&managed_out.stdout), 40),
            tail(&managed_stderr, 40),
        );
        let managed_observed = managed_forbidden.exists();

        // ── the unmanaged control: the identical script, run directly ──────
        let unmanaged_forbidden = scratch.forbidden().join("unmanaged.txt");
        let unmanaged_out = Command::new("/bin/sh")
            .arg(&stub)
            .env("AA_TEST_FORBIDDEN_WRITE", &unmanaged_forbidden)
            .output()?;
        assert!(
            unmanaged_out.status.success(),
            "the unmanaged control script must itself run cleanly"
        );
        let unmanaged_observed = unmanaged_forbidden.exists();

        // A forbidden write is a bypass claim only where a boundary was
        // supposed to stop it. Here none was requested, so the honest
        // measurement is symmetry, not prevention — `assert_prevented`
        // would be the wrong assertion to reach for.
        assert_eq!(
            managed_observed, unmanaged_observed,
            "a default `aasm run` launch and a fully unmanaged run of the identical script must land \
             the same forbidden write the same way — managed_observed={managed_observed} \
             unmanaged_observed={unmanaged_observed}",
        );
        assert!(
            managed_observed,
            "the control premise (an unconfined write lands) does not hold on this host, so the \
             symmetry above is unattributable",
        );

        // ── the launch's own report must say so, not something stronger ────
        assert!(
            managed_stderr.contains("posture=no_boundary"),
            "a default launch must report `posture=no_boundary`, not a stronger claim it did not \
             earn; stderr tail:\n{}",
            tail(&managed_stderr, 60),
        );
        assert!(
            managed_stderr.contains("backend_selected=false"),
            "a default launch must report `backend_selected=false`; stderr tail:\n{}",
            tail(&managed_stderr, 60),
        );

        measured(
            SCENARIO_MANAGED_VS_UNMANAGED,
            AttackFamily::ObserveAndDegradedTruthfulness,
            "a default `aasm run claude` launch lands a forbidden write exactly as an unmanaged run \
             of the same script does, and its own machine-readable isolation report honestly states \
             posture=no_boundary / backend_selected=false rather than a stronger claim",
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Scenario 2: fail-closed on an unavailable backend.
    // -----------------------------------------------------------------------

    const SCENARIO_FAIL_CLOSED: &str = "aaasm5532_unavailable_backend_refuses_rather_than_bypasses";

    /// AC: requesting an execution-isolation boundary this host cannot build
    /// refuses the launch outright — the forbidden write never lands — while
    /// the identical launch differing only by `--isolation none` does let it
    /// land. `aa-isolation-sandlock`'s own confinement is Linux-only and is
    /// not what this measures; what is measured is `aa-cli`'s own refusal
    /// path (`aa-cli/src/commands/run.rs::explicit_backend`), which is
    /// host-independent behaviour this host can genuinely exercise, since
    /// `sandlock` is unavailable here.
    #[tokio::test(flavor = "multi_thread")]
    async fn requesting_isolation_on_an_unavailable_backend_refuses_the_launch_rather_than_running_unconfined(
    ) -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let scratch = Scratch::new("aaasm5532-fail-closed");

        let tmp = tempfile::tempdir()?;
        let root = tmp.path();
        let stub = write_agent_stub(root, "echo reached > \"$AA_TEST_FORBIDDEN_WRITE\"")?;
        let policy = write_test_policy(root, "aaasm5532-fail-closed")?;

        // ── attack: ask for a boundary this host cannot build ──────────────
        let attack_forbidden = scratch.forbidden().join("attack.txt");
        let attack_root = root.join("attack");
        std::fs::create_dir_all(&attack_root)?;
        let mut attack = build_launch(
            &attack_root,
            "aaasm5532-fail-closed-attack",
            &stub,
            &policy,
            &proxy,
            gateway.endpoint(),
            &attack_forbidden,
            &["--isolation", "process", "--isolation-backend", "sandlock"],
        )?;
        let attack_out = attack.cmd.output()?;
        let attack_observed = attack_forbidden.exists();
        let attack_detail = format!(
            "exit={:?} stderr tail:\n{}",
            attack_out.status.code(),
            tail(&String::from_utf8_lossy(&attack_out.stderr), 30),
        );

        // ── control: the same launch, differing only by `--isolation none` ──
        let control_forbidden = scratch.forbidden().join("control.txt");
        let control_root = root.join("control");
        std::fs::create_dir_all(&control_root)?;
        let mut control = build_launch(
            &control_root,
            "aaasm5532-fail-closed-control",
            &stub,
            &policy,
            &proxy,
            gateway.endpoint(),
            &control_forbidden,
            &["--isolation", "none"],
        )?;
        let control_out = control.cmd.output()?;
        let control_observed = control_forbidden.exists();
        let control_detail = format!(
            "exit={:?} stderr tail:\n{}",
            control_out.status.code(),
            tail(&String::from_utf8_lossy(&control_out.stderr), 30),
        );

        let pair = ControlledPair::new(
            AttackFamily::BackendPosture,
            Effect::new(
                "aasm run claude --isolation process --isolation-backend sandlock (unavailable on this host)",
                attack_observed,
                attack_detail,
            ),
            Effect::new("aasm run claude --isolation none", control_observed, control_detail),
        );
        assert_prevented(SCENARIO_FAIL_CLOSED, &pair);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Scenario 3: interruption during a managed launch (ticket scenario 13).
    // -----------------------------------------------------------------------

    const SCENARIO_SIGTERM: &str = "aaasm5532_sigterm_stops_a_delayed_side_effect";

    fn signal_group(pgid: i32, signal: i32) {
        unsafe {
            libc::kill(-pgid, signal);
        }
    }

    struct GroupReaper(i32);
    impl Drop for GroupReaper {
        fn drop(&mut self) {
            signal_group(self.0, libc::SIGKILL);
        }
    }

    /// AC: `SIGTERM` sent to a managed launch, well before its child's own
    /// delayed forbidden write, stops that write from landing — a real
    /// kill-after-syscall measurement (not an exit-status proxy for it): the
    /// effect asserted on is the file's existence, never the launcher's exit
    /// code. `spawn_and_wait`'s own doc names forwarding `SIGTERM`/`SIGINT`
    /// to the child as existing behaviour; this is the first test to measure
    /// what that forwarding actually accomplishes against a real side effect.
    #[tokio::test(flavor = "multi_thread")]
    async fn sigterm_during_a_managed_launch_stops_the_child_before_its_delayed_side_effect_lands() -> anyhow::Result<()>
    {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let scratch = Scratch::new("aaasm5532-sigterm");

        let tmp = tempfile::tempdir()?;
        let root = tmp.path();
        // Three seconds is comfortably longer than the 500ms this test waits
        // before signalling, and comfortably shorter than the 30s dev-tool
        // detection/registration overhead already budgeted for other launches
        // in this suite would need to be exceeded for a false pass.
        let stub = write_agent_stub(root, "sleep 3; echo reached > \"$AA_TEST_FORBIDDEN_WRITE\"")?;
        let policy = write_test_policy(root, "aaasm5532-sigterm")?;

        // ── attack: SIGTERM sent 500ms after spawn, well before the sleep ──
        let attack_forbidden = scratch.forbidden().join("attack.txt");
        let attack_root = root.join("attack");
        std::fs::create_dir_all(&attack_root)?;
        let mut attack = build_launch(
            &attack_root,
            "aaasm5532-sigterm-attack",
            &stub,
            &policy,
            &proxy,
            gateway.endpoint(),
            &attack_forbidden,
            &[],
        )?;
        attack.cmd.process_group(0);
        let mut attack_child = attack.cmd.spawn()?;
        let attack_pgid = attack_child.id() as i32;
        let _attack_reaper = GroupReaper(attack_pgid);

        tokio::time::sleep(Duration::from_millis(500)).await;
        signal_group(attack_pgid, libc::SIGTERM);

        let attack_deadline = std::time::Instant::now() + Duration::from_secs(10);
        let attack_status = loop {
            if let Some(status) = attack_child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() > attack_deadline {
                signal_group(attack_pgid, libc::SIGKILL);
                break attack_child.wait()?;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let attack_observed = attack_forbidden.exists();
        let attack_detail = format!("launcher exit={:?} after SIGTERM at +500ms", attack_status.code());

        // ── control: the same launch, differing only by not being signalled ──
        let control_forbidden = scratch.forbidden().join("control.txt");
        let control_root = root.join("control");
        std::fs::create_dir_all(&control_root)?;
        let mut control = build_launch(
            &control_root,
            "aaasm5532-sigterm-control",
            &stub,
            &policy,
            &proxy,
            gateway.endpoint(),
            &control_forbidden,
            &[],
        )?;
        let control_out = control.cmd.output()?;
        let control_observed = control_forbidden.exists();
        let control_detail = format!(
            "launcher exit={:?}, never signalled, left to run its full 3s sleep",
            control_out.status.code(),
        );

        let pair = ControlledPair::new(
            AttackFamily::ForbiddenFilesystemWrite,
            Effect::new(
                "aasm run claude, SIGTERM at +500ms (write delayed 3s)",
                attack_observed,
                attack_detail,
            ),
            Effect::new(
                "aasm run claude, left to run uninterrupted",
                control_observed,
                control_detail,
            ),
        );
        assert_prevented(SCENARIO_SIGTERM, &pair);
        Ok(())
    }
}

/// A skip must be legible in the output; a test binary that silently contains
/// no tests is indistinguishable from a passing one.
#[cfg(not(unix))]
#[test]
fn adversarial_isolation_launch_is_not_measured_on_this_host() {
    println!("SKIP [aaasm5532_isolation_launch]: unix-only scenarios, this host is not unix");
}
