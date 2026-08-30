//! AAASM-5866 — a governed launch must leave no orphaned dedicated proxy
//! process behind, on any termination path (AAASM-5857 mandatory
//! verification scenarios A, D, E).
//!
//! # What this measures
//!
//! `ProxyGuard`'s `Drop` (`aa-cli/src/commands/proxy/guard.rs`) is the
//! teardown mechanism: SIGTERM, poll, SIGKILL. Its own crate has unit
//! coverage that `Drop` runs and sends signals. What no test drives is the
//! **process tree as observed from outside `aasm run`** across the actual
//! termination paths an operator or a bug can produce — the case where a
//! defect (an early `return`/`?` that skips the drop, a detached child, a
//! signal race) would surface as a real orphaned process, not as a Rust
//! value going out of scope correctly in a unit test's own process.
//!
//! Each scenario here spawns a real `aasm run`, captures the dedicated
//! proxy's OS pid by scanning for a child of the `aasm` process (matching
//! neither by name alone — a leftover process with the same argv from an
//! unrelated run must not be mistaken for this launch's own), drives the
//! termination path under test, and then asserts the pid is actually gone
//! (`kill -0` fails) rather than merely that `aasm run`'s own exit code
//! looked right.
//!
//! * **A — normal exit**: the launched tool exits on its own; the dedicated
//!   proxy must not survive `aasm run`'s own exit.
//! * **D — proxy-start failure**: `aa-proxy` is not resolvable; the launch
//!   must fail closed with nothing spawned at all — not "started then
//!   leaked", but never started.
//! * **E — proxy crash mid-session**: the dedicated proxy is killed out from
//!   under a still-running session. There is no mid-session liveness
//!   watchdog in `aasm run` today (nothing polls the child's `try_wait`
//!   after spawn) — so what this scenario can honestly measure is not "the
//!   launcher notices and reacts", but the weaker, still-true claim the
//!   product actually makes: a dead dedicated proxy is a dead TCP listener,
//!   so nothing can silently route through it un-intercepted. Asserting the
//!   stronger claim (active detection) would be asserting a premise this
//!   code does not implement.
//!
//! Scenario B/C/H (cross-attribution under concurrency) is
//! `cli_run_concurrent_isolation.rs`'s subject, not this file's — see that
//! module doc for why sequential/concurrent isolation is split out
//! separately from leak-freedom.

#[allow(unused_imports)]
mod common;
#[allow(dead_code, unused_imports)]
mod conformance_support;
#[allow(unused_imports)]
mod grpc_gateway_support;
#[allow(unused_imports)]
mod proxy_trust_support;
#[allow(dead_code, unused_imports)]
mod spike_support;

// AAASM-5977: re-exported from `common::precondition`, which already loads
// this file — a second `#[path] mod evidence;` here would load it twice in
// one binary (clippy's `duplicate_mod`). A `use`, not a `mod`.
#[allow(unused_imports)]
pub use common::precondition::evidence;

#[cfg(unix)]
mod leak_freedom {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::grpc_gateway_support::GrpcGateway;
    use super::proxy_trust_support::{aasm_binary, cargo_target_dir, TrustedProxy};

    const AGENT_ID: &str = "aaasm5866-agent";

    /// How long to wait for the dedicated proxy's pid to appear as a child of
    /// `aasm run`. Raised from 15s to 45s while chasing a local failure that
    /// turned out to have a different cause (see `write_short_lived_stub`) —
    /// this widening did not fix that failure, so treat it only as headroom
    /// against `ProxyGuard::spawn`'s fork happening after this launch's own
    /// gRPC registration with the gateway (AAASM-5863), not as a proven need.
    /// Kept at 45s as cheap insurance on a dev machine that runs several
    /// other concurrent Claude Code sessions; CI runners are far less loaded.
    const PROXY_CHILD_PATIENCE: Duration = Duration::from_secs(45);

    fn write_test_policy(dir: &Path) -> std::io::Result<PathBuf> {
        let path = dir.join("policy.yaml");
        std::fs::write(
            &path,
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n\
             \x20 name: aaasm5866-leak-freedom\n\
             spec:\n\
             \x20 tools:\n\
             \x20   read_file:\n\
             \x20     allow: true\n\
             \x20   shell:\n\
             \x20     allow: false\n",
        )?;
        Ok(path)
    }

    /// Exits almost immediately after reporting — for the normal-exit
    /// scenario, where the session's own natural lifetime is what tears the
    /// proxy down.
    ///
    /// Not a bare `exit 0`: on a machine under heavy concurrent load (this
    /// dev machine routinely runs several other Claude Code sessions with
    /// their own subprocess trees), an instantly-exiting child lets the
    /// whole `aasm run` lifecycle — spawn proxy, launch stub, stub exits,
    /// tear proxy down, `aasm run` exits — complete inside a single CPU
    /// scheduling gap of this test's own polling thread, so the dedicated
    /// proxy's pid can come and go without a single poll ever landing while
    /// it exists. That is a hole in this test's *observation*, not evidence
    /// the proxy leaked or failed to start — a longer patience window
    /// doesn't help, since the race is about scheduling granularity, not
    /// duration (confirmed: still failed at 45s patience). A brief
    /// deterministic sleep before exit doesn't change what scenario A
    /// measures (a normally-exiting session must not leak its proxy) — it
    /// just gives the polling thread a real window to land in.
    fn write_short_lived_stub(dir: &Path) -> std::io::Result<PathBuf> {
        write_stub(dir, "sleep 0.5\nexit 0")
    }

    /// Survives until `SIGTERM`, then exits promptly — for scenarios that
    /// need a session alive long enough to signal or to observe the proxy
    /// mid-session, without depending on a fixed sleep duration racing the
    /// test.
    fn write_long_lived_stub(dir: &Path) -> std::io::Result<PathBuf> {
        write_stub(dir, "trap 'exit 0' TERM\nwhile true; do sleep 0.2; done")
    }

    fn write_stub(dir: &Path, tail: &str) -> std::io::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let bin_dir = dir.join("bin");
        std::fs::create_dir_all(&bin_dir)?;
        let bin = bin_dir.join("claude");
        std::fs::write(
            &bin,
            format!(
                r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "2.1.999 (Claude Code)"
  exit 0
fi
{{
  echo "AA_AGENT_ID=$AA_AGENT_ID"
  echo "HTTPS_PROXY=$HTTPS_PROXY"
}} > "$AA_TEST_ENV_DUMP"
{tail}
"#
            ),
        )?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        Ok(bin)
    }

    fn parse_dump(raw: &str) -> BTreeMap<String, String> {
        raw.lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Everything one scenario needs to launch `aasm run` and then interrogate
    /// or signal it from outside.
    struct Host {
        dump: PathBuf,
        cmd: std::process::Command,
    }

    fn build_host(stub_dir: &Path, proxy: &TrustedProxy, gateway_endpoint: &str, stub: &Path) -> anyhow::Result<Host> {
        let tmp_root = stub_dir.to_path_buf();
        let home = tmp_root.join("home");
        let project = tmp_root.join("project");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&project)?;
        let policy = write_test_policy(&tmp_root)?;
        let dump = tmp_root.join("child-env.txt");

        let path_var = {
            let mut parts = vec![
                stub.parent().expect("stub has a parent").to_path_buf(),
                proxy.proxy_bin_dir().to_path_buf(),
            ];
            parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
            std::env::join_paths(parts)?
        };

        let mut cmd = std::process::Command::new(aasm_binary());
        cmd.current_dir(&project)
            .env("HOME", &home)
            .env("PATH", &path_var)
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("AASM_STATE_DIR", tmp_root.join("state"))
            .env("AA_CA_DIR", tmp_root.join("ca"))
            .env("AASM_CLAUDE_MANAGED_ROOT", tmp_root.join("managed"))
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("AA_TEST_ENV_DUMP", &dump)
            .env("AA_GATEWAY_ENDPOINT", gateway_endpoint)
            .args([
                "run",
                "claude",
                "--policy",
                &policy.to_string_lossy(),
                "--agent-id",
                AGENT_ID,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());

        Ok(Host { dump, cmd })
    }

    /// The pid of a process that is a **direct child of `parent_pid`** and
    /// whose command line names `aa-proxy` — i.e., this launch's own
    /// dedicated proxy, not a leftover from an unrelated run or the
    /// standalone `TrustedProxy` (which is never a child of the `aasm run`
    /// process under test; it is spawned independently by this harness).
    fn find_proxy_child_pid(parent_pid: u32) -> Option<u32> {
        let out = std::process::Command::new("ps")
            .args(["-eo", "pid,ppid,command"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            // `split_whitespace` (not `splitn(3, char::is_whitespace)`):
            // `ps` right-pads the pid/ppid columns with multiple spaces, and
            // splitting on every individual whitespace char turns each run
            // of padding into empty tokens, corrupting the parse (this is a
            // real bug this test shipped with once — see AAASM-5866 review
            // history). `split_whitespace` collapses runs of whitespace and
            // skips empty tokens, which is what fixed-width `ps` output
            // actually needs. A line that still fails to parse (there
            // shouldn't be any, but `ps` output is not a contract) is
            // skipped with `continue`, not propagated with `?` — one
            // malformed line must not abort the whole scan and silently
            // report "no proxy found".
            let mut cols = line.split_whitespace();
            let Some(pid) = cols.next().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let Some(ppid) = cols.next().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let command: String = cols.collect::<Vec<_>>().join(" ");
            if ppid == parent_pid && command.contains("aa-proxy") {
                return Some(pid);
            }
        }
        None
    }

    /// Whether `pid` currently exists (`kill -0`) **and is not a zombie**.
    ///
    /// `kill(pid, 0)` succeeds for a zombie too — the process table entry
    /// lingers until the process's *real* parent calls `wait()` on it, which
    /// for a dedicated proxy killed out from under a still-running session
    /// (scenario E) is `aasm run`, and nothing in `aasm run` proactively
    /// reaps its proxy child mid-session (there is no liveness watchdog —
    /// see the module doc). A zombie has no CPU, no open listener, and will
    /// never run again; treating it as "still alive" would make this
    /// assertion measure `aasm run`'s reaping *promptness*, which this
    /// scenario deliberately does not exercise (see the module doc's
    /// scenario-E note), instead of the "the OS process is functionally
    /// dead" claim this function actually needs to answer.
    fn pid_is_alive(pid: u32) -> bool {
        // SAFETY: signal 0 sends nothing; it only probes existence and
        // permission, which is exactly what this needs and never affects
        // the target process.
        if unsafe { libc::kill(pid as libc::pid_t, 0) } != 0 {
            return false;
        }
        !pid_is_zombie(pid)
    }

    /// Whether `ps` reports `pid` in zombie (`Z`) state. `None`/parse failure
    /// (pid already gone by the time `ps` samples it, `ps` itself failing)
    /// is treated as "not a zombie" — `pid_is_alive`'s own `kill -0` call is
    /// the authority on existence; this only refines an existing "alive"
    /// verdict, never substitutes for it.
    fn pid_is_zombie(pid: u32) -> bool {
        let Ok(out) = std::process::Command::new("ps")
            .args(["-o", "state=", "-p", &pid.to_string()])
            .output()
        else {
            return false;
        };
        String::from_utf8_lossy(&out.stdout).trim().starts_with('Z')
    }

    /// Every `pid,ppid,command` row of the whole process table — diagnostic
    /// only, dumped into a panic message so a failure to find the expected
    /// child is debuggable from CI/log output alone instead of requiring a
    /// live repro.
    fn dump_process_table() -> String {
        std::process::Command::new("ps")
            .args(["-eo", "pid,ppid,command"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_else(|e| format!("<ps failed: {e}>"))
    }

    fn wait_for_pid_alive(parent_pid: u32, patience: Duration) -> Option<u32> {
        let deadline = Instant::now() + patience;
        while Instant::now() < deadline {
            if let Some(pid) = find_proxy_child_pid(parent_pid) {
                return Some(pid);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    fn wait_for_pid_gone(pid: u32, patience: Duration) -> bool {
        let deadline = Instant::now() + patience;
        while Instant::now() < deadline {
            if !pid_is_alive(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        !pid_is_alive(pid)
    }

    /// Poll for a file becoming readable, rather than checking once.
    ///
    /// The proxy child pid becoming visible at the OS level (`wait_for_pid_alive`)
    /// is an earlier, weaker signal than the tool having actually finished writing
    /// its "started" report — under instrumented (`cargo llvm-cov`) execution the
    /// gap between the two widens enough to flip a one-shot check to `Err`
    /// (AAASM-6012). Bounded the same way as the other readiness waits in this
    /// file, not a fixed sleep.
    fn wait_for_file_readable(path: &std::path::Path, patience: Duration) -> bool {
        let deadline = Instant::now() + patience;
        while Instant::now() < deadline {
            if std::fs::read_to_string(path).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        std::fs::read_to_string(path).is_ok()
    }

    /// Scenario A: a launch that runs to completion on its own must not
    /// leave its dedicated proxy running after it exits.
    #[tokio::test(flavor = "multi_thread")]
    async fn normal_exit_leaves_no_orphaned_proxy_process() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let stub = write_short_lived_stub(tmp.path())?;
        let host = build_host(tmp.path(), &proxy, gateway.endpoint(), &stub)?;

        let mut child = host.cmd;
        let mut running = child.spawn().expect("aasm run claude should execute");
        let aasm_pid = running.id();

        let proxy_pid = wait_for_pid_alive(aasm_pid, PROXY_CHILD_PATIENCE).unwrap_or_else(|| {
            panic!(
                "the dedicated proxy never appeared as a child of aasm pid {aasm_pid} within the \
                 patience window; full process table at the moment of failure:\n{}",
                dump_process_table(),
            )
        });

        let status = running.wait()?;
        assert!(status.success(), "aasm run claude should exit 0, got {status:?}");

        assert!(
            std::fs::read_to_string(&host.dump).is_ok(),
            "the tool must actually have run for this to be a meaningful normal-exit measurement",
        );

        assert!(
            wait_for_pid_gone(proxy_pid, Duration::from_secs(10)),
            "dedicated proxy pid {proxy_pid} is still alive after aasm run exited normally — a \
             normal-exit governed launch must not leak its proxy process",
        );

        drop(tmp);
        Ok(())
    }

    /// Scenario A (via the SIGTERM path an operator's Ctrl-C actually takes):
    /// terminating `aasm run` mid-session must tear the tool and the
    /// dedicated proxy down together, not leave either running.
    #[tokio::test(flavor = "multi_thread")]
    async fn sigterm_to_the_launcher_leaves_no_orphaned_proxy_process() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let stub = write_long_lived_stub(tmp.path())?;
        let host = build_host(tmp.path(), &proxy, gateway.endpoint(), &stub)?;

        let mut child = host.cmd;
        let mut running = child.spawn().expect("aasm run claude should execute");
        let aasm_pid = running.id();

        let proxy_pid = wait_for_pid_alive(aasm_pid, PROXY_CHILD_PATIENCE).unwrap_or_else(|| {
            panic!(
                "the dedicated proxy never appeared as a child of aasm pid {aasm_pid} within the \
                 patience window; full process table at the moment of failure:\n{}",
                dump_process_table(),
            )
        });
        assert!(
            wait_for_file_readable(&host.dump, PROXY_CHILD_PATIENCE),
            "the tool must have started (and reported) before this test signals the launcher, or \
             a SIGTERM sent too early would prove nothing about tearing down a live session",
        );

        // SAFETY: `aasm_pid` is this test's own freshly spawned child.
        let sigterm_ok = unsafe { libc::kill(aasm_pid as libc::pid_t, libc::SIGTERM) };
        assert_eq!(sigterm_ok, 0, "failed to send SIGTERM to aasm run's own pid {aasm_pid}");

        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = running.try_wait()? {
                break status;
            }
            if Instant::now() > deadline {
                let _ = running.kill();
                panic!("aasm run did not exit within 15s of receiving SIGTERM");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        // A signalled shutdown is not expected to report success; only that
        // it actually happened and tore everything down with it.
        let _ = status;

        assert!(
            wait_for_pid_gone(proxy_pid, Duration::from_secs(10)),
            "dedicated proxy pid {proxy_pid} is still alive after SIGTERM to aasm run — an \
             operator's Ctrl-C must not leave the dedicated proxy running",
        );

        drop(tmp);
        Ok(())
    }

    /// Scenario D: a launch that cannot start its dedicated proxy must
    /// refuse before anything is spawned — not spawn-then-leak.
    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_start_failure_spawns_nothing_to_leak() -> anyhow::Result<()> {
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let stub_dir = tmp.path().join("stubroot");
        std::fs::create_dir_all(&stub_dir)?;
        let stub = write_short_lived_stub(&stub_dir)?;

        let home = tmp.path().join("home");
        let project = tmp.path().join("project");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&project)?;
        let policy = write_test_policy(tmp.path())?;
        let dump = tmp.path().join("child-env.txt");

        // `resolve_binary` (`aa-cli/src/commands/proxy/start.rs`) also checks
        // beside the running `aasm` executable's own directory, before PATH —
        // so this needs a copy with no real `aa-proxy` sibling
        // (AAASM-5982), or the refusal this test exists to prove never
        // happens regardless of what PATH excludes.
        let aasm_alone = super::proxy_trust_support::aasm_without_proxy_sibling(&tmp.path().join("aasm-alone"))?;

        // Deliberately no `aa-proxy` anywhere on this PATH — only the stub's
        // own directory, so `which claude` still resolves but `which
        // aa-proxy` (inside `ProxyGuard::spawn`) cannot.
        let path_var = {
            let mut parts = vec![stub.parent().expect("stub has a parent").to_path_buf()];
            parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
            std::env::join_paths(parts)?
        };

        // A baseline snapshot of every `aa-proxy`-named process on the
        // system, taken before the launch — the assertion below is that
        // this set is **unchanged** afterward, which is a stronger, more
        // honest claim than "no aa-proxy child of this pid", since a launch
        // that never got as far as recording its own child relationship
        // would trivially pass the weaker check.
        let before = all_aa_proxy_pids();

        let out = std::process::Command::new(&aasm_alone)
            .current_dir(&project)
            .env("HOME", &home)
            .env("PATH", &path_var)
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("AASM_STATE_DIR", tmp.path().join("state"))
            .env("AA_CA_DIR", tmp.path().join("ca"))
            .env("AASM_CLAUDE_MANAGED_ROOT", tmp.path().join("managed"))
            .env("AA_TEST_ENV_DUMP", &dump)
            .env("AA_GATEWAY_ENDPOINT", gateway.endpoint())
            .args([
                "run",
                "claude",
                "--policy",
                &policy.to_string_lossy(),
                "--agent-id",
                AGENT_ID,
            ])
            .output()
            .expect("aasm run claude should execute (and refuse)");

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "a launch that cannot start its dedicated proxy must refuse, not succeed\nstderr:\n{stderr}",
        );
        assert!(
            stderr.contains("aa-proxy binary not found"),
            "the refusal must name the actual cause, not an unrelated gate\nstderr:\n{stderr}",
        );
        assert!(
            !dump.exists(),
            "the tool must never have been launched — a governed launch that cannot start its \
             proxy is not allowed to fall back to launching ungoverned",
        );

        // A brief settle window: even a refusal that spawned nothing takes a
        // moment to fully exit and for `ps` to reflect a clean process
        // table — this is not waiting for cleanup, only for the negative
        // result to be reliably observable.
        std::thread::sleep(Duration::from_millis(200));
        let after = all_aa_proxy_pids();
        // Subset, not equality: this machine runs several concurrent
        // sessions, each free to start or stop its own `aa-proxy` processes
        // (standalone or dedicated) between the two snapshots below — that
        // churn is real and expected, and is not this test's subject.
        // What *is* this test's subject is whether this refused launch
        // itself added anything, so the only sound assertion is "nothing
        // new appeared", not "the whole system-wide set held still".
        let newly_appeared: std::collections::BTreeSet<u32> = after.difference(&before).copied().collect();
        assert!(
            newly_appeared.is_empty(),
            "new aa-proxy-named process(es) appeared across a refused launch that spawned no tool: \
             {newly_appeared:?} (before: {before:?}, after: {after:?}) — a launch that cannot start \
             its dedicated proxy must not have started anything at all",
        );

        Ok(())
    }

    /// Every pid whose command line contains `aa-proxy` **and** was spawned
    /// from this test's own build tree. Used only as a before/after
    /// set-equality check, never to identify a specific launch's own proxy
    /// (that is [`find_proxy_child_pid`]'s job).
    ///
    /// Scoped to this tree's own `cargo_target_dir()`, not matched by name
    /// alone system-wide: this machine runs several concurrent, unrelated
    /// sessions, each free to start and stop its own `aa-proxy` processes
    /// (built from its own worktree's `target/`) between the two snapshots
    /// this function feeds a before/after diff — a name-only match cannot
    /// tell that churn apart from this refused launch's own. `resolve_binary`
    /// (`aa-cli/src/commands/proxy/guard.rs`, via `which`/`~/.cargo/bin`) and
    /// this harness's own `aasm_binary`/`aa_proxy_binary` both resolve to an
    /// absolute, canonicalized path, so a genuine leak from *this* launch's
    /// `aa-proxy` always carries this tree's `cargo_target_dir()` in its
    /// command line, while another session's own `aa-proxy` (built from a
    /// different `target/`, even a differently-named sibling worktree) never
    /// does — unless that session's `aa-proxy` happens to be a
    /// `~/.cargo/bin`-installed copy with no target-dir path in its argv at
    /// all, which this scoping cannot distinguish from a leak either; that
    /// residual gap is why this stays a diff (a pre-existing installed copy
    /// churning would appear in both `before` and `after`) rather than a bare
    /// "is the set nonempty" check.
    fn all_aa_proxy_pids() -> std::collections::BTreeSet<u32> {
        let tree_marker = cargo_target_dir().to_string_lossy().into_owned();
        let out = std::process::Command::new("ps")
            .args(["-eo", "pid,command"])
            .output()
            .expect("ps must be available on the platforms this test runs on");
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .skip(1)
            .filter(|l| l.contains("aa-proxy") && l.contains(&tree_marker))
            .filter_map(|l| l.split_whitespace().next()?.parse().ok())
            .collect()
    }

    /// Scenario E, honestly scoped: `aasm run` has no mid-session liveness
    /// watchdog on the dedicated proxy today, so killing it out from under a
    /// live session cannot be shown to make the launcher *notice*. What it
    /// does prove, and what "no silent ungoverned continuation" actually
    /// reduces to for this product: a governed session's traffic is routed
    /// at exactly one loopback address, and once that address has nothing
    /// listening on it, nothing can reach the network through it — there is
    /// no fallback path that would let traffic through unintercepted just
    /// because the interceptor died.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dead_dedicated_proxy_accepts_no_further_connections() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let stub = write_long_lived_stub(tmp.path())?;
        let host = build_host(tmp.path(), &proxy, gateway.endpoint(), &stub)?;

        let mut child = host.cmd;
        let running = child.spawn().expect("aasm run claude should execute");
        let aasm_pid = running.id();
        // Owns `running` from here on, not just its pid: this scenario
        // deliberately never lets `aasm run`'s own teardown run (there is
        // nothing in production code that would have triggered it), so it is
        // the only thing that will ever reap this child — on every exit path,
        // including the `?`/`assert!`/`panic!` early returns above the
        // explicit cleanup this function used to rely on, which left the
        // spawned process un-`wait()`ed on those paths (clippy correctly
        // flagged it: a value going out of scope on panic does not itself
        // wait() a `Child`, only `Drop` does that).
        let reaper = KillOnDrop(running);

        let proxy_pid = wait_for_pid_alive(aasm_pid, PROXY_CHILD_PATIENCE).unwrap_or_else(|| {
            panic!(
                "the dedicated proxy never appeared as a child of aasm pid {aasm_pid} within the \
                 patience window; full process table at the moment of failure:\n{}",
                dump_process_table(),
            )
        });

        let raw = std::fs::read_to_string(&host.dump)
            .unwrap_or_else(|e| panic!("the launched tool wrote no environment dump ({e})"));
        let seen = parse_dump(&raw);
        let proxy_url = seen
            .get("HTTPS_PROXY")
            .unwrap_or_else(|| panic!("the launched tool saw no HTTPS_PROXY; saw:\n{raw}"))
            .clone();
        let addr = proxy_url
            .strip_prefix("http://")
            .unwrap_or_else(|| panic!("unexpected proxy url shape: {proxy_url}"))
            .to_string();

        // Before killing it: the address is live — a positive control, so
        // "nothing answers after the kill" is known to mean something
        // rather than the address never having worked in the first place.
        assert!(
            std::net::TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(2)).is_ok(),
            "the dedicated proxy's own address must accept a connection before it is killed, or \
             this test cannot distinguish 'died' from 'never worked'",
        );

        // SAFETY: `proxy_pid` was just captured as a live child of this
        // test's own `aasm run` child — simulating a crash, not sending a
        // graceful signal, since the scenario under test is an abrupt
        // failure, not an orderly shutdown.
        let killed = unsafe { libc::kill(proxy_pid as libc::pid_t, libc::SIGKILL) };
        assert_eq!(killed, 0, "failed to SIGKILL the dedicated proxy pid {proxy_pid}");
        assert!(
            wait_for_pid_gone(proxy_pid, Duration::from_secs(5)),
            "the dedicated proxy did not actually die after SIGKILL — this scenario needs a \
             genuinely dead proxy to measure anything",
        );

        assert!(
            std::net::TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(2)).is_err(),
            "a connection to the dedicated proxy's address succeeded after the proxy process was \
             killed — something else is now listening there, which would let a governed session's \
             traffic through unintercepted",
        );

        // No explicit cleanup here: `reaper`'s `Drop` (below) kills and reaps
        // the still-running launcher/tool on every exit path from this point,
        // including this success path — this scenario deliberately did not
        // let `aasm run`'s own teardown run (there is nothing in production
        // code that would have triggered it), so nothing else will stop
        // these processes.
        drop(reaper);

        Ok(())
    }

    /// Kills and reaps the launcher (and whatever it still owns) on every
    /// exit path from [`a_dead_dedicated_proxy_accepts_no_further_connections`]
    /// — the success path (explicit `drop`, above) and a panicking assertion
    /// unwinding past it alike. Owns the `Child` itself, not just its pid:
    /// `wait()`ing it here, not only signalling it, is what keeps the
    /// spawned process from becoming a zombie under *this test's own*
    /// process on the panic paths a bare kill-by-pid guard would still leave
    /// un-reaped.
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[cfg(not(unix))]
#[test]
fn leak_freedom_is_not_measured_on_this_host() {
    let reason = format!(
        "the leak-freedom evidence needs POSIX signals and a POSIX shell stand-in for the \
         `claude` binary; this host is {}. AAASM-5866 is NOT evidenced here.",
        std::env::consts::OS
    );
    println!("SKIP [AAASM-5866]: {reason}");
    conformance_support::outcome::record(
        "aaasm-5866-leak-freedom",
        conformance_support::Measurement::UnsupportedPlatform,
        &reason,
    );
}
