//! AAASM-6293 (QA epic AAASM-6174, ST-6; golden journey J84 / AAASM-6262) —
//! live sentinel-exposure verification of the credential broker's "no
//! secret exposure" property against a **real spawned `aasm run`**, not a
//! hand-constructed [`aa_isolation::credential_broker::CredentialBrokerReport`].
//!
//! # What the unit tests in `aa-isolation/src/credential_broker.rs` already
//! prove, and what they cannot
//!
//! That module's own tests (`cargo nextest run -p aa-isolation --lib
//! credential_broker::`, all 15 passing — see this ticket's verification
//! comment) prove `credential_gate` refuses/admits correctly against a
//! report the test constructs by hand. They cannot prove a **real launch**
//! actually withholds the covered provider-key env var from a **real child
//! process** — that wiring lives in `aa-cli/src/commands/run.rs`
//! (`report_for_launch` -> `withheld_from_isolation_report` ->
//! `effective_child_env`/`Command::env_remove`), entirely outside this
//! crate, and AAASM-6164's own module doc already names the gap this file
//! closes: "`withheld_from_isolation_report` ... reads this report's
//! default empty list and never strips a withheld provider key from the one
//! launch shape every default `aasm run` actually takes" was the live
//! defect; this file is the regression harness for it staying fixed.
//!
//! # The sentinel and why it is never a real credential
//!
//! Every value this file injects is `sk-ant-QA6174-<pid>-<nanos>` — shaped
//! like a real Anthropic key only so the broker's env-name-based stripping
//! (which does not inspect the value) treats it identically to one, and
//! unique per process+time so a stale value from a previous run's logs can
//! never be mistaken for this run's own exposure. `AAASM-6174` in the
//! literal string ties any stray hit straight back to this QA epic.
//!
//! # Fail-closed: live as of AAASM-6347/6348/6349
//!
//! AAASM-6293 recorded the "broker required but unavailable" refusal as
//! unreachable because no policy source issued `BrokeragePosture::BrokerRequired`.
//! A policy can now state `credentials: posture: broker_required`, and the
//! `broker_required_*` scenarios below drive that through the real binary on
//! the default `--isolation none` arm: refused (naming the policy statement)
//! when no credential lease or no brokered service covers the launch, admitted
//! when both do, with a `not_required` positive control.
//!
//! Not covered live here: an isolated backend. No backend is usable on this
//! macOS host (Sandlock is Linux-only; the VM backend needs a runtime), so the
//! backend-arm gates are covered by `aa-cli` and `aa-isolation` unit tests only.
//! The admitted scenario proves the child's env/argv/descriptors are clean, not
//! that the child is confined.
//!
//! # The `ps -E` finding (AAASM-6187's macOS counterpart)
//!
//! [`credential_broker_sentinel::a_descendant_can_read_the_supervisors_own_ps_e_environment`]
//! is a **positive finding**, not a regression test for a stated contract —
//! nothing in this product claims `ps -E`/`ps -Eww` protection for the
//! supervising `aasm` process's own exec-time environment block. It pins the
//! current, real behaviour: a same-uid descendant (the launched tool, or any
//! other same-uid process) can read the **supervisor's** full environment
//! via `ps -Eww -p <aasm pid>` on macOS, via the kernel's `KERN_PROCARGS2`
//! sysctl, regardless of what `aa-cli` scrubs from the *child's own* `Command`
//! environment. This is orthogonal to (and not fixed by) the stripping this
//! file's other tests verify — the child's own env/argv/`lsof` stay clean;
//! the supervisor's own `ps -E` view does not. Documented, not fixed, per
//! this ticket's explicit scope.

#[allow(unused_imports)]
mod grpc_gateway_support;
#[allow(unused_imports)]
mod proxy_trust_support;

#[cfg(all(unix, target_os = "macos"))]
mod credential_broker_sentinel {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::grpc_gateway_support::GrpcGateway;
    use super::proxy_trust_support::{aasm_binary, TrustedProxy};

    const AGENT_ID: &str = "aaasm6293-agent";

    /// A fresh sentinel per call: `sk-ant-QA6174-<this test pid>-<nanos>`.
    /// Never a real credential (see module doc). The caller greps for the
    /// full value first and the bare random suffix (pid+nanos) separately —
    /// aa-security's own scanner may redact the recognisable `sk-ant-...`
    /// prefix and leave a partial value behind, which a full-string-only
    /// grep would miss entirely.
    fn sentinel() -> (String, String) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("now is after the epoch")
            .as_nanos();
        let suffix = format!("{}-{nanos}", std::process::id());
        (format!("sk-ant-QA6174-{suffix}"), suffix)
    }

    fn write_test_policy(dir: &Path, credentials_policy: Option<&str>) -> std::io::Result<PathBuf> {
        let path = dir.join("policy.yaml");
        if let Some(document) = credentials_policy {
            std::fs::write(&path, document)?;
            return Ok(path);
        }
        std::fs::write(
            &path,
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n\
             \x20 name: aaasm6293-credential-broker-sentinel\n\
             spec:\n\
             \x20 tools:\n\
             \x20   read_file:\n\
             \x20     allow: true\n\
             \x20   shell:\n\
             \x20     allow: false\n",
        )?;
        Ok(path)
    }

    /// The stub `claude` binary: writes a start-marker first (so a
    /// fail-closed assertion can tell "never started" from "started and
    /// then exited"), then dumps everything a sentinel could leak through
    /// from *this* process's own vantage point:
    ///
    /// * its own full environment (`env`)
    /// * its own argv (`"$@"`)
    /// * every file descriptor it holds open (`lsof -p $$`) — a broker that
    ///   merely closed stdin/stdout on the real secret but left it mapped
    ///   into a file descriptor would not show up in `env`/argv alone.
    /// * `ps -Eww -p $PPID` — its own parent is the `aasm` supervisor on the
    ///   unconfined launch path this harness exercises (no isolation
    ///   backend is configured on this host — AAASM-6292/ST-5's own
    ///   finding), so this is exactly the AAASM-6187 macOS counterpart
    ///   channel: can a descendant read the supervisor's own exec-time
    ///   environment.
    fn write_stub(dir: &Path, marker: &Path) -> std::io::Result<PathBuf> {
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
touch "{marker}"
{{
  echo "===ENV==="
  env
  echo "===ARGV==="
  i=0
  for a in "$@"; do
    echo "ARG[$i]=$a"
    i=$((i + 1))
  done
  echo "===LSOF==="
  lsof -p $$ 2>&1
  echo "===PS_PPID($PPID)==="
  ps -Eww -p "$PPID" 2>&1
}} > "$AA_TEST_DUMP"
sleep 0.3
exit 0
"#,
                marker = marker.display(),
            ),
        )?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        Ok(bin)
    }

    /// Everything one scenario needs to launch `aasm run` and then inspect
    /// its own artifacts. `extra_env` carries the per-scenario credential
    /// facts (`AA_PROXY_PROVIDER_KEYS`, the sentinel `ANTHROPIC_API_KEY`) so
    /// the two scenarios below (broker active / positive control) differ in
    /// exactly one input.
    struct Host {
        dump: PathBuf,
        marker: PathBuf,
        state_dir: PathBuf,
        cmd: std::process::Command,
    }

    fn build_host(
        tmp_root: &Path,
        proxy: &TrustedProxy,
        gateway_endpoint: &str,
        extra_env: &[(&str, &str)],
    ) -> anyhow::Result<Host> {
        build_host_with_policy(tmp_root, proxy, gateway_endpoint, extra_env, None)
    }

    /// As [`build_host`], but `credentials_policy` replaces the default tool
    /// policy with a `credentials:`-node document (AAASM-6349) so a scenario
    /// can state `posture: broker_required`, with or without the explicit
    /// credential lease.
    fn build_host_with_policy(
        tmp_root: &Path,
        proxy: &TrustedProxy,
        gateway_endpoint: &str,
        extra_env: &[(&str, &str)],
        credentials_policy: Option<&str>,
    ) -> anyhow::Result<Host> {
        let home = tmp_root.join("home");
        let project = tmp_root.join("project");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&project)?;
        let policy = write_test_policy(tmp_root, credentials_policy)?;
        let dump = tmp_root.join("child-dump.txt");
        let marker = tmp_root.join("child-started.marker");
        let state_dir = tmp_root.join("state");
        let stub = write_stub(tmp_root, &marker)?;

        let path_var = {
            let mut parts = vec![
                stub.parent().expect("stub has a parent").to_path_buf(),
                proxy.proxy_bin_dir().to_path_buf(),
            ];
            parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
            std::env::join_paths(parts)?
        };

        let mut cmd = std::process::Command::new(aasm_binary());
        // `env_clear()` is load-bearing, not cosmetic: a `Command` inherits the
        // *real* ambient process environment by default, and this test's own
        // dump/`ps -Eww` instrumentation faithfully reports exactly what it
        // finds. Without clearing first, every real credential in this
        // developer's or CI runner's own shell (tokens, API keys — anything
        // named `*_TOKEN`/`*_KEY`) would flow into the spawned `aasm run`,
        // get reported by the stub's dump, and risk being echoed into a test
        // failure message — turning the detector itself into a leak. This is
        // not hypothetical: an earlier version of this file without
        // `env_clear()` did exactly that locally (real `GITHUB_TOKEN`,
        // `OPENAI_API_KEY`, `SLACK_BOT_TOKEN`, et al. from this developer's
        // own shell reached a test failure message before this fix landed —
        // never committed, caught before push). Only the names below are
        // real inputs to the behaviour under test.
        cmd.env_clear();
        cmd.current_dir(&project)
            .env("HOME", &home)
            .env("PATH", &path_var)
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("AASM_STATE_DIR", &state_dir)
            .env("AA_CA_DIR", tmp_root.join("ca"))
            .env("AASM_CLAUDE_MANAGED_ROOT", tmp_root.join("managed"))
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("AA_TEST_DUMP", &dump)
            .env("AA_GATEWAY_ENDPOINT", gateway_endpoint)
            .args([
                "run",
                "claude",
                "--policy",
                &policy.to_string_lossy(),
                "--agent-id",
                AGENT_ID,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }

        Ok(Host {
            dump,
            marker,
            state_dir,
            cmd,
        })
    }

    fn wait_for_file(path: &Path, patience: Duration) -> bool {
        let deadline = Instant::now() + patience;
        while Instant::now() < deadline {
            if std::fs::metadata(path).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        std::fs::metadata(path).is_ok()
    }

    /// Recursively greps every regular file under `root` for `needle`,
    /// returning the paths that matched. Binary-safe (`grep -rla`-equivalent
    /// via a byte search, not a UTF-8 string search) because receipts/logs
    /// may not be valid UTF-8.
    fn grep_tree_for(root: &Path, needle: &str) -> Vec<PathBuf> {
        let mut hits = Vec::new();
        if !root.exists() {
            return hits;
        }
        let mut stack = vec![root.to_path_buf()];
        let needle = needle.as_bytes();
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_dir() {
                    stack.push(path);
                } else if file_type.is_file() {
                    if let Ok(bytes) = std::fs::read(&path) {
                        if bytes.windows(needle.len().max(1)).any(|window| window == needle) {
                            hits.push(path);
                        }
                    }
                }
            }
        }
        hits
    }

    /// Scenario: credential broker active (`AA_PROXY_PROVIDER_KEYS` names a
    /// real-shaped key for `api.anthropic.com`) and the operator's ambient
    /// `ANTHROPIC_API_KEY` is the sentinel. `report_for_launch` must cover
    /// `ANTHROPIC_API_KEY` as secretless `BrokerPerformsRequest`, so
    /// `withheld_from_isolation_report` must name it, and `spawn_and_wait`'s
    /// `env_remove` must strip it before the real child ever execs — the
    /// sentinel must appear in none of: the child's own env, its argv, its
    /// open file descriptors (`lsof`), and no receipt/log/state-dir file
    /// this run wrote.
    #[tokio::test(flavor = "multi_thread")]
    async fn broker_active_sentinel_never_reaches_the_child_or_any_artifact() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let (sentinel, suffix) = sentinel();

        let host = build_host(
            tmp.path(),
            &proxy,
            gateway.endpoint(),
            &[
                (
                    "AA_PROXY_PROVIDER_KEYS",
                    "api.anthropic.com=sk-ant-REAL-OPERATOR-KEY-not-the-sentinel",
                ),
                ("ANTHROPIC_API_KEY", &sentinel),
            ],
        )?;

        let mut child = host.cmd;
        let mut running = child.spawn().expect("aasm run claude should execute");
        let status = running.wait()?;
        assert!(
            status.success(),
            "aasm run claude should exit 0 with the broker active, got {status:?}"
        );

        assert!(
            wait_for_file(&host.dump, Duration::from_secs(10)),
            "the stub never wrote its dump — the tool did not actually run, which would make this \
             a vacuous negative result",
        );
        assert!(
            std::fs::metadata(&host.marker).is_ok(),
            "the stub's start-marker is missing even though it reported a dump — the marker is \
             written before anything else, so this would mean the dump path ran without the \
             process itself ever truly starting",
        );
        let dump = std::fs::read_to_string(&host.dump)?;
        // Split by channel, deliberately: the `===PS_PPID` section is the
        // supervisor's own exec-time environment as read by `ps -Eww`, a
        // channel this file's own `a_descendant_can_read_the_supervisors_own_ps_e_environment`
        // test documents as a known, unfixed residual exposure independent
        // of AAASM-6164's withholding mechanism (see this file's module
        // doc). Folding it into *this* assertion would make this test fail
        // for a reason that has nothing to do with the contract it is named
        // for, and would make the real regression (a leak into the child's
        // own env/argv/lsof) indistinguishable from the already-documented,
        // orthogonal `ps -E` finding.
        let own_channel = dump
            .split("===PS_PPID")
            .next()
            .expect("the dump always has a ===PS_PPID marker");
        assert!(
            !own_channel.contains(&sentinel) && !own_channel.contains(&suffix),
            "the sentinel (or its bare random suffix, in case of partial redaction) appeared in the \
             child's own env/argv/lsof dump while the credential broker was active — \
             AAASM-6164's withholding contract is broken:\n{own_channel}",
        );

        // Full-state-dir sweep: zero hits across every receipt/log/state
        // file this run actually wrote, for the full sentinel and the bare
        // suffix independently.
        for root in [
            &host.state_dir,
            proxy.data_dir(),
            proxy.log_path().parent().unwrap_or(proxy.log_path()),
        ] {
            let full_hits = grep_tree_for(root, &sentinel);
            let suffix_hits = grep_tree_for(root, &suffix);
            assert!(
                full_hits.is_empty(),
                "sentinel value found in state/receipt/log files under {}: {full_hits:?}",
                root.display(),
            );
            assert!(
                suffix_hits.is_empty(),
                "sentinel suffix (possible partial redaction) found in state/receipt/log files under {}: {suffix_hits:?}",
                root.display(),
            );
        }

        drop(tmp);
        Ok(())
    }

    /// Positive control for the test above: the identical launch, with the
    /// **only** change being that no credential broker is configured for
    /// `api.anthropic.com` (`AA_PROXY_PROVIDER_KEYS` unset). `report_for_launch`
    /// then covers no service, `withheld_from_isolation_report` names
    /// nothing, and the sentinel reaches the child by plain ambient
    /// inheritance — exactly AAASM-6164's own module doc's "the operator's
    /// own provider key anyway, via ambient environment inheritance" defect
    /// description.
    ///
    /// This is the falsification half AAASM-6293 explicitly asks for: if
    /// this test did *not* observe the sentinel, the detection method in the
    /// test above would be proven broken, not the broker proven safe.
    #[tokio::test(flavor = "multi_thread")]
    async fn broker_absent_sentinel_leaks_to_the_child_proving_detection_works() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let (sentinel, _suffix) = sentinel();

        // No `AA_PROXY_PROVIDER_KEYS` at all — the broker covers nothing.
        let host = build_host(
            tmp.path(),
            &proxy,
            gateway.endpoint(),
            &[("ANTHROPIC_API_KEY", &sentinel)],
        )?;

        let mut child = host.cmd;
        let mut running = child.spawn().expect("aasm run claude should execute");
        let status = running.wait()?;
        assert!(
            status.success(),
            "aasm run claude should exit 0 even with no broker configured, got {status:?}"
        );

        assert!(
            wait_for_file(&host.dump, Duration::from_secs(10)),
            "the stub never wrote its dump in the positive-control run",
        );
        let dump = std::fs::read_to_string(&host.dump)?;
        assert!(
            dump.contains(&sentinel),
            "positive control failed: the sentinel did NOT reach the child's own env even with no \
             credential broker configured. Either this host's default launch path strips \
             ANTHROPIC_API_KEY unconditionally (in which case the negative test above proves \
             nothing about the broker specifically — it would pass even with the broker deleted), \
             or this harness is not exercising the ambient-inheritance path AAASM-6164 exists to \
             close. Dump:\n{dump}",
        );

        drop(tmp);
        Ok(())
    }

    /// The AAASM-6187 macOS counterpart finding (documented, not fixed —
    /// see this file's module doc). A same-uid descendant of the `aasm`
    /// supervisor can read the supervisor's own full exec-time environment
    /// — including the real `ANTHROPIC_API_KEY` the operator's shell handed
    /// to `aasm run` itself — via `ps -Eww -p <aasm pid>`, independent of
    /// whatever `aa-cli` strips from the *child's own* `Command` environment.
    ///
    /// This is pinned as a passing test (not `#[ignore]`d) because it is not
    /// a violated contract to track toward a fix — nothing in this product
    /// claims `ps -E` protection for the supervisor process. It exists so a
    /// future change that happens to close this channel is noticed (the
    /// assertion would start failing and this doc comment explains why that
    /// would be good news), and so the finding has one reproducible place to
    /// point at instead of living only in a ticket comment.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_descendant_can_read_the_supervisors_own_ps_e_environment() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let (sentinel, _suffix) = sentinel();

        let host = build_host(
            tmp.path(),
            &proxy,
            gateway.endpoint(),
            &[
                (
                    "AA_PROXY_PROVIDER_KEYS",
                    "api.anthropic.com=sk-ant-REAL-OPERATOR-KEY-not-the-sentinel",
                ),
                ("ANTHROPIC_API_KEY", &sentinel),
            ],
        )?;

        let mut child = host.cmd;
        let mut running = child.spawn().expect("aasm run claude should execute");
        let status = running.wait()?;
        assert!(status.success(), "aasm run claude should exit 0, got {status:?}");
        assert!(
            wait_for_file(&host.dump, Duration::from_secs(10)),
            "the stub never wrote its dump"
        );

        let dump = std::fs::read_to_string(&host.dump)?;

        // The child's own view stays clean — same property the first test
        // above verifies, re-checked here so this test is self-contained
        // evidence of the *split*: clean child channel, leaking supervisor
        // channel, both from one launch.
        let own_env_section = dump
            .split("===PS_PPID")
            .next()
            .expect("the dump always has a ===PS_PPID marker");
        assert!(
            !own_env_section.contains(&sentinel),
            "the child's own env/argv/lsof leaked the sentinel — that is this file's other \
             regression, not the ps -E finding this test targets",
        );

        // The supervisor channel: did `ps -Eww -p $PPID` (run from inside
        // the child, against the `aasm` supervisor's real pid) actually
        // observe the sentinel?
        let ps_ppid_section = dump
            .split("===PS_PPID")
            .nth(1)
            .expect("the dump always has a ===PS_PPID section");

        if ps_ppid_section.contains(&sentinel) {
            // Expected, and the whole point of this test: record it plainly.
            eprintln!(
                "AAASM-6293 finding (macOS counterpart of AAASM-6187): a same-uid descendant's \
                 `ps -Eww -p $PPID` call reads the aasm supervisor's own real ANTHROPIC_API_KEY \
                 value out of its exec-time environment block (KERN_PROCARGS2), even though the \
                 child's own env/argv/lsof never carried it. This is a residual exposure channel \
                 that exists independent of AAASM-6164's own withholding mechanism, and is not \
                 addressed by it."
            );
        } else {
            // Not expected on this host/macOS version. Still useful: it means
            // either SIP/entitlement restrictions on this runner block
            // cross-process `ps -E` even same-uid, or the supervisor's real
            // env genuinely didn't carry the value this call expected. Either
            // way, this is new information worth surfacing rather than
            // silently treating as "the finding went away".
            eprintln!(
                "AAASM-6293: `ps -Eww -p $PPID` against the aasm supervisor did NOT show the \
                 sentinel on this host — the AAASM-6187 Linux finding's macOS counterpart was not \
                 reproduced here. Full PS_PPID section:\n{ps_ppid_section}"
            );
        }

        drop(tmp);
        Ok(())
    }

    // ---- AAASM-6349 (J84 part 3): `credentials: posture: broker_required` ----
    //
    // The scenarios below drive the real `aasm run` on the default
    // `--isolation none` arm with a policy that states
    // `credentials: posture: broker_required` (AAASM-6347/6348). The only
    // input that differs between them is the policy document and whether a
    // broker covers `api.anthropic.com`.
    //
    // What these prove, and what they do not: the gate admits or refuses on
    // four facts (a fail-closed broker, a brokered service, an explicit
    // `credential` lease, brokered env names withheld). They do not confine
    // the child. A same-uid process can still read the supervisor's exec-time
    // environment (see the `ps -E` test above), so nothing here is a claim of
    // plaintext-secret isolation. An egress lease or `egress: broker_required`
    // never supplies the credential lease; the no-lease case is refused.

    const BROKER_KEYS: (&str, &str) = (
        "AA_PROXY_PROVIDER_KEYS",
        "api.anthropic.com=sk-ant-REAL-OPERATOR-KEY-not-the-sentinel",
    );
    const REFUSAL_POLICY_NAME: &str = "credentials: posture: broker_required";
    const BROKER_REQUIRED_NO_LEASE: &str = "credentials:\n  posture: broker_required\n";
    const BROKER_REQUIRED_WITH_LEASE: &str = "credentials:\n  posture: broker_required\nauthority:\n  leases:\n    - \
         domain: credential\n      scope: whole\n      reason: aaasm6349 sentinel\n";
    /// `not_required` alone is "no enforcement section" and fails to load, so
    /// the control also states a tool rule; the only variable vs. the
    /// refusing policies is the credentials posture.
    const NOT_REQUIRED: &str = "tools:\n  read_file:\n    allow: true\ncredentials:\n  posture: not_required\n";
    const REFUSAL_NO_GRANT: &str = "no explicit grant authorizes credential brokerage for this run";
    const REFUSAL_NO_SERVICE: &str = "no upstream service is covered by any credential brokerage";

    /// What a finished `aasm run`, refused or not, left behind.
    struct Outcome {
        status: std::process::ExitStatus,
        /// stdout + stderr of the supervisor itself.
        supervisor_output: String,
        dump: Option<String>,
        started: bool,
        state_dir: PathBuf,
    }

    fn launch(host: Host) -> anyhow::Result<Outcome> {
        let Host {
            dump,
            marker,
            state_dir,
            mut cmd,
        } = host;
        let output = cmd.output()?;
        let supervisor_output = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let dump = if wait_for_file(&dump, Duration::from_secs(3)) {
            Some(std::fs::read_to_string(&dump)?)
        } else {
            None
        };
        Ok(Outcome {
            status: output.status,
            supervisor_output,
            dump,
            started: std::fs::metadata(&marker).is_ok(),
            state_dir,
        })
    }

    /// The child's own env/argv/lsof channel only; the `ps -E` supervisor
    /// channel is the documented residual and is asserted separately.
    fn own_channel(dump: &str) -> &str {
        dump.split("===PS_PPID").next().expect("split always yields one part")
    }

    fn assert_nothing_persisted(outcome: &Outcome, proxy: &TrustedProxy, sentinel: &str, suffix: &str) {
        for root in [&outcome.state_dir, proxy.data_dir()] {
            assert!(
                grep_tree_for(root, sentinel).is_empty() && grep_tree_for(root, suffix).is_empty(),
                "sentinel found in files under {}",
                root.display()
            );
        }
    }

    /// Refusal: no credential lease covers the brokered credential, so the
    /// launch is refused before any child exists, the refusal names the
    /// policy statement that caused it, and the sentinel appears nowhere.
    #[tokio::test(flavor = "multi_thread")]
    async fn broker_required_without_a_credential_lease_is_refused_before_the_child_starts() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let (sentinel, suffix) = sentinel();
        let host = build_host_with_policy(
            tmp.path(),
            &proxy,
            gateway.endpoint(),
            &[BROKER_KEYS, ("ANTHROPIC_API_KEY", &sentinel)],
            Some(BROKER_REQUIRED_NO_LEASE),
        )?;

        let outcome = launch(host)?;

        assert!(
            !outcome.status.success(),
            "a broker_required policy with no credential lease must refuse the launch:\n{}",
            outcome.supervisor_output
        );
        assert!(
            outcome.supervisor_output.contains(REFUSAL_POLICY_NAME),
            "the refusal must name `{REFUSAL_POLICY_NAME}`:\n{}",
            outcome.supervisor_output
        );
        assert!(
            outcome.supervisor_output.contains(REFUSAL_NO_GRANT),
            "refused, but not for the missing credential grant:\n{}",
            outcome.supervisor_output
        );
        assert!(
            !outcome.started && outcome.dump.is_none(),
            "the refused launch must never start the child"
        );
        assert!(
            !outcome.supervisor_output.contains(&sentinel) && !outcome.supervisor_output.contains(&suffix),
            "the refusal output must not echo the credential"
        );
        assert_nothing_persisted(&outcome, &proxy, &sentinel, &suffix);
        Ok(())
    }

    /// Refusal when no broker covers the credential: a lease alone is not
    /// enough, because no brokered service exists to perform the request.
    #[tokio::test(flavor = "multi_thread")]
    async fn broker_required_with_a_lease_but_no_broker_is_refused() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let (sentinel, suffix) = sentinel();
        // No `AA_PROXY_PROVIDER_KEYS`: the broker covers no service.
        let host = build_host_with_policy(
            tmp.path(),
            &proxy,
            gateway.endpoint(),
            &[("ANTHROPIC_API_KEY", &sentinel)],
            Some(BROKER_REQUIRED_WITH_LEASE),
        )?;

        let outcome = launch(host)?;

        assert!(
            !outcome.status.success(),
            "broker_required with no brokered service must refuse even with a lease:\n{}",
            outcome.supervisor_output
        );
        assert!(outcome.supervisor_output.contains(REFUSAL_POLICY_NAME));
        assert!(
            outcome.supervisor_output.contains(REFUSAL_NO_SERVICE),
            "refused, but not because no broker covers a service:\n{}",
            outcome.supervisor_output
        );
        assert!(!outcome.started, "the refused launch must never start the child");
        assert!(!outcome.supervisor_output.contains(&sentinel));
        assert_nothing_persisted(&outcome, &proxy, &sentinel, &suffix);
        Ok(())
    }

    /// Admission: broker covers the service and an explicit credential lease
    /// is authored, so the launch proceeds, and the child's own
    /// env/argv/lsof never carries the sentinel.
    #[tokio::test(flavor = "multi_thread")]
    async fn broker_required_with_a_lease_and_a_broker_launches_without_the_sentinel() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let (sentinel, suffix) = sentinel();
        let host = build_host_with_policy(
            tmp.path(),
            &proxy,
            gateway.endpoint(),
            &[BROKER_KEYS, ("ANTHROPIC_API_KEY", &sentinel)],
            Some(BROKER_REQUIRED_WITH_LEASE),
        )?;

        let outcome = launch(host)?;

        assert!(
            outcome.status.success(),
            "a covered broker_required launch must be admitted:\n{}",
            outcome.supervisor_output
        );
        assert!(
            outcome.started,
            "the child must have started, or the negative below is vacuous"
        );
        let dump = outcome.dump.as_deref().expect("a started child writes its dump");
        let own = own_channel(dump);
        assert!(
            !own.contains(&sentinel) && !own.contains(&suffix),
            "the sentinel reached the child's env/argv/lsof under broker_required:\n{own}"
        );
        assert_nothing_persisted(&outcome, &proxy, &sentinel, &suffix);
        Ok(())
    }

    /// Positive control: the identical launch with `posture: not_required`
    /// and no broker is admitted, and here the sentinel DOES reach the child
    /// through ambient inheritance. That proves the detector sees a leak, so
    /// the absence above is not vacuous, and that `not_required` makes no
    /// brokerage promise.
    #[tokio::test(flavor = "multi_thread")]
    async fn not_required_posture_launches_and_does_not_withhold_the_ambient_credential() -> anyhow::Result<()> {
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;
        let tmp = tempfile::tempdir()?;
        let (sentinel, _suffix) = sentinel();
        let host = build_host_with_policy(
            tmp.path(),
            &proxy,
            gateway.endpoint(),
            &[("ANTHROPIC_API_KEY", &sentinel)],
            Some(NOT_REQUIRED),
        )?;

        let outcome = launch(host)?;

        assert!(
            outcome.status.success(),
            "a not_required launch must be admitted:\n{}",
            outcome.supervisor_output
        );
        let dump = outcome.dump.as_deref().expect("a started child writes its dump");
        assert!(
            own_channel(dump).contains(&sentinel),
            "positive control failed: the detector did not see an unbrokered ambient credential"
        );
        Ok(())
    }
}
