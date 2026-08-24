//! AAASM-5865 — concurrent `aasm run` launches must not cross-attribute
//! (AAASM-5857 mandatory scenarios B, C, H).
//!
//! # What this measures
//!
//! AAASM-5863 gave each governed launch its own dedicated `aa-proxy`,
//! started only after that launch's own registration succeeds, with that
//! registration's real `agent_id` baked into the proxy's config
//! (`aa-proxy/src/config.rs::ProxyConfig::agent_id`). That closes the
//! *plumbing* — an agent id reaches a proxy process. It does not by itself
//! prove *isolation*: two dedicated proxies could still, through a shared
//! path or a race in `launch_state::allocate`, end up pointed at the same
//! audit file, or one launch's traffic could dial through the other's
//! proxy port if allocation were not actually collision-proof under real
//! concurrency (as opposed to `launch_state`'s own sequential unit tests).
//!
//! So this drives two real `aasm run` launches, **genuinely concurrently**
//! (both spawned before either is awaited), each with its own registered
//! agent id, and asserts on the artifacts each one actually produced:
//!
//! * distinct dedicated-proxy addresses (scenario B/C: no shared proxy)
//! * distinct per-launch audit files, each containing at least one record
//!   attributed to its own agent id and **zero** attributed to the other's
//!   (scenario H: no cross-attribution, and non-vacuously — an empty file
//!   would trivially pass a "contains none of the other's records" check
//!   without proving anything, so this also asserts each file is not
//!   empty and is attributed to the right agent)
//! * the gateway's own registration records agree with what each launch's
//!   audit trail says about itself
//!
//! Sequential-launch isolation (the two-launches-in-a-row half of scenario
//! B) is not re-derived here: `launch_state::allocate`'s own
//! `two_allocations_get_distinct_audit_and_ready_paths_but_share_the_ca_dir`
//! unit test already covers path uniqueness across two sequential calls,
//! and every existing `cli_run_claude_governed_launch.rs` scenario is
//! itself one launch that leaves no state for a later one to collide with.
//! What no existing test drives is two launches *whose lifetimes overlap in
//! wall-clock time* — the case where a defect in shared mutable state
//! (a global rather than a per-call temp dir, a proxy that bound the
//! requested port instead of an ephemeral one, ...) would actually surface.

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

#[path = "evidence/mod.rs"]
pub mod evidence;

#[cfg(unix)]
mod concurrent_isolation {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::grpc_gateway_support::{expected_did, GrpcGateway};
    use super::proxy_trust_support::{aasm_binary, TrustedProxy};

    /// One launch's identity. Distinct agent ids are the whole point — a test
    /// that reused one id across both launches could not tell "isolated" from
    /// "coincidentally identical" apart.
    struct Launch {
        agent_id: &'static str,
        team_id: &'static str,
    }

    const LAUNCH_A: Launch = Launch {
        agent_id: "aaasm5865-agent-a",
        team_id: "aaasm5865-team-a",
    };
    const LAUNCH_B: Launch = Launch {
        agent_id: "aaasm5865-agent-b",
        team_id: "aaasm5865-team-b",
    };

    /// Same narrow, enforcing policy `cli_run_claude_governed_launch.rs`
    /// uses — a governed launch under an allow-all policy would not be
    /// exercising anything a bug in policy plumbing could fail.
    fn write_test_policy(dir: &Path) -> std::io::Result<PathBuf> {
        let path = dir.join("policy.yaml");
        std::fs::write(
            &path,
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n\
             \x20 name: aaasm5865-concurrent-isolation\n\
             spec:\n\
             \x20 tools:\n\
             \x20   read_file:\n\
             \x20     allow: true\n\
             \x20   shell:\n\
             \x20     allow: false\n",
        )?;
        Ok(path)
    }

    /// Same reporting stub as `cli_run_claude_governed_launch.rs`: the tool
    /// writes what it observed in its own environment to a file, because that
    /// is the only vantage the launch's own claims can be checked against.
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
  echo "HTTPS_PROXY=$HTTPS_PROXY"
} > "$AA_TEST_ENV_DUMP"
exit 0
"#,
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

    /// One launch's laid-out host: its own project root, stub, policy, dump
    /// file and command, ready to `.spawn()`. Building this ahead of time
    /// (rather than inline in the test body) is what lets both launches be
    /// spawned back to back with no `.output()`/await between them.
    struct Host {
        cmd: std::process::Command,
        dump: PathBuf,
    }

    fn build_host(
        root: &Path,
        launch: &Launch,
        proxy: &TrustedProxy,
        gateway_endpoint: &str,
        state_dir: &Path,
    ) -> anyhow::Result<Host> {
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&project)?;
        let stub = write_stub_binary(root)?;
        let policy = write_test_policy(root)?;
        let dump = root.join("child-env.txt");

        // Same PATH construction as `cli_run_claude_governed_launch.rs`:
        // the stub first (so `which claude` finds it), then
        // `proxy.proxy_bin_dir()` (AAASM-5863 — each launch's own dedicated
        // `aa-proxy` resolves through this, not through `proxy` itself,
        // which here only bootstraps CA trust and gives both launches a
        // shared `AA_DATA_DIR` to register against).
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
            // Distinct `AASM_STATE_DIR` per launch's *own* per-launch-proxy
            // state (`${AASM_STATE_DIR}/runs/...`), rather than the two
            // sharing one — the test needs to find each launch's audit file
            // unambiguously by walking its own `runs/` tree afterward, not
            // by pattern-matching a shared directory two launches wrote
            // into concurrently.
            .env("AASM_STATE_DIR", state_dir)
            .env("AA_CA_DIR", root.join("ca"))
            .env("AASM_CLAUDE_MANAGED_ROOT", root.join("managed"))
            // Shared: both launches register against the same `AA_DATA_DIR`
            // (the standalone proxy's CA-trust record) and the same gateway
            // — isolation is the claim under test, so the inputs that could
            // let isolation happen "by construction" (separate gateways,
            // separate data dirs) are deliberately held constant instead.
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("AA_TEST_ENV_DUMP", &dump)
            .env("AA_GATEWAY_ENDPOINT", gateway_endpoint)
            .args([
                "run",
                "claude",
                "--policy",
                &policy.to_string_lossy(),
                "--agent-id",
                launch.agent_id,
                "--team-id",
                launch.team_id,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        Ok(Host { cmd, dump })
    }

    /// Every `ProxyAuditEntry` line's `agent_id` field, read from whichever
    /// file under `${state_dir}/runs/**/audit.jsonl` this launch's own
    /// dedicated proxy wrote to. There is exactly one such file per launch —
    /// `launch_state::allocate` gives each launch its own directory — found
    /// by walking rather than assumed by name, since the directory name
    /// carries a `tempfile`-generated suffix this test does not control.
    fn read_audit_agent_ids(state_dir: &Path) -> anyhow::Result<Vec<Option<String>>> {
        let runs = state_dir.join("runs");
        let mut audit_files = Vec::new();
        if runs.is_dir() {
            for entry in std::fs::read_dir(&runs)? {
                let entry = entry?;
                let candidate = entry.path().join("audit.jsonl");
                if candidate.is_file() {
                    audit_files.push(candidate);
                }
            }
        }
        anyhow::ensure!(
            audit_files.len() == 1,
            "expected exactly one audit.jsonl under {}, found {}: {audit_files:?} — this test's \
             per-launch-directory assumption (one `runs/*` dir per launch) no longer holds",
            runs.display(),
            audit_files.len(),
        );
        let raw = std::fs::read_to_string(&audit_files[0])?;
        let mut ids = Vec::new();
        for line in raw.lines().filter(|l| !l.trim().is_empty()) {
            let entry: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| anyhow::anyhow!("audit line is not valid JSON: {e}\nline: {line}"))?;
            ids.push(entry.get("agent_id").and_then(|v| v.as_str()).map(str::to_owned));
        }
        Ok(ids)
    }

    /// Two governed launches, spawned so their lifetimes genuinely overlap,
    /// must each get their own dedicated proxy and their own attributed
    /// audit trail — never each other's.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_concurrent_launches_do_not_cross_attribute() -> anyhow::Result<()> {
        // ── shared preconditions ───────────────────────────────────────────
        let proxy = TrustedProxy::start()?;
        let gateway = GrpcGateway::start().await?;

        let tmp = tempfile::tempdir()?;
        let root_a = tmp.path().join("a");
        let root_b = tmp.path().join("b");
        std::fs::create_dir_all(&root_a)?;
        std::fs::create_dir_all(&root_b)?;
        let state_a = root_a.join("state");
        let state_b = root_b.join("state");

        let host_a = build_host(&root_a, &LAUNCH_A, &proxy, gateway.endpoint(), &state_a)?;
        let host_b = build_host(&root_b, &LAUNCH_B, &proxy, gateway.endpoint(), &state_b)?;

        // ── genuinely concurrent: both spawned before either is awaited ────
        let mut child_a = host_a.cmd;
        let mut child_b = host_b.cmd;
        let proc_a = child_a.spawn().expect("aasm run claude (A) should execute");
        let proc_b = child_b.spawn().expect("aasm run claude (B) should execute");

        // Both `spawn_blocking` handles are created before either is
        // awaited, and both are awaited via `try_join!` rather than two
        // sequential `?`s — the earlier sequential form let A's error
        // short-circuit the function before B's `Child` was ever `wait()`ed
        // on, which `clippy::zombie_processes` correctly flagged: a B that
        // failed to `spawn()` at all would leave A's freshly-spawned
        // `aasm run` reaped, but a mid-run panic or error propagating from
        // A would strand B unreaped for the rest of the test process's life.
        let wait_a = tokio::task::spawn_blocking(move || proc_a.wait_with_output());
        let wait_b = tokio::task::spawn_blocking(move || proc_b.wait_with_output());
        let (out_a, out_b) = tokio::try_join!(wait_a, wait_b)?;
        let (out_a, out_b) = (out_a?, out_b?);

        for (label, out) in [("A", &out_a), ("B", &out_b)] {
            assert!(
                out.status.success(),
                "launch {label} should exit 0\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
        }

        // ── each launch's own dedicated proxy is distinct ──────────────────
        let dump_a = std::fs::read_to_string(&host_a.dump)
            .unwrap_or_else(|e| panic!("launch A wrote no environment dump ({e})"));
        let dump_b = std::fs::read_to_string(&host_b.dump)
            .unwrap_or_else(|e| panic!("launch B wrote no environment dump ({e})"));
        let seen_a = parse_dump(&dump_a);
        let seen_b = parse_dump(&dump_b);

        let proxy_a = seen_a.get("HTTPS_PROXY").cloned().unwrap_or_default();
        let proxy_b = seen_b.get("HTTPS_PROXY").cloned().unwrap_or_default();
        assert!(
            proxy_a.starts_with("http://127.0.0.1:") && proxy_b.starts_with("http://127.0.0.1:"),
            "both launches must be routed at a loopback proxy; saw A={proxy_a:?} B={proxy_b:?}",
        );
        assert_ne!(
            proxy_a, proxy_b,
            "two concurrent launches must get two distinct dedicated proxies (AAASM-5863), not \
             share one — sharing would mean one launch's traffic can be attributed to the other",
        );

        // ── each launch's audit trail is attributed to itself, and only itself ──
        let did_a = expected_did(&state_a, LAUNCH_A.agent_id);
        let did_b = expected_did(&state_b, LAUNCH_B.agent_id);
        assert_ne!(did_a, did_b, "two distinct agent ids must derive two distinct DIDs");

        let ids_in_a = read_audit_agent_ids(&state_a)?;
        let ids_in_b = read_audit_agent_ids(&state_b)?;

        // Non-vacuity first: an empty audit file would trivially satisfy "no
        // cross-attribution" below without establishing anything. A governed
        // launch that reaches a real Claude Code adapter always emits at
        // least the settings-file / telemetry side-channel traffic the
        // adapter's own MitM host list covers, so an empty file here is
        // itself a finding, not a quiet pass.
        assert!(
            !ids_in_a.is_empty(),
            "launch A's audit file is empty — either it produced no traffic through its own \
             dedicated proxy, or this test found the wrong file. Either way, the cross-attribution \
             assertion below would be vacuous.",
        );
        assert!(!ids_in_b.is_empty(), "launch B's audit file is empty (see A's message)");

        assert!(
            ids_in_a.iter().any(|id| id.as_deref() == Some(did_a.as_str())),
            "launch A's own audit file must contain at least one record attributed to A's own \
             identity ({did_a}); saw: {ids_in_a:?}",
        );
        assert!(
            ids_in_b.iter().any(|id| id.as_deref() == Some(did_b.as_str())),
            "launch B's own audit file must contain at least one record attributed to B's own \
             identity ({did_b}); saw: {ids_in_b:?}",
        );

        assert!(
            !ids_in_a.iter().any(|id| id.as_deref() == Some(did_b.as_str())),
            "launch A's audit file must contain zero records attributed to B ({did_b}); saw: \
             {ids_in_a:?} — cross-attribution between two concurrent launches is the exact defect \
             AAASM-5865 exists to catch",
        );
        assert!(
            !ids_in_b.iter().any(|id| id.as_deref() == Some(did_a.as_str())),
            "launch B's audit file must contain zero records attributed to A ({did_a}); saw: \
             {ids_in_b:?}",
        );

        // Scenario H, directly: no `<unknown>` (i.e. `None`/absent) agent id
        // where attribution is expected — every record either launch's own
        // dedicated proxy wrote carries a real identity, since that proxy's
        // `AA_AGENT_ID` was always set (AAASM-5863 starts the dedicated
        // proxy only after registration succeeds).
        assert!(
            ids_in_a.iter().all(|id| id.is_some()),
            "every record in A's audit file must carry a real agent id, never `None`; saw: \
             {ids_in_a:?}",
        );
        assert!(
            ids_in_b.iter().all(|id| id.is_some()),
            "every record in B's audit file must carry a real agent id, never `None`; saw: \
             {ids_in_b:?}",
        );

        // Non-vacuity for the negative checks above comes from the positive
        // checks together with `assert_ne!(did_a, did_b)` earlier: each file
        // is shown to contain its *own* identity and distinct identities are
        // shown to exist, so "contains none of the other's" is excluding a
        // real, known-present value — not vacuously true over two empty or
        // identical sets. (An earlier version of this test carried a
        // redundant assertion here that recomputed the same two predicates
        // already checked above and could never fail; removed rather than
        // left as false rigor — see AAASM-5865 PR review.)

        // ── the gateway agrees: two registrations, two distinct identities ──
        let registrations = gateway.session().registrations();
        assert_eq!(
            registrations.len(),
            2,
            "both launches must have registered independently"
        );
        let registered_ids: std::collections::BTreeSet<String> = registrations
            .iter()
            .filter_map(|r| r.agent_id.as_ref().map(|id| id.agent_id.clone()))
            .collect();
        assert_eq!(
            registered_ids,
            std::collections::BTreeSet::from([did_a.clone(), did_b.clone()]),
            "the gateway must have seen exactly the two distinct identities each launch used",
        );
        assert_eq!(
            gateway
                .session()
                .deregistrations()
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([did_a, did_b]),
            "both sessions must have been closed under the identity that opened them",
        );

        Ok(())
    }
}

#[cfg(not(unix))]
#[test]
fn concurrent_isolation_is_not_measured_on_this_host() {
    let reason = format!(
        "the concurrent-isolation evidence needs a POSIX shell stand-in for the `claude` binary; \
         this host is {}. AAASM-5865 is NOT evidenced here.",
        std::env::consts::OS
    );
    println!("SKIP [AAASM-5865]: {reason}");
    conformance_support::outcome::record(
        "aaasm-5865-concurrent-isolation",
        conformance_support::Measurement::UnsupportedPlatform,
        &reason,
    );
}
