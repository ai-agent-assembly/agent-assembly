//! AAASM-5930 — J63 (AAASM-5853) closing evidence: a deterministic,
//! non-LLM-dependent trigger for a real governed `aasm run claude` launch
//! reaching a real **allow** and a real **deny** outcome, adjudicated by a
//! real gateway `PolicyService`, through the real per-launch proxy's MCP
//! enforcement bridge (`aa_proxy::mcp_enforce`).
//!
//! # Why this file exists, and what it does not duplicate
//!
//! `cli_run_claude_governed_launch.rs` (AAASM-1112) already proves real
//! binary → real `aasm run` → real dedicated per-launch proxy → real gateway
//! registration → real credential redaction. What it does not prove: its
//! `GrpcGateway` test double carries no `PolicyService`, so no policy-gated
//! tool call in that file ever reaches a real allow/deny adjudication — the
//! policy it supplies is a precondition (AAASM-5349 requires *some* resolved
//! policy to launch at all), not something a tool call is actually checked
//! against.
//!
//! `e2e_mcp_interceptor.rs`'s `st_q_1`/`st_q_2` independently prove the
//! missing half — real `ProxyServer` + real `PolicyServiceImpl` + MCP
//! `tools/call` interception, correct allow/deny JSON-RPC behaviour, correct
//! audit evidence — driven by a synthetic JSON-RPC client, not a real
//! dev-tool binary.
//!
//! This file connects the two: the real `claude` binary's own MCP traffic,
//! launched through the real `aasm run` chain, hits the same real
//! `PolicyService` adjudication `st_q_1`/`st_q_2` already proved works.
//!
//! # The deterministic trigger
//!
//! A live multi-turn conversation with a real model cannot be relied on to
//! deterministically attempt a specific tool call (AAASM-5853's own stated
//! blocker). [`conformance_mcp_support::ConformanceUpstream`] mocks only the
//! model's response — scripted to request one allowed and one denied MCP
//! tool call in sequence — while every other hop (binary, launch, proxy,
//! gateway, policy, real MCP tool execution with an observable side effect)
//! is real. See that module's doc for the wire-protocol detail (in
//! particular: MCP tool names must be the `mcp__<server>__<tool>` qualified
//! form — verified empirically against the real `claude` 2.1.238 binary).
//!
//! # Fidelity label
//!
//! Real-binary-gated (`spike_support::require_claude`) and macOS-gated
//! (`spike_support::require_macos` — the CA-trust mechanism this scenario
//! also exercises is currently only wired for macOS System Keychain trust).
//! Not part of mandatory PR CI for the same reason `cli_run_claude_governed_
//! launch.rs`'s own real-binary scenario isn't: no real `claude` binary on
//! hosted CI runners. This is `RELEASE_QA_DETERMINISTIC` evidence, run by a
//! release-QA pass on a machine with the real binary installed — not
//! `CI_AUTOMATED` coverage, and it must not be represented as the latter.

#[path = "evidence/mod.rs"]
pub mod evidence;

#[allow(unused_imports)]
mod common;

#[allow(dead_code, unused_imports)]
mod spike_support;

#[allow(dead_code, unused_imports)]
mod conformance_support;

#[allow(unused_imports)]
mod proxy_trust_support;

#[allow(unused_imports)]
mod grpc_gateway_support;

#[allow(unused_imports)]
mod conformance_gateway_support;

#[allow(unused_imports)]
mod conformance_mcp_support;

#[cfg(unix)]
mod deterministic_conformance {
    use std::os::unix::process::CommandExt as _;
    use std::path::Path;
    use std::time::Duration;

    use aa_core::integration::{IntegrationRequest, ProtectionProfile, ReceiptStore, SettingsScope};
    use aa_core::DevToolKind;
    use aa_devtool_claude_code::{ClaudeCodeAdapter, ClaudeCodeIntegration, ClaudeCodePaths};
    use aa_proxy::tls::CaStore;
    use aa_runtime::devint::adapters::claude_code_registration;
    use aa_runtime::devint::{EngineLifecycle, IntegrationLifecycle};

    use aa_gateway::registry::convert::proto_agent_id_to_key;
    use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;

    use super::conformance_mcp_support::{
        enable_mcp_server, ensure_mcp_server_enabled, sentinel_path, write_mcp_config, ConformanceUpstream, TASK_MARKER,
    };
    use super::grpc_gateway_support::expected_did;
    use super::proxy_trust_support::{aasm_binary, TrustedProxy};
    use super::spike_support::proxy_harness::install_crypto_provider;
    use super::spike_support::RealHomeGuard;

    const AGENT_ID: &str = "aaasm5930-agent";
    // Must be a real, publicly resolvable hostname, not a fabricated one:
    // Claude Code's MCP client resolves the server's hostname itself before
    // the connection ever reaches the proxy's CONNECT handling — a fake
    // internal-looking domain fails DNS resolution client-side and the
    // server is silently never dialled at all (confirmed empirically: zero
    // requests of any kind arrived at a fabricated hostname, despite the
    // identical config working over plain loopback HTTP with no DNS
    // involved). `example.com` and its subdomains are reserved for exactly
    // this by RFC 2606 and always resolve; `e2e_mcp_interceptor.rs` already
    // uses the same domain for the same reason.
    const MCP_HOST: &str = "mcp.example.com";
    const MCP_SERVER_NAME: &str = "conformance";
    const ALLOW_TOOL: &str = "allow_test";
    const DENY_TOOL: &str = "deny_test";

    /// The policy this scenario's claim depends on: `allow_test` allowed,
    /// `deny_test` denied, both as real MCP tool-call rules the gateway's
    /// `PolicyService` adjudicates — not the adapter-rendered
    /// `permissions.allow/deny` Claude Code enforces on itself for its own
    /// built-in tools (a different, adapter-local mechanism this scenario
    /// does not exercise). `mcp_tools` here mirrors the schema
    /// `e2e_mcp_interceptor.rs`'s own `mcp_deny_read_file.yaml`/`allow_all.yaml`
    /// fixtures use for the same gateway-side MCP tool_name match.
    fn write_test_policy(dir: &Path) -> std::io::Result<std::path::PathBuf> {
        let path = dir.join("policy.yaml");
        std::fs::write(
            &path,
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n\
             \x20 name: aaasm5930-conformance\n\
             \x20 version: \"0.1.0\"\n\
             spec:\n\
             \x20 tools:\n\
             \x20   allow_test:\n\
             \x20     allow: true\n\
             \x20   deny_test:\n\
             \x20     allow: false\n",
        )?;
        Ok(path)
    }

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

    fn path_with_both(first: &Path, second: &Path) -> anyhow::Result<std::ffi::OsString> {
        let existing = std::env::var_os("PATH").unwrap_or_default();
        let mut parts = vec![first.to_path_buf(), second.to_path_buf()];
        parts.extend(std::env::split_paths(&existing));
        Ok(std::env::join_paths(parts)?)
    }

    fn tail(output: &str) -> String {
        output
            .lines()
            .rev()
            .take(40)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    }

    const SCENARIO: &str = "aaasm5930_deterministic_allow_and_deny";

    /// Find every `audit.jsonl` this launch's dedicated proxy could have
    /// written under `${AASM_STATE_DIR}/runs/*/audit.jsonl`
    /// (`aa-cli/src/commands/proxy/launch_state.rs::allocate`). A plain
    /// directory walk rather than the `glob` crate: one extra dependency for
    /// a two-level, non-recursive listing this test only needs once.
    fn glob_audit_jsonl(state_dir: &Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
        let runs = state_dir.join("runs");
        if !runs.is_dir() {
            return Ok(Vec::new());
        }
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&runs)? {
            let candidate = entry?.path().join("audit.jsonl");
            if candidate.is_file() {
                found.push(candidate);
            }
        }
        Ok(found)
    }

    /// Parse a proxy audit JSONL file into its entries, in file order.
    fn read_audit_entries(path: &Path) -> anyhow::Result<Vec<aa_proxy::audit_jsonl::ProxyAuditEntry>> {
        let raw = std::fs::read_to_string(path)?;
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).map_err(|e| anyhow::anyhow!("parsing audit.jsonl line: {e}\nline: {l}")))
            .collect()
    }

    /// The scenario AAASM-5930 exists for: a real `claude` binary, launched
    /// through a real `aasm run`, reaches a real allow and a real deny
    /// outcome for two MCP tool calls — both adjudicated by a real gateway
    /// `PolicyService`, both crossing the real per-launch proxy's MCP
    /// enforcement bridge.
    #[tokio::test(flavor = "multi_thread")]
    async fn real_binary_reaches_a_real_allow_and_a_real_deny_via_gateway_policy() -> anyhow::Result<()> {
        let Some(claude) = super::spike_support::require_claude(SCENARIO) else {
            return Ok(());
        };
        if !super::spike_support::require_macos(SCENARIO) {
            return Ok(());
        }
        install_crypto_provider();
        let real_home = RealHomeGuard::capture();

        let tmp = tempfile::Builder::new().prefix("aaasm5930-debug-").tempdir_in("/tmp")?;
        let root = tmp.path();
        let home = root.join("home");
        let project = root.join("project");
        let state = root.join("state");
        let ca_dir = root.join("ca");
        let sentinel_dir = root.join("sentinels");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&project)?;
        std::fs::create_dir_all(&ca_dir)?;
        std::fs::create_dir_all(&sentinel_dir)?;

        // A headless launch cannot click through Claude Code's interactive
        // per-project trust dialog, and without it Claude Code silently
        // ignores every `permissions`/MCP-server rule in the project's own
        // config and never attempts a tool call at all — confirmed
        // empirically, and independent of `--dangerously-skip-permissions`
        // (that flag only bypasses Claude Code's own per-tool-call
        // confirmation, not this project-level trust gate). Pre-seed the
        // trust flag exactly the way Claude Code's own refusal message says
        // to: `projects[<abs path>].hasTrustDialogAccepted` in the config
        // file at `$CLAUDE_CONFIG_DIR/.claude.json`. Canonicalized because
        // macOS's `/var/folders/...` is a symlink to `/private/var/folders/
        // ...` and Claude Code keys this map on the resolved path.
        let project_canonical = project.canonicalize().unwrap_or_else(|_| project.clone());
        std::fs::write(
            home.join(".claude").join(".claude.json"),
            serde_json::json!({
                "projects": {
                    project_canonical.to_string_lossy(): {"hasTrustDialogAccepted": true}
                }
            })
            .to_string(),
        )?;

        // The real `.mcp.json` + `.claude/settings.json` Claude Code reads at
        // launch — written directly, since the adapter's own managed keys
        // never include `mcpServers` (see `write_mcp_config`'s doc).
        write_mcp_config(&project, MCP_SERVER_NAME, MCP_HOST)?;

        let policy_path = write_test_policy(root)?;

        // ── the combined gateway: registration + real policy adjudication ──
        let (gateway_endpoint, registry) = super::conformance_gateway_support::start_full_gateway(&policy_path).await?;

        // ── the deterministic upstream: model API + real MCP tool server ──
        let ca = CaStore::load_or_create(&ca_dir)
            .await
            .map_err(|e| anyhow::anyhow!("certificate authority: {e}"))?;
        let upstream =
            ConformanceUpstream::start(&ca, MCP_HOST, MCP_SERVER_NAME, ALLOW_TOOL, DENY_TOOL, &sentinel_dir).await?;
        drop(ca);

        // ── the dedicated per-launch proxy `aasm run` will start ──────────
        // This standalone proxy is only the launch's registration/CA-trust
        // precondition (AAASM-5323) — it does not carry the launched tool's
        // own traffic, so it needs no gateway/policy wiring of its own; see
        // `cli_run_claude_governed_launch.rs`'s identical note.
        let proxy = TrustedProxy::start_intercepting(&ca_dir, upstream.addr, &state, &[])?;
        let proxy_url = proxy.expected_proxy_url();

        // ── the install whose launch environment is under test ────────────
        let integrations = state.join("integrations");
        let paths = ClaudeCodePaths::default()
            .with_home(&home)
            .with_config_dir(home.join(".claude"))
            .with_project(&project)
            .with_state(&integrations)
            .with_ca_source(ca_dir.join("ca-cert.pem"));
        let integration = std::sync::Arc::new(
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
        // Must run after `apply` — see `enable_mcp_server`'s doc for why.
        enable_mcp_server(&home.join(".claude"), MCP_SERVER_NAME)?;

        // ── the launch ──────────────────────────────────────────────────
        let prompt = format!("{TASK_MARKER}: call allow_test then deny_test");
        let stdout_path = root.join("aasm-stdout.txt");
        let stderr_path = root.join("aasm-stderr.txt");
        let mut cmd = std::process::Command::new(aasm_binary());
        cmd.current_dir(&project)
            .env("HOME", &home)
            .env("PATH", path_with_both(claude.parent().expect("claude has a parent"), proxy.proxy_bin_dir())?)
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("AASM_STATE_DIR", &state)
            .env("AA_CA_DIR", &ca_dir)
            .env("AASM_CLAUDE_MANAGED_ROOT", root.join("managed"))
            .env("AA_DATA_DIR", proxy.data_dir())
            .env("AA_GATEWAY_ENDPOINT", &gateway_endpoint)
            // AAASM-5863: `aasm run` resolves and spawns its OWN dedicated
            // `aa-proxy` for this one launch (via `ProxyGuard::spawn`, on an
            // ephemeral port it picks) rather than routing through the
            // standalone `proxy` this file starts above — that one exists
            // only as the launch's registration/CA-trust precondition (see
            // `cli_run_claude_governed_launch.rs`'s identical note). The
            // dedicated proxy's own `gateway_endpoint` is sourced from
            // `ProxyGuardOptions` (built from `AA_GATEWAY_ENDPOINT` via
            // `run_registration::gateway_endpoint()`), and `build_command`
            // sets `AA_PROXY_GATEWAY_ENDPOINT` on the child itself — so no
            // separate env var is needed here.
            .env("AA_TEST_PROXY_UPSTREAM", upstream.addr.to_string())
            .env("AA_PROXY_LLM_ONLY", "false")
            .env("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY", "1")
            .env("ANTHROPIC_AUTH_TOKEN", "AAASM5930-DUMMY-NOT-A-REAL-TOKEN")
            .env_remove("NODE_EXTRA_CA_CERTS")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("ANTHROPIC_BASE_URL")
            .env_remove("HTTPS_PROXY")
            .env_remove("HTTP_PROXY")
            .env_remove("https_proxy")
            .env_remove("http_proxy")
            .stdout(std::fs::File::create(&stdout_path)?)
            .stderr(std::fs::File::create(&stderr_path)?)
            .process_group(0)
            .args([
                "run",
                "claude",
                "--policy",
                &policy_path.to_string_lossy(),
                "--agent-id",
                AGENT_ID,
                "--",
                "-p",
                &prompt,
                "--dangerously-skip-permissions",
            ]);
        let mut child = cmd.spawn().expect("aasm run claude should execute");
        let pgid = child.id() as i32;
        let _reaper = GroupReaper(pgid);

        // `aasm run` itself re-applies the adapter's managed settings keys as
        // part of its own launch sequence (reading the real `--policy` this
        // time, which is why `permissions.allow`/`deny` end up correct) —
        // clobbering this scenario's `enable_mcp_server` patch a second time,
        // on a schedule this harness doesn't control. A fixed handful of
        // early re-asserts can still lose that race (confirmed empirically —
        // discovery keeps working either way since Claude Code reads
        // `.mcp.json` directly for that, but `tools/call` is gated on this
        // key and silently never gets attempted if it's clobbered back to
        // `[]` after the window closes). `ensure_mcp_server_enabled` is
        // idempotent — it skips the write whenever the file already holds
        // the desired value — so running it for the launch's whole duration
        // closes the race without triggering the sustained-rewrite-loop
        // problem a naive unconditional loop would cause (Claude Code
        // live-file-watches `settings.json` and reloads its permission state
        // on every write, confirmed empirically via
        // `[DEBUG] Replacing all allow rules for destination 'userSettings'`
        // in `~/.claude/debug/<session>.txt`).
        let config_dir_for_patch = home.join(".claude");
        let patch_handle = tokio::spawn(async move {
            loop {
                let _ = ensure_mcp_server_enabled(&config_dir_for_patch, MCP_SERVER_NAME);
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        });

        // ── wait for evidence, then stop the session ───────────────────────
        // `-p` is a single-turn print-and-exit invocation, so the child exits
        // on its own once the scripted conversation reaches its final text
        // turn — no signal needed on the happy path. The deadline below is
        // the fallback for a launch that never converges (e.g. the MCP
        // handshake failed silently), not the normal exit path.
        let started = std::time::Instant::now();
        // `allow_test` is a known gap (see the AAASM-5930 finding in
        // `conformance_mcp_support::respond_mcp`'s `is_mcp_keep_alive`
        // comment): its tools/call never opens a fresh connection, so the
        // client exhausts its own 60s per-call timeout before giving up.
        // `deny_test` is dispatched only after that timeout, so the deadline
        // must outlast it plus deny's own (near-instant) round trip and the
        // conversation's final turn.
        let deadline = Duration::from_secs(90);
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if started.elapsed() > deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if child.try_wait()?.is_none() {
            signal_group(pgid, libc::SIGTERM);
            let grace = std::time::Instant::now();
            while grace.elapsed() < Duration::from_secs(15) {
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
        patch_handle.abort();
        let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        println!(
            "MEASURED governed launch: launcher_exit={:?} elapsed={:?}",
            launcher_exit.code(),
            started.elapsed(),
        );
        println!(
            "MEASURED tool_calls actually reaching the MCP server: {:?}",
            upstream.tool_call_names()
        );
        // Every request this mock actually saw, in arrival order — the
        // record that distinguishes "the allow leg's tools/call never left
        // the client" from "it reached this mock and was mishandled" for
        // whoever triages a future failure here.
        println!(
            "MEASURED upstream requests (host, path, len): {:?}",
            upstream
                .requests()
                .iter()
                .map(|r| (r.host.clone(), r.path.clone(), r.body.len()))
                .collect::<Vec<_>>()
        );

        let allow_sentinel = sentinel_path(&sentinel_dir, ALLOW_TOOL);
        let deny_sentinel = sentinel_path(&sentinel_dir, DENY_TOOL);

        // ── deny-leg audit-attribution evidence ─────────────────────────────
        //
        // Read *before* the allow-leg bail below, deliberately: the deny
        // leg's evidence (proxy refused the call before dialing upstream) is
        // independent of whether the allow leg's connection-reuse gap
        // (AAASM-5930) happens to be open on this run. Gating this behind
        // the allow-leg bail would mean a real deny-side regression could
        // hide for as long as the allow gap stays open — the two claims
        // must be checked independently of each other's outcome.
        //
        // This proves the proxy's own persisted audit record correctly names
        // *why* the deny leg's sentinel is absent — the same evidence chain a
        // real operator would read after the fact, not just what this test's
        // own mock observed. Read from
        // `${AASM_STATE_DIR}/runs/<label>-<suffix>/audit.jsonl`
        // (`aa-cli/src/commands/proxy/launch_state.rs::allocate`) rather than
        // a fixed path, since the suffix is `tempfile`'s own collision-proof
        // generation; this launch is the only thing that wrote under `state`
        // in this test, so exactly one match is expected.
        let audit_paths: Vec<_> = glob_audit_jsonl(&state)?;
        assert_eq!(
            audit_paths.len(),
            1,
            "expected exactly one per-launch audit.jsonl under {}: {audit_paths:?}",
            state.display()
        );
        let audit_entries = read_audit_entries(&audit_paths[0])?;
        assert!(
            !audit_entries.is_empty(),
            "the proxy wrote an audit.jsonl but it recorded nothing — the deny leg must have \
             produced at least one entry"
        );

        // The deny leg's refusal, as the persisted record — not the proxy's
        // in-process log line, which a future refactor could change without
        // this test noticing. `RefusalRule::McpToolCall` is the same
        // discriminant `aa-proxy/src/proxy/mod.rs::emit_rule_refusal` writes
        // for exactly this branch (a gateway-denied `tools/call`, or one that
        // could not be evaluated and was refused fail-closed).
        let deny_refusals: Vec<_> = audit_entries
            .iter()
            .filter(|e| e.host == MCP_HOST && e.refusal_rule == Some(aa_proxy::audit_jsonl::RefusalRule::McpToolCall))
            .collect();
        assert!(
            !deny_refusals.is_empty(),
            "no audit entry attributes a refusal to RefusalRule::McpToolCall on {MCP_HOST} — the \
             deny leg's sentinel-absence proves nothing reached the MCP server, but without this \
             the persisted evidence trail doesn't say *why*: {audit_entries:?}"
        );
        for entry in &deny_refusals {
            assert_eq!(
                entry.decision,
                aa_proxy::audit_jsonl::ProxyAuditDecision::Blocked,
                "an McpToolCall-refused entry must carry decision=Blocked, not a decision that \
                 implies the bytes went anywhere: {entry:?}"
            );
            assert_eq!(
                entry.agent_id.as_deref(),
                Some(AGENT_ID),
                "the audit record must attribute the refusal to the agent identity that made the \
                 call, not leave it unattributed: {entry:?}"
            );
        }
        // The negative half of the same claim: exactly one refusal, not one
        // per leg. `path` is the bare `/mcp` HTTP target for every MCP call
        // regardless of which tool (the tool name lives in the JSON-RPC
        // body, which a rule-refused entry never persists — refused before
        // any body-level inspection would help), so "one call refused" is
        // the strongest claim this record shape can make; the allow leg's
        // own evidence is the sentinel + upstream-request assertions above,
        // not this file.
        assert_eq!(
            deny_refusals.len(),
            1,
            "expected exactly one McpToolCall refusal (the deny leg) on {MCP_HOST}, found {}: \
             {audit_entries:?}",
            deny_refusals.len()
        );
        assert!(
            !deny_sentinel.exists(),
            "the denied MCP tool call must NEVER reach the real MCP server — its sentinel existing means \
             the gateway policy adjudication (or the proxy's enforcement of it) failed to block a call it \
             was configured to deny"
        );

        // ── allow-leg evidence (AAASM-5930 gap tracked separately) ─────────
        if !allow_sentinel.exists() {
            println!("NOT MEASURED aasm stdout tail: {}", tail(&stdout));
            println!("NOT MEASURED aasm stderr tail: {}", tail(&stderr));
            real_home.assert_unchanged(SCENARIO);
            anyhow::bail!(
                "NOT MEASURED [{SCENARIO}]: the allowed tool call never reached the MCP server \
                 (sentinel absent) — this is a gap in the evidence, not a pass. \
                 stdout tail:\n{}\nstderr tail:\n{}",
                tail(&stdout),
                tail(&stderr),
            );
        }
        assert!(
            allow_sentinel.exists(),
            "the allowed MCP tool call must actually reach the real MCP server and write its sentinel"
        );

        // The registered identity, as the same durable IdentityStore `aasm run`
        // itself used derives it — not asserted by string-matching a log line,
        // by looking the *actual* record up in the *real* registry under the
        // exact key this did:key + team would file under. A record existing
        // here is a real, gateway-adjudicated registration under a genuinely
        // derived identity — not the historical `agent_id="<unknown>"` gap
        // this Story's platform notes warn about, which would derive a
        // completely different (or no) key.
        let did = expected_did(&state, AGENT_ID);
        let key = proto_agent_id_to_key(&ProtoAgentId {
            org_id: String::new(),
            team_id: String::new(),
            agent_id: did.clone(),
        });
        let record = registry.get(&key);
        assert!(
            record.is_some(),
            "no registry record found for the derived did `{did}` — the session either never \
             registered or registered under a different identity than the one it derived"
        );

        real_home.assert_unchanged(SCENARIO);
        Ok(())
    }
}

/// A skip must be legible in the output; a test binary that silently
/// contains no tests is indistinguishable from a passing one.
#[cfg(not(unix))]
#[test]
fn deterministic_conformance_is_not_measured_on_this_host() {
    println!("SKIP [aaasm5930_deterministic_allow_and_deny]: unix-only scenario, this host is not unix");
}
