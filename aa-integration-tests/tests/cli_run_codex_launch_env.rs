//! AAASM-5920 — the CA-trust launch environment AAASM-5856/AAASM-5917 install
//! is sufficient for a governed `aasm run codex` launch to have its request
//! adjudicated by the proxy.
//!
//! # What this measures, and what it does not
//!
//! Same fixture pair `cli_run_claude_governed_launch.rs`'s
//! `real_binary_governed_launch` module uses — `TrustedProxy::start_intercepting`
//! (the shipped `ProxyServer` in a process, upstream dial redirected) plus
//! `TlsCapturingUpstream` (a loopback provider whose leaf is signed by the same
//! CA the proxy MitMs with) — driving the real `aasm` binary. What stands in
//! for `claude` there is `examples/codex_tls_client` here: a `codex`
//! stand-in that re-implements Codex's own documented CA-resolution
//! precedence and sends one request, rather than the shipped `codex` binary.
//! `codex_tls_client`'s own module doc states that limitation; this file does
//! not claim to have exercised the real binary.
//!
//! # Why the install goes through `EngineLifecycle`, not just the launch
//!
//! Driving `CodexIntegration::plan`/`apply` through the production
//! `codex_registration` wiring (AAASM-5918's export) is what makes this an
//! **install** test rather than a store test: the launch environment the
//! child reads has to be the one AAASM-5917's plan actually produced, not one
//! this test wrote directly with `LaunchEnvStore::set`.
//!
//! # The negative control
//!
//! Same fixture, one variable moved: after `apply`, this file unsets
//! `CODEX_CA_CERTIFICATE` from the user-scope launch-environment store and
//! reruns the launch. Three independent facts distinguish "did not launch"
//! from "launched and correctly refused to trust the proxy": the outcome file
//! exists and names `system roots` as the winning branch (proves the stub
//! ran), it reports a certificate-verification failure (proves it attempted
//! the connection and rejected the proxy's leaf), and the upstream recorded
//! zero requests (proves nothing reached the provider). `count == 0` alone
//! would be indistinguishable from "never launched" — that is exactly the
//! false-pass shape a prior audit finding warned about
//! (`feedback_absence_of_failure_is_not_presence_of_coverage`).

use std::path::Path;
use std::time::Duration;

use aa_core::integration::{IntegrationRequest, ProtectionProfile, ReceiptStore, SettingsScope};
use aa_core::DevToolKind;
use aa_devtool_codex::{CodexAdapter, CodexIntegration, CodexPaths};
use aa_devtool_contract::LaunchEnvStore;
use aa_proxy::tls::CaStore;
use aa_runtime::devint::adapters::codex_registration;
use aa_runtime::devint::{EngineLifecycle, IntegrationLifecycle};

#[path = "evidence/mod.rs"]
pub mod evidence;

#[allow(dead_code, unused_imports)]
mod spike_support;

#[allow(unused_imports)]
mod proxy_trust_support;

#[allow(unused_imports)]
mod grpc_gateway_support;

use grpc_gateway_support::GrpcGateway;
use proxy_trust_support::{aasm_binary, codex_tls_client_binary, TrustedProxy};
use spike_support::proxy_harness::install_crypto_provider;
use spike_support::{assert_recorded_and_secret_absent, TlsCapturingUpstream, SYNTHETIC_SECRET};

/// The host this scenario's mock upstream answers for — Codex's real API
/// host, matching `real_binary_governed_launch`'s use of the real
/// `api.anthropic.com`. A synthetic hostname was tried first and the gateway's
/// `policy.network` stage (AAASM-5851, authoritative once a gateway is
/// configured) refused the CONNECT tunnel for it: with no explicit network
/// rule in the test policy, only a recognised host is permitted, and the
/// client never needs DNS to resolve it — the CONNECT tunnel goes to the
/// proxy, which redirects its own upstream dial via `AA_TEST_PROXY_UPSTREAM`.
const TARGET_HOST: &str = "api.openai.com";

/// How long to wait for the stand-in's one request before concluding nothing
/// is coming.
const REQUEST_PATIENCE: Duration = Duration::from_secs(20);

struct Fixture {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    home: std::path::PathBuf,
    state: std::path::PathBuf,
    ca_dir: std::path::PathBuf,
    outcome_path: std::path::PathBuf,
    codex_paths: CodexPaths,
}

impl Fixture {
    fn create() -> anyhow::Result<Self> {
        let tmp = tempfile::tempdir()?;
        let root = tmp.path().to_path_buf();
        let home = root.join("home");
        let state = root.join("state");
        let ca_dir = root.join("ca");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&ca_dir)?;
        let outcome_path = root.join("outcome.txt");

        let integrations = state.join("integrations");
        let codex_paths = CodexPaths::default()
            .with_home(&home)
            .with_state(&integrations)
            .with_ca_source(ca_dir.join("ca-cert.pem"));

        Ok(Self {
            _tmp: tmp,
            root,
            home,
            state,
            ca_dir,
            outcome_path,
            codex_paths,
        })
    }

    fn integrations_state(&self) -> std::path::PathBuf {
        self.state.join("integrations")
    }
}

/// Parse `codex_tls_client`'s `key=value` outcome dump.
fn parse_outcome(raw: &str) -> std::collections::BTreeMap<String, String> {
    raw.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn read_outcome(path: &Path) -> Option<std::collections::BTreeMap<String, String>> {
    std::fs::read_to_string(path).ok().map(|raw| parse_outcome(&raw))
}

/// Install a Codex integration through the production wiring, over `fixture`'s
/// roots and routed through `proxy_url`.
async fn install(fixture: &Fixture, proxy_url: &str) -> anyhow::Result<()> {
    let integration = std::sync::Arc::new(
        CodexIntegration::with_paths(fixture.codex_paths.clone())
            .with_adapter(CodexAdapter::default().with_home_dir(fixture.home.clone()))
            .through_proxy(proxy_url),
    );
    let service = EngineLifecycle::new(
        vec![codex_registration(integration)],
        ReceiptStore::at(fixture.integrations_state().join("store")),
    );
    let tool = DevToolKind::Codex;
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
    Ok(())
}

/// Run the `codex` stand-in via `aasm run codex` and wait for it to finish (it
/// exits on its own after one request — unlike an interactive tool, there is
/// no session to close).
///
/// AAASM-5863: `aasm run` does not reuse `proxy` (the standalone
/// `start_intercepting` process) for traffic — it spawns its **own** dedicated
/// `aa-proxy`. `proxy.proxy_bin_dir()` on `PATH` is what makes that dedicated
/// process resolve to the same built binary; `AA_TEST_PROXY_UPSTREAM` /
/// `AA_PROXY_LLM_ONLY` / `AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY` on this command
/// are what make it redirect to the same mock upstream and skip its
/// self-signed leaf's verification, mirroring
/// `cli_run_claude_governed_launch.rs`'s `real_binary_governed_launch` module.
fn run_codex_stand_in(
    fixture: &Fixture,
    gateway: &GrpcGateway,
    proxy: &TrustedProxy,
    upstream_addr: std::net::SocketAddr,
) -> anyhow::Result<i32> {
    let stub_dir = fixture.root.join("bin");
    std::fs::create_dir_all(&stub_dir)?;
    let stub = stub_dir.join("codex");
    std::fs::copy(codex_tls_client_binary(), &stub)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))?;
    }

    let path_var = {
        let mut parts = vec![stub_dir.clone(), proxy.proxy_bin_dir().to_path_buf()];
        parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
        std::env::join_paths(parts)?
    };

    let real_policy = fixture.root.join("policy.yaml");
    std::fs::write(
        &real_policy,
        "apiVersion: agent-assembly/v1\n\
         kind: Policy\n\
         metadata:\n\
         \x20 name: aaasm5920-codex-ca-trust\n\
         spec:\n\
         \x20 tools:\n\
         \x20   read_file:\n\
         \x20     allow: true\n\
         \x20   shell:\n\
         \x20     allow: false\n",
    )?;

    let stdout_path = fixture.root.join("aasm-stdout.txt");
    let stderr_path = fixture.root.join("aasm-stderr.txt");
    let mut cmd = std::process::Command::new(aasm_binary());
    cmd.current_dir(&fixture.root)
        .env("HOME", &fixture.home)
        .env("PATH", &path_var)
        .env("AASM_STATE_DIR", &fixture.state)
        .env("AA_CA_DIR", &fixture.ca_dir)
        .env("AA_DATA_DIR", proxy.data_dir())
        .env("AA_GATEWAY_ENDPOINT", gateway.endpoint())
        .env("AA_TEST_PROXY_UPSTREAM", upstream_addr.to_string())
        .env("AA_PROXY_LLM_ONLY", "false")
        .env("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY", "1")
        // AAASM-5851: once a gateway endpoint is configured, the dedicated
        // proxy's CONNECT-time egress check is authoritative via the
        // gateway's `policy.network` PolicyService RPC and fails closed when
        // that RPC is unreachable. `GrpcGateway` here registers only
        // `AgentLifecycleService` (identity registration) — the same fixture
        // `real_binary_governed_launch` in cli_run_claude_governed_launch.rs
        // uses, which never actually exercises this path because it is
        // gated behind a real installed `claude` binary and returns early on
        // a CI runner without one. This test's subject is the CA-trust
        // launch environment, not gateway network-policy enforcement, so
        // failing open here is the narrow, documented fixture gap — not a
        // silent weakening of what the test asserts.
        .env("AA_PROXY_NETWORK_FAIL_OPEN", "1")
        .env("AASM5920_OUTCOME_FILE", &fixture.outcome_path)
        .env("AASM5920_TARGET_HOST", TARGET_HOST)
        // A developer's ambient value must not supply the thing under test —
        // the launch environment the install materialised is what must carry
        // these, not whatever the harness process happens to have.
        .env_remove("CODEX_CA_CERTIFICATE")
        .env_remove("SSL_CERT_FILE")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("https_proxy")
        .env_remove("http_proxy")
        .stdout(std::fs::File::create(&stdout_path)?)
        .stderr(std::fs::File::create(&stderr_path)?)
        .args([
            "run",
            "codex",
            "--policy",
            &real_policy.to_string_lossy(),
            "--agent-id",
            "aaasm5920-agent",
        ]);
    let status = cmd.status()?;
    let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    println!(
        "MEASURED aasm exit={:?}\nstdout tail: {}\nstderr tail: {}",
        status.code(),
        tail(&stdout),
        tail(&stderr)
    );
    Ok(status.code().unwrap_or(-1))
}

fn tail(output: &str) -> String {
    let start = output.len().saturating_sub(2048);
    output[output.char_indices().find(|(i, _)| *i >= start).map_or(0, |(i, _)| i)..].to_string()
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_governed_codex_launch_has_its_request_redacted_and_the_secret_never_reaches_the_provider(
) -> anyhow::Result<()> {
    install_crypto_provider();
    let fixture = Fixture::create()?;

    // ── the provider, behind the proxy's own certificate authority ─────────
    let ca = CaStore::load_or_create(&fixture.ca_dir)
        .await
        .map_err(|e| anyhow::anyhow!("certificate authority: {e}"))?;
    let upstream = std::sync::Arc::new(TlsCapturingUpstream::start(&ca, TARGET_HOST).await?);
    drop(ca);

    // ── the proxy `aasm run` will vouch for, MitM-ing onto the mock ────────
    let proxy = TrustedProxy::start_intercepting(&fixture.ca_dir, upstream.addr, &fixture.state, &[])?;
    let proxy_url = proxy.expected_proxy_url();

    // ── the gateway ─────────────────────────────────────────────────────────
    let gateway = GrpcGateway::start().await?;

    // ── the install — production EngineLifecycle wiring ────────────────────
    install(&fixture, &proxy_url).await?;

    // ── the launch ───────────────────────────────────────────────────────
    run_codex_stand_in(&fixture, &gateway, &proxy, upstream.addr)?;

    let observed = upstream.wait_for_requests(1, REQUEST_PATIENCE).await;
    println!("MEASURED requests reaching the provider: {observed}");
    assert!(
        observed >= 1,
        "the stand-in's traffic never reached the mock upstream — the CA-trust launch environment did \
         not deliver a working handshake"
    );

    let bodies = upstream.bodies();
    assert_recorded_and_secret_absent(&bodies, SYNTHETIC_SECRET, "AAASM-5920 codex CA-trust launch");

    let outcome = read_outcome(&fixture.outcome_path).expect("codex_tls_client must have written an outcome file");
    assert_eq!(
        outcome.get("branch").map(String::as_str),
        Some("CODEX_CA_CERTIFICATE"),
        "the installed launch environment must win the branch, not SSL_CERT_FILE or system roots: {outcome:?}"
    );
    assert_eq!(
        outcome.get("result").map(String::as_str),
        Some("success"),
        "the stand-in's request must have completed through the proxy: {outcome:?}"
    );

    // ── the negative control: one variable moved ────────────────────────────
    LaunchEnvStore::at(fixture.codex_paths.launch_env_dir(SettingsScope::User).unwrap())
        .unset("CODEX_CA_CERTIFICATE")
        .map_err(|e| anyhow::anyhow!("unsetting CODEX_CA_CERTIFICATE: {e}"))?;

    run_codex_stand_in(&fixture, &gateway, &proxy, upstream.addr)?;

    // (a) the stub launched — an outcome exists and names the fallback branch.
    let control = read_outcome(&fixture.outcome_path).expect("the negative control must still write an outcome file");
    assert_eq!(
        control.get("branch").map(String::as_str),
        Some("system roots"),
        "with CODEX_CA_CERTIFICATE unset the stand-in must fall back to system roots, proving it ran \
         without the installed trust material: {control:?}"
    );
    // (b) it connected and the handshake was refused — a certificate error.
    assert_eq!(
        control.get("result").map(String::as_str),
        Some("error"),
        "without the installed CA the request must fail on the handshake, not silently succeed: {control:?}"
    );
    let detail = control.get("detail").cloned().unwrap_or_default();
    assert!(
        detail.to_lowercase().contains("certificate") || detail.to_lowercase().contains("invalid peer"),
        "the failure must be a certificate-verification error, not some unrelated connectivity failure: \
         {control:?}"
    );
    // (c) nothing new reached the mock upstream.
    let bodies_after_control = upstream.bodies();
    assert_eq!(
        bodies_after_control.len(),
        bodies.len(),
        "the negative-control run must not have delivered any additional request to the provider"
    );

    Ok(())
}
