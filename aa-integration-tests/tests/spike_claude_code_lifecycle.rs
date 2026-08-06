//! AAASM-5276 Spike — Claude Code install / protection / repair / removal
//! lifecycle on macOS, as an executable evidence harness.
//!
//! Implements scenarios 11.1–11.11 of `docs/src/devtools/product-brief.md`
//! (AAASM-5273). Each scenario is one test; each test either measures the claim
//! or skips with a printed reason. Nothing here asserts on the *presence of
//! configuration* as a proxy for protection — that is the design rule §11 opens
//! with, and the reason [`spike_support::status`] cannot reach
//! `GatewayProtected` without exercised evidence.
//!
//! # Portability
//!
//! CI runs on Linux, where there is no `claude` binary and no macOS keychain.
//! Scenarios needing the real binary call `require_claude()` and return early
//! with `SKIP: …` printed. Everything else — the adapter, the receipt, the
//! proxy, the scanner, the mock provider — is pure Rust and runs everywhere.
//!
//! # Safety
//!
//! Every test opens with `RealHomeGuard::capture()` and closes with
//! `assert_unchanged`, so a regression that escapes the temp tree and writes the
//! developer's live `~/.claude/settings.json` fails the suite loudly. The guard
//! fingerprints size+mtime only and never reads the file's contents.

/// The evidence ledger (AAASM-5465), declared once per test binary.
///
/// The support modules re-export it rather than declaring their own, because a
/// binary including two of them would otherwise load the same file twice.
#[path = "evidence/mod.rs"]
pub mod evidence;

mod spike_support;

use std::time::Duration;

use aa_devtool_contract::{DevToolAdapter, PolicyDecision, PolicyDocument, PolicyRule};
use aa_proxy::audit_jsonl::ProxyAuditEntry;
use aa_proxy::config::CredentialAction;
use aa_proxy::tls::CaStore;
use spike_support::proxy_harness::{
    client_trusting_proxy_ca, drive_direct, drive_emulated_client, install_crypto_provider, ClaudeLaunch, ProxyHarness,
    ANTHROPIC_HOST,
};
use spike_support::{
    assert_recorded_and_secret_absent, assert_recorded_and_secret_present, claude_version, find_secret, locate_claude,
    require_claude, require_macos, sha256_hex, AnthropicMock, Evidence, HostEnforcement, Measurement, Mechanism,
    ProtectionLevel, RealHomeGuard, SpikeReceipt, StatusInputs, StatusReport, TempClaudeEnv, TlsCapturingUpstream,
    AASM_OWNED_SETTINGS_KEYS, SYNTHETIC_SECRET,
};

/// Ledger names for the two scenarios that can decline to measure.
///
/// Constants rather than literals at the call site because the same name has to
/// reach both guards of a scenario and the CI summary that reads the ledger; a
/// typo would silently split one scenario into two records.
const SCENARIO_REAL_BINARY_PROXY: &str = "spike-11.3-real-binary-through-proxy";
const SCENARIO_REAL_BINARY_BASE_URL: &str = "spike-11.3-real-binary-base-url-redirection";

/// Endpoint the managed launcher records as the injected `HTTPS_PROXY` value at
/// install time. Scenario 11.6 perturbs it to drive the second drift mechanism.
const INSTALLED_ENDPOINT: &str = "http://127.0.0.1:8899";

/// Policy the Spike installs — one allow, one deny, one MCP allow and one MCP
/// deny, so all four AASM-owned settings keys carry a non-trivial value and a
/// drift in any of them is observable.
fn spike_policy() -> PolicyDocument {
    PolicyDocument {
        version: 1,
        name: "aaasm-5276-spike".to_owned(),
        rules: vec![
            PolicyRule {
                action_pattern: "Read".to_owned(),
                decision: PolicyDecision::Allow,
            },
            PolicyRule {
                action_pattern: "Bash".to_owned(),
                decision: PolicyDecision::Deny,
            },
            PolicyRule {
                action_pattern: "mcp:filesystem".to_owned(),
                decision: PolicyDecision::Allow,
            },
            PolicyRule {
                action_pattern: "mcp:search".to_owned(),
                decision: PolicyDecision::Deny,
            },
        ],
        enforcement_mode: aa_devtool_contract::EnforcementMode::Enforce,
    }
}

/// Run the Spike's `install` step: generate managed settings from policy, apply
/// them through the real adapter, and record a receipt.
///
/// Returns the receipt plus the post-install bytes.
async fn install(env: &TempClaudeEnv) -> anyhow::Result<(SpikeReceipt, Vec<u8>)> {
    let adapter = env.adapter();
    let pre = env.read_settings();
    let settings = adapter.generate_managed_settings(&spike_policy()).await?;
    adapter.apply_settings(&settings).await?;
    let post = env
        .read_settings()
        .ok_or_else(|| anyhow::anyhow!("apply_settings produced no file"))?;
    let receipt = SpikeReceipt::record_install(
        "spike-claude-code",
        "claude",
        // The non-declaring lookup: this helper is on the path of every
        // scenario in the file, including the hermetic ones, and the version is
        // decoration on a receipt rather than a precondition. Calling the
        // gating form here made every hermetic scenario print a `SKIP:` line it
        // had not earned (AAASM-5465).
        locate_claude().ok().and_then(|b| claude_version(&b)),
        &env.settings_path(),
        pre.as_deref(),
        &post,
        INSTALLED_ENDPOINT,
    )?;
    Ok((receipt, post))
}

// ── 11.1 Idempotent install ─────────────────────────────────────────────────

/// Applying the managed settings twice with no intervening change must leave the
/// file byte-identical and the receipt identical.
///
/// The assertion that carries it is a SHA-256 comparison of the whole file, not
/// a field-by-field JSON compare: key insertion order and serialiser formatting
/// are exactly the kind of "no-op" mutation an idempotence claim has to exclude.
#[tokio::test]
async fn scenario_11_1_install_is_idempotent() {
    let guard = RealHomeGuard::capture();
    println!(
        "SAFETY: guarding {} (metadata only, contents never read)",
        guard.path().display()
    );
    let env = TempClaudeEnv::new().expect("temp env");

    let (receipt_1, after_1) = install(&env).await.expect("first install");
    let digest_1 = sha256_hex(&after_1);

    let (receipt_2, after_2) = install(&env).await.expect("second install");
    let digest_2 = sha256_hex(&after_2);

    assert_eq!(
        digest_1, digest_2,
        "second install mutated the settings file (not idempotent)"
    );
    assert_eq!(
        receipt_1.installed_values, receipt_2.installed_values,
        "second install recorded different managed values",
    );
    assert!(
        receipt_2.detect_drift(Some(&after_2), INSTALLED_ENDPOINT).is_empty(),
        "a freshly re-applied install must report no drift",
    );

    guard.assert_unchanged("11.1");
}

// ── 11.2 Unrelated user settings preserved ──────────────────────────────────

/// User-authored keys outside the AASM-managed four survive install, repair and
/// removal byte-for-byte in value.
///
/// This also pins the managed-key set: the test asserts that *exactly* the four
/// keys in [`AASM_OWNED_SETTINGS_KEYS`] changed, so if
/// `aa-devtool-claude-code/src/apply.rs:47` grows a fifth without this list
/// following, the test fails rather than silently under-reporting AASM's
/// footprint.
#[tokio::test]
async fn scenario_11_2_unrelated_user_settings_preserved() {
    let guard = RealHomeGuard::capture();
    let env = TempClaudeEnv::new().expect("temp env");

    // Seed user-authored settings, in the canonical pretty form the adapter's
    // serialiser also emits, so the byte-exactness claim in 11.7 is about
    // content rather than formatting.
    let seeded = serde_json::json!({
        "theme": "dark",
        "model": "claude-sonnet-4-5",
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]},
        "env": {"USER_AUTHORED": "keep-me"},
        "statusLine": {"type": "command", "command": "echo hi"},
    });
    let seeded_bytes = serde_json::to_string_pretty(&seeded).unwrap().into_bytes();
    env.write_settings(&seeded_bytes).expect("seed settings");
    let before = env.snapshot();

    let (receipt, after_install) = install(&env).await.expect("install");

    let before_json = before.json().expect("seed parses");
    let after_json: serde_json::Value = serde_json::from_slice(&after_install).expect("post-install parses");

    // Every unmanaged key survives unchanged.
    for (key, value) in before_json.as_object().unwrap() {
        assert_eq!(
            after_json.get(key),
            Some(value),
            "install mutated the user-authored key `{key}`",
        );
    }
    // Exactly the managed four were added.
    let added: Vec<&String> = after_json
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| before_json.get(k.as_str()).is_none())
        .collect();
    let mut added_sorted: Vec<&str> = added.iter().map(|s| s.as_str()).collect();
    added_sorted.sort_unstable();
    let mut expected: Vec<&str> = AASM_OWNED_SETTINGS_KEYS.to_vec();
    expected.sort_unstable();
    assert_eq!(
        added_sorted, expected,
        "install's footprint differs from the documented AASM-owned key set",
    );

    // Repair keeps them.
    let repaired = receipt.repair_settings(Some(&after_install)).expect("repair");
    let repaired_json: serde_json::Value = serde_json::from_slice(&repaired).unwrap();
    for (key, value) in before_json.as_object().unwrap() {
        assert_eq!(repaired_json.get(key), Some(value), "repair mutated `{key}`");
    }

    // Removal restores the pre-install state byte-exactly.
    let removed = receipt
        .removal_settings(Some(&repaired))
        .expect("removal")
        .expect("file existed before install, so removal rewrites it");
    env.write_settings(&removed).expect("write removal");
    assert_eq!(
        env.snapshot().digest(),
        before.digest(),
        "post-removal file is not byte-identical to the pre-install snapshot",
    );

    guard.assert_unchanged("11.2");
}

// ── 11.3 / 11.4 Synthetic secret never reaches the provider ─────────────────

/// Drive secret-bearing traffic through the real `aa-proxy` MitM path and assert
/// the mock provider recorded traffic **and** never saw the raw value, while the
/// forwarded payload carries the semantics-preserving placeholder.
///
/// Combines 11.3 and 11.4 because they are two assertions on one measurement:
/// splitting them would double a ~1s proxy setup for no extra evidence.
///
/// This uses the emulated Anthropic client, not the real binary — see
/// [`scenario_11_3_real_claude_binary_through_proxy`] for the real-binary run.
#[tokio::test(flavor = "multi_thread")]
async fn scenario_11_3_and_11_4_secret_redacted_before_reaching_provider() {
    let guard = RealHomeGuard::capture();
    install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = CaStore::load_or_create(dir.path()).await.expect("ca");
    let upstream = TlsCapturingUpstream::start(&ca, ANTHROPIC_HOST)
        .await
        .expect("tls upstream");
    let client = std::sync::Arc::new(client_trusting_proxy_ca(dir.path()).await.expect("client cfg"));

    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel::<ProxyAuditEntry>(64);
    let proxy = ProxyHarness::start(
        dir.path(),
        ca,
        CredentialAction::RedactOnly,
        upstream.addr,
        Some(audit_tx),
    )
    .await
    .expect("proxy starts");
    println!("MEASURED: proxy startup to first accept = {:?}", proxy.startup);

    let prompt = format!("Please review this config line: ANTHROPIC_API_KEY={SYNTHETIC_SECRET} and explain it.");
    let result = drive_emulated_client(proxy.addr, client, &prompt)
        .await
        .expect("drive through proxy");
    assert!(
        result.connected(),
        "CONNECT through the proxy failed: {}",
        result.connect_status,
    );
    println!("MEASURED: proxied request round-trip = {:?}", result.elapsed);

    let observed = upstream.wait_for_requests(1, Duration::from_secs(10)).await;
    assert_eq!(observed, 1, "mock provider must record exactly the one request driven");

    // 11.3 — traffic flowed, and no encoding of the secret reached the provider.
    let bodies = upstream.bodies();
    assert_recorded_and_secret_absent(&bodies, SYNTHETIC_SECRET, "11.3 mechanism-A proxy MitM");

    // 11.4 — the placeholder is present and surrounding content is intact.
    let forwarded = upstream.last_body().expect("forwarded body is utf-8");
    assert!(
        forwarded.contains("[REDACTED:AnthropicKey]"),
        "forwarded payload lacks the semantics-preserving placeholder: {forwarded}",
    );
    assert!(
        forwarded.contains("Please review this config line:") && forwarded.contains("and explain it."),
        "redaction damaged surrounding content: {forwarded}",
    );
    let forwarded_json: serde_json::Value =
        serde_json::from_str(&forwarded).expect("11.4: redacted body must still be valid JSON the provider can parse");
    assert_eq!(forwarded_json["model"], "claude-sonnet-4-5");
    // The provider saw a well-formed Messages request, so the session is not
    // broken by protection — the second half of 11.4's claim.
    assert_eq!(
        upstream.request_lines(),
        vec![("POST".to_owned(), "/v1/messages".to_owned())],
    );
    assert!(
        upstream.last_header_names().contains(&"anthropic-version".to_owned()),
        "provider-required headers were dropped in transit: {:?}",
        upstream.last_header_names(),
    );
    assert!(
        result.inner_response.as_deref().unwrap_or_default().contains("200"),
        "the client did not receive a successful response: {:?}",
        result.inner_response,
    );

    // The proxy emitted an audit entry naming the finding, without the value.
    let entry = audit_rx.recv().await.expect("proxy emitted an audit entry");
    assert!(
        entry
            .credential_findings
            .iter()
            .any(|f| f.matched == "[REDACTED:AnthropicKey]"),
        "audit entry does not name the AnthropicKey finding: {entry:?}",
    );

    guard.assert_unchanged("11.3/11.4");
}

/// Real-binary counterpart to 11.3: spawn `claude -p` with `HTTPS_PROXY` at the
/// proxy and `NODE_EXTRA_CA_CERTS` at the temp CA PEM.
///
/// Skips where the binary is absent. Records the exact behaviour either way —
/// whether MitM TLS is accepted by the binary's bundled Node TLS stack is the
/// single most load-bearing unknown for productising Mechanism A, and it can
/// only be answered by the real binary.
#[tokio::test(flavor = "multi_thread")]
async fn scenario_11_3_real_claude_binary_through_proxy() {
    let guard = RealHomeGuard::capture();
    let Some(bin) = require_claude(SCENARIO_REAL_BINARY_PROXY) else {
        return;
    };
    if !require_macos(SCENARIO_REAL_BINARY_PROXY) {
        return;
    }
    install_crypto_provider();

    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = CaStore::load_or_create(dir.path()).await.expect("ca");
    let upstream = TlsCapturingUpstream::start(&ca, ANTHROPIC_HOST)
        .await
        .expect("upstream");
    let proxy = ProxyHarness::start(dir.path(), ca, CredentialAction::RedactOnly, upstream.addr, None)
        .await
        .expect("proxy");

    let env = TempClaudeEnv::new().expect("temp env");
    env.write_repo_file("config/app.env", &format!("ANTHROPIC_API_KEY={SYNTHETIC_SECRET}\n"))
        .expect("seed repo secret");

    let run = ClaudeLaunch::new(
        &bin,
        env.home(),
        env.repo(),
        format!("Echo this configuration line verbatim: ANTHROPIC_API_KEY={SYNTHETIC_SECRET}"),
    )
    .env("HTTPS_PROXY", proxy.proxy_url())
    .env("HTTP_PROXY", proxy.proxy_url())
    .env("NODE_EXTRA_CA_CERTS", proxy.ca_pem().display().to_string())
    .env("ANTHROPIC_AUTH_TOKEN", "AAASM5276-DUMMY-NOT-A-REAL-TOKEN")
    // Four is the full observed egress set for one headless run: two
    // `/v1/messages` POSTs, one MCP-registry GET and one
    // `/api/event_logging/v2/batch` telemetry POST. Waiting for all four is
    // what proves the proxy scans the binary's *side channels* too, not just
    // its model endpoint. Bounded, because the binary never exits when every
    // host is MitM'd onto one mock.
    .run_until(Duration::from_secs(25), || upstream.request_count() >= 4)
    .await
    .expect("spawn claude");

    println!(
        "MEASURED real-binary mechanism A: version={:?} exit={:?} stopped_by_harness={} elapsed={:?}",
        claude_version(&bin),
        run.exit_code,
        run.timed_out,
        run.elapsed,
    );
    println!("MEASURED real-binary stdout: {}", run.stdout.trim());
    if !run.stderr.trim().is_empty() {
        println!("MEASURED real-binary stderr: {}", run.stderr.trim());
    }

    let observed = upstream.wait_for_requests(1, Duration::from_secs(20)).await;
    println!("MEASURED real-binary requests reaching the mock through the proxy: {observed}");
    println!("MEASURED real-binary request lines: {:?}", upstream.request_lines());

    if observed == 0 {
        // Both opt-outs are behind us — macOS, and the binary exists — so the
        // scenario committed to measuring. Zero traffic is a *failed*
        // measurement, and until AAASM-5465 it returned and was counted as a
        // pass alongside the scenarios that genuinely measured something.
        let detail = format!(
            "the real claude binary produced no upstream traffic through the proxy (exit={:?}, \
             timed_out={}); mechanism A is unproven against the real binary",
            run.exit_code, run.timed_out,
        );
        spike_support::outcome::record(SCENARIO_REAL_BINARY_PROXY, Measurement::NotMeasured, &detail);
        guard.assert_unchanged("11.3-real-binary");
        panic!("NOT MEASURED [{SCENARIO_REAL_BINARY_PROXY}]: {detail}. This is a gap in the evidence, not a pass.");
    }

    // The load-bearing claim: traffic flowed and no body carried the secret.
    let bodies = upstream.bodies();
    assert_recorded_and_secret_absent(&bodies, SYNTHETIC_SECRET, "11.3 real binary via proxy MitM");

    // The binary opens several connections (Messages plus side channels); the
    // placeholder is expected in whichever body carried the prompt, not
    // necessarily the last one to arrive.
    let redacted_bodies = bodies
        .iter()
        .filter(|b| String::from_utf8_lossy(b).contains("[REDACTED:AnthropicKey]"))
        .count();
    println!(
        "MEASURED real-binary bodies carrying the placeholder: {redacted_bodies} of {}",
        bodies.len()
    );
    for (i, body) in bodies.iter().enumerate() {
        let text = String::from_utf8_lossy(body);
        println!(
            "MEASURED real-binary body #{i}: {} bytes, head={:?}",
            body.len(),
            text.chars().take(160).collect::<String>(),
        );
    }
    assert!(
        redacted_bodies > 0,
        "the real binary's traffic reached the provider but no body carried the redaction \
         placeholder — the prompt never crossed the scanned path",
    );

    spike_support::outcome::record(
        SCENARIO_REAL_BINARY_PROXY,
        Measurement::Measured,
        &format!(
            "{observed} request(s) observed through the proxy, {redacted_bodies} of {} carried the \
             redaction placeholder",
            bodies.len()
        ),
    );
    guard.assert_unchanged("11.3-real-binary");
}

/// Mechanism B, the required negative result: `ANTHROPIC_BASE_URL` pointed
/// straight at a provider takes AASM out of the path entirely, so the raw secret
/// arrives.
///
/// Asserted **positively**. A mechanism the product might be tempted to use for
/// convenience routing must be shown to provide no protection, or a future
/// implementer will reach for it.
#[tokio::test(flavor = "multi_thread")]
async fn scenario_11_3_base_url_redirection_removes_aasm_from_the_path() {
    let guard = RealHomeGuard::capture();
    let mock = AnthropicMock::start().await.expect("mock");
    let prompt = format!("here is a key: {SYNTHETIC_SECRET}");
    let elapsed = drive_direct(&mock.url, &prompt).await.expect("direct request");
    println!("MEASURED: direct (no-proxy) request round-trip = {elapsed:?}");

    assert_eq!(mock.wait_for_requests(1, Duration::from_secs(5)).await, 1);
    assert_eq!(
        mock.request_lines(),
        vec![("POST".to_owned(), "/v1/messages".to_owned())]
    );
    assert_recorded_and_secret_present(
        &mock.bodies(),
        SYNTHETIC_SECRET,
        "11.3 mechanism-B base-URL redirection",
    );

    guard.assert_unchanged("11.3-mechanism-B");
}

/// Real-binary Mechanism B: point the actual `claude` binary at the mock via
/// `ANTHROPIC_BASE_URL` and confirm the raw secret lands in the provider's
/// recorded body with no AASM component in the path.
#[tokio::test(flavor = "multi_thread")]
async fn scenario_11_3_real_claude_binary_base_url_redirection() {
    let guard = RealHomeGuard::capture();
    let Some(bin) = require_claude(SCENARIO_REAL_BINARY_BASE_URL) else {
        return;
    };
    let mock = AnthropicMock::start().await.expect("mock");
    let env = TempClaudeEnv::new().expect("temp env");

    let run = ClaudeLaunch::new(
        &bin,
        env.home(),
        env.repo(),
        format!("Echo this verbatim: {SYNTHETIC_SECRET}"),
    )
    .env("ANTHROPIC_BASE_URL", &mock.url)
    .env("ANTHROPIC_AUTH_TOKEN", "AAASM5276-DUMMY-NOT-A-REAL-TOKEN")
    .timeout(Duration::from_secs(120))
    .run()
    .await
    .expect("spawn claude");

    println!(
        "MEASURED real-binary mechanism B: exit={:?} timed_out={} elapsed={:?} stdout={:?}",
        run.exit_code,
        run.timed_out,
        run.elapsed,
        run.stdout.trim(),
    );

    let observed = mock.wait_for_requests(1, Duration::from_secs(20)).await;
    println!("MEASURED real-binary requests reaching the mock directly: {observed}");
    println!("MEASURED real-binary request lines: {:?}", mock.request_lines());
    println!("MEASURED real-binary request headers: {:?}", mock.last_header_names());
    if observed == 0 {
        let detail = "the real binary produced no traffic; mechanism B unproven on this host";
        spike_support::outcome::record(SCENARIO_REAL_BINARY_BASE_URL, Measurement::NotMeasured, detail);
        guard.assert_unchanged("11.3-real-binary-B");
        panic!(
            "NOT MEASURED [{SCENARIO_REAL_BINARY_BASE_URL}]: {detail}. This is a gap in the \
             evidence, not a pass."
        );
    }
    assert_recorded_and_secret_present(
        &mock.bodies(),
        SYNTHETIC_SECRET,
        "11.3 real binary via ANTHROPIC_BASE_URL",
    );

    spike_support::outcome::record(
        SCENARIO_REAL_BINARY_BASE_URL,
        Measurement::Measured,
        &format!("{observed} request(s) reached the mock with AASM out of the path, as required"),
    );
    guard.assert_unchanged("11.3-real-binary-B");
}

// ── 11.5 Raw secret absent from audit / logs / traces / receipt ─────────────

/// Collect every artefact one protected run produces and assert the raw value is
/// in none of them, **while** the finding metadata (kind and count) is present.
///
/// The second half is what distinguishes "detected and redacted" from "never
/// seen". An artefact set with neither the secret nor any finding would pass a
/// naive absence check while proving the scanner never ran.
#[tokio::test(flavor = "multi_thread")]
async fn scenario_11_5_raw_secret_absent_from_all_artefacts() {
    let guard = RealHomeGuard::capture();
    install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = CaStore::load_or_create(dir.path()).await.expect("ca");
    let upstream = TlsCapturingUpstream::start(&ca, ANTHROPIC_HOST)
        .await
        .expect("upstream");
    let client = std::sync::Arc::new(client_trusting_proxy_ca(dir.path()).await.expect("client cfg"));

    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel::<ProxyAuditEntry>(64);
    let mut proxy = ProxyHarness::start(
        dir.path(),
        ca,
        CredentialAction::RedactOnly,
        upstream.addr,
        Some(audit_tx),
    )
    .await
    .expect("proxy");

    let prompt = format!("token check {SYNTHETIC_SECRET} please");
    drive_emulated_client(proxy.addr, client, &prompt).await.expect("drive");
    assert_eq!(upstream.wait_for_requests(1, Duration::from_secs(10)).await, 1);

    // Artefact 1: the proxy's JSONL audit entries.
    let mut audit_entries = Vec::new();
    while let Ok(entry) = audit_rx.try_recv() {
        audit_entries.push(entry);
    }
    assert!(!audit_entries.is_empty(), "no audit entries were produced");
    let audit_json = serde_json::to_string(&audit_entries).expect("audit serialises");

    // Artefact 2: runtime pipeline events (what a trace/diagnostic bundle carries).
    let mut pipeline_debug = String::new();
    while let Ok(event) = proxy.events.try_recv() {
        pipeline_debug.push_str(&format!("{event:?}\n"));
    }

    // Artefact 3: the installation receipt and status output.
    let env = TempClaudeEnv::new().expect("temp env");
    let (receipt, after) = install(&env).await.expect("install");
    let status = StatusReport::compute(&StatusInputs {
        installed: true,
        core_reachable: true,
        evidence: vec![Evidence::Exercised {
            mechanism: Mechanism::InjectedProxyEndpoint.as_str().to_owned(),
            observation: format!("{} finding(s) redacted", audit_entries[0].credential_findings.len()),
        }],
        ..Default::default()
    });

    let artefacts: Vec<(&str, Vec<u8>)> = vec![
        ("proxy-audit-jsonl", audit_json.clone().into_bytes()),
        ("runtime-pipeline-events", pipeline_debug.clone().into_bytes()),
        ("installation-receipt", receipt.to_json().into_bytes()),
        ("post-install-settings", after.clone()),
        ("status-output", status.render().into_bytes()),
    ];
    for (name, bytes) in &artefacts {
        assert!(
            find_secret(std::slice::from_ref(bytes), SYNTHETIC_SECRET).is_none(),
            "raw synthetic secret found in artefact `{name}`",
        );
    }

    // Finding metadata present: kind and count, never the value.
    let findings: usize = audit_entries.iter().map(|e| e.credential_findings.len()).sum();
    assert!(
        findings > 0,
        "audit recorded zero findings — the scanner never detected anything"
    );
    assert!(
        audit_json.contains("AnthropicKey"),
        "audit output does not name the detected credential kind",
    );
    println!(
        "MEASURED: {findings} finding(s) recorded across {} audit entries",
        audit_entries.len()
    );

    guard.assert_unchanged("11.5");
}

// ── 11.6 Drift detected and repaired in two mechanisms ──────────────────────

/// Perturb two independent managed mechanisms, assert both are reported with
/// expected-versus-actual, assert the level drops before repair, and assert
/// repair restores only AASM-owned values.
///
/// The user-authored key is perturbed **in the same edit** as the managed key.
/// Repair must fix one and leave the other alone; asserting only that the
/// managed key was restored would not distinguish a correct repair from one that
/// rewrote the whole file from the receipt.
#[tokio::test]
async fn scenario_11_6_drift_detected_and_repaired_in_two_mechanisms() {
    let guard = RealHomeGuard::capture();
    let env = TempClaudeEnv::new().expect("temp env");
    env.write_settings(
        serde_json::to_string_pretty(&serde_json::json!({"theme": "dark"}))
            .unwrap()
            .as_bytes(),
    )
    .expect("seed");
    let (receipt, after_install) = install(&env).await.expect("install");
    assert!(receipt
        .detect_drift(Some(&after_install), INSTALLED_ENDPOINT)
        .is_empty());

    // Mechanism 1 — hand-edit an AASM-managed settings key, and a user key
    // alongside it in the same write.
    let mut doc: serde_json::Value = serde_json::from_slice(&after_install).unwrap();
    doc["permissionMode"] = serde_json::json!("bypassPermissions");
    doc["theme"] = serde_json::json!("light-edited-by-user");
    let perturbed = serde_json::to_string_pretty(&doc).unwrap().into_bytes();
    env.write_settings(&perturbed).expect("perturb");

    // Mechanism 2 — the injected proxy endpoint changed out from under us.
    let perturbed_endpoint = "http://127.0.0.1:9999";

    let drift = receipt.detect_drift(Some(&perturbed), perturbed_endpoint);
    let mechanisms: std::collections::BTreeSet<Mechanism> = drift.iter().map(|d| d.mechanism).collect();
    assert_eq!(
        mechanisms.len(),
        2,
        "expected drift in two distinct mechanisms, got: {drift:?}",
    );
    let settings_drift = drift
        .iter()
        .find(|d| d.mechanism == Mechanism::ManagedSettings)
        .expect("settings drift reported");
    assert_eq!(settings_drift.key, "permissionMode");
    assert_eq!(settings_drift.expected, "\"default\"");
    assert_eq!(settings_drift.actual, "\"bypassPermissions\"");
    let endpoint_drift = drift
        .iter()
        .find(|d| d.mechanism == Mechanism::InjectedProxyEndpoint)
        .expect("endpoint drift reported");
    assert_eq!(endpoint_drift.expected, INSTALLED_ENDPOINT);
    assert_eq!(endpoint_drift.actual, perturbed_endpoint);

    // Level drops before repair, even though the core is up and the config
    // "exists".
    let drifted_status = StatusReport::compute(&StatusInputs {
        installed: true,
        core_reachable: true,
        evidence: vec![Evidence::Exercised {
            mechanism: "proxy-mitm".to_owned(),
            observation: "previously exercised".to_owned(),
        }],
        drift: drift.clone(),
        ..Default::default()
    });
    assert_eq!(drifted_status.level, ProtectionLevel::Integrated);
    assert!(!drifted_status.claims_sensitive_data_protection());
    assert_eq!(drifted_status.drift.len(), drift.len());

    // Repair — AASM-owned values only.
    let repaired = receipt.repair_settings(Some(&perturbed)).expect("repair");
    env.write_settings(&repaired).expect("write repair");
    let repaired_json: serde_json::Value = serde_json::from_slice(&repaired).unwrap();
    assert_eq!(
        repaired_json["permissionMode"], "default",
        "repair did not restore the managed key"
    );
    assert_eq!(
        repaired_json["theme"], "light-edited-by-user",
        "repair overwrote a user-authored key it does not own",
    );
    assert!(
        receipt.detect_drift(Some(&repaired), INSTALLED_ENDPOINT).is_empty(),
        "drift persists after repair",
    );

    guard.assert_unchanged("11.6");
}

// ── 11.7 Removal restores pre-install state ─────────────────────────────────

/// Two removal cases, because they exercise different receipt branches: a
/// settings file that existed before install (restore values) and one that did
/// not (delete the file).
///
/// The no-prior-file case is the one that catches an installer leaving an
/// AASM-owned artefact behind.
#[tokio::test]
async fn scenario_11_7_removal_restores_pre_install_state() {
    let guard = RealHomeGuard::capture();

    // Case A — a pre-existing settings file, in the writer's canonical form.
    let env_a = TempClaudeEnv::new().expect("temp env");
    let seeded = serde_json::to_string_pretty(&serde_json::json!({
        "theme": "dark",
        "permissionMode": "plan",
    }))
    .unwrap()
    .into_bytes();
    env_a.write_settings(&seeded).expect("seed");
    let before_a = env_a.snapshot();
    let (receipt_a, after_a) = install(&env_a).await.expect("install");
    assert_ne!(env_a.snapshot().digest(), before_a.digest(), "install changed nothing");

    let removed = receipt_a
        .removal_settings(Some(&after_a))
        .expect("removal")
        .expect("file existed before");
    env_a.write_settings(&removed).expect("write");
    assert_eq!(
        env_a.snapshot().digest(),
        before_a.digest(),
        "case A: post-removal state is not byte-identical to pre-install",
    );
    // The pre-install `permissionMode: plan` was restored, not deleted.
    assert_eq!(env_a.snapshot().json().unwrap()["permissionMode"], "plan");

    // Case B — no settings file at all before install.
    let env_b = TempClaudeEnv::new().expect("temp env");
    let before_b = env_b.snapshot();
    assert!(before_b.bytes.is_none(), "case B precondition: no settings file");
    let (receipt_b, _after_b) = install(&env_b).await.expect("install");
    assert!(env_b.read_settings().is_some(), "install created no file");

    assert!(
        receipt_b
            .removal_settings(env_b.read_settings().as_deref())
            .unwrap()
            .is_none(),
        "case B: removal must delete the file rather than rewrite it",
    );
    std::fs::remove_file(env_b.settings_path()).expect("remove");
    assert_eq!(env_b.snapshot(), before_b, "case B: an AASM-owned artefact remained");

    guard.assert_unchanged("11.7");
}

/// Documented limitation of the Spike's key-level restore: it is
/// **semantics-exact but not byte-exact** when the pre-install file used a
/// different serialisation from the one `apply_settings_at` emits.
///
/// `aa-devtool-claude-code/src/apply.rs:85` reserialises the whole document with
/// `serde_json::to_string_pretty`, so a compact or differently-indented
/// user-authored file cannot survive an install/remove cycle byte-for-byte no
/// matter how good the receipt is. Asserted rather than described, so the
/// productisation ticket inherits a failing-by-construction fact, not a note.
#[tokio::test]
async fn scenario_11_7_byte_exact_restore_fails_for_non_canonical_formatting() {
    let guard = RealHomeGuard::capture();
    let env = TempClaudeEnv::new().expect("temp env");

    // Compact JSON — what a hand-edited or tool-generated file may look like.
    let compact = br#"{"theme":"dark","permissionMode":"plan"}"#.to_vec();
    env.write_settings(&compact).expect("seed");
    let before = env.snapshot();

    let (receipt, after) = install(&env).await.expect("install");
    let removed = receipt.removal_settings(Some(&after)).unwrap().unwrap();
    env.write_settings(&removed).expect("write");

    assert_ne!(
        env.snapshot().digest(),
        before.digest(),
        "unexpected: byte-exact restore succeeded for non-canonical input — if the adapter \
         gained content-preserving writes, this limitation is resolved and the test should be \
         inverted",
    );
    assert_eq!(
        env.snapshot().json().unwrap(),
        before.json().unwrap(),
        "restore must at minimum be semantics-exact",
    );
    println!(
        "MEASURED gap: install/remove is semantics-exact but NOT byte-exact for non-canonical \
         formatting (apply.rs reserialises the whole document)",
    );

    guard.assert_unchanged("11.7-formatting");
}

// ── 11.8 Protection-level reporting ─────────────────────────────────────────

/// Three configurations must produce three distinguishable reports, and all
/// three must report host enforcement as unavailable rather than omitting it.
#[tokio::test]
async fn scenario_11_8_protection_level_reporting_distinguishes_three_levels() {
    let guard = RealHomeGuard::capture();

    // (a) Settings applied, never launched through the managed path.
    let integrated = StatusReport::compute(&StatusInputs {
        installed: true,
        core_reachable: true,
        evidence: vec![Evidence::ReadBack {
            mechanism: Mechanism::ManagedSettings.as_str().to_owned(),
        }],
        ..Default::default()
    });
    assert_eq!(integrated.level, ProtectionLevel::Integrated);
    assert!(
        !integrated.claims_sensitive_data_protection(),
        "`Integrated` must not claim sensitive-data protection",
    );
    assert!(integrated.confirmed_by_exercise.is_empty());
    assert_eq!(integrated.confirmed_by_read_back, vec!["managed-settings"]);

    // (b) Protection actually exercised (the 11.3 measurement).
    let protected = StatusReport::compute(&StatusInputs {
        installed: true,
        core_reachable: true,
        evidence: vec![
            Evidence::ReadBack {
                mechanism: Mechanism::ManagedSettings.as_str().to_owned(),
            },
            Evidence::Exercised {
                mechanism: Mechanism::InjectedProxyEndpoint.as_str().to_owned(),
                observation: "1 request forwarded redacted, 1 AnthropicKey finding".to_owned(),
            },
        ],
        ..Default::default()
    });
    assert_eq!(protected.level, ProtectionLevel::GatewayProtected);
    assert!(protected.claims_sensitive_data_protection());
    assert_eq!(protected.confirmed_by_exercise, vec!["injected-proxy-endpoint"]);
    assert_eq!(
        protected.confirmed_by_read_back,
        vec!["managed-settings"],
        "the report must separate exercised mechanisms from read-back-only ones",
    );

    // (c) Host enforcement is reported as unavailable in every case.
    for report in [&integrated, &protected] {
        assert_eq!(report.host_enforcement, HostEnforcement::Unavailable);
        assert!(
            report.render().contains("Host Enforced: unavailable on this platform"),
            "host enforcement must be reported, never omitted",
        );
    }

    guard.assert_unchanged("11.8");
}

// ── 11.9 Core stopped mid-session fails closed ──────────────────────────────

/// Stopping the core mid-session must drop the reported level to *not
/// protected* — the word "unknown" must not appear — and traffic must stop
/// flowing through the interception path.
#[tokio::test(flavor = "multi_thread")]
async fn scenario_11_9_core_stopped_mid_session_fails_closed() {
    let guard = RealHomeGuard::capture();
    install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = CaStore::load_or_create(dir.path()).await.expect("ca");
    let upstream = TlsCapturingUpstream::start(&ca, ANTHROPIC_HOST)
        .await
        .expect("upstream");
    let client_cfg = client_trusting_proxy_ca(dir.path()).await.expect("client cfg");
    let proxy = ProxyHarness::start(dir.path(), ca, CredentialAction::RedactOnly, upstream.addr, None)
        .await
        .expect("proxy");

    // Session is live and protected.
    let ok = drive_emulated_client(proxy.addr, std::sync::Arc::new(client_cfg.clone()), "warm up")
        .await
        .expect("drive");
    assert!(ok.connected());
    assert!(proxy.is_reachable().await);
    let live = StatusReport::compute(&StatusInputs {
        installed: true,
        core_reachable: true,
        evidence: vec![Evidence::Exercised {
            mechanism: "proxy-mitm".to_owned(),
            observation: "1 request intercepted".to_owned(),
        }],
        ..Default::default()
    });
    assert_eq!(live.level, ProtectionLevel::GatewayProtected);

    // Stop the core.
    let stopped_at = std::time::Instant::now();
    proxy.stop();
    let mut detection_window = None;
    for _ in 0..100 {
        if !proxy.is_reachable().await {
            detection_window = Some(stopped_at.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let detection_window = detection_window.expect("proxy must stop accepting connections after stop()");
    println!("MEASURED: core-stop detection window = {detection_window:?}");

    let after = StatusReport::compute(&StatusInputs {
        installed: true,
        core_reachable: false,
        evidence: vec![Evidence::Exercised {
            mechanism: "proxy-mitm".to_owned(),
            observation: "1 request intercepted (before core stop)".to_owned(),
        }],
        ..Default::default()
    });
    assert_eq!(after.level, ProtectionLevel::NotProtected);
    assert!(!after.claims_sensitive_data_protection());
    let rendered = after.render();
    assert!(
        rendered.contains("Not protected"),
        "status must say not protected: {rendered}"
    );
    assert!(
        !rendered.to_lowercase().contains("unknown"),
        "status must not degrade to 'unknown': {rendered}",
    );

    // And a new request through the dead proxy fails rather than silently
    // bypassing it.
    let dead = drive_emulated_client(proxy.addr, std::sync::Arc::new(client_cfg), "after core stop").await;
    assert!(
        dead.is_err() || !dead.as_ref().map(|r| r.connected()).unwrap_or(false),
        "traffic still traversed a stopped core: {dead:?}",
    );

    guard.assert_unchanged("11.9");
}

// ── 11.10 Observe-only never reads as protection ────────────────────────────

/// Under observe-only the decision is computed and audited but the payload is
/// forwarded unchanged: the mock provider **does** receive the synthetic value.
///
/// Asserted positively. This is the scenario that stops "monitoring" from being
/// displayable as "protected".
#[tokio::test(flavor = "multi_thread")]
async fn scenario_11_10_observe_only_forwards_the_secret_and_never_claims_protection() {
    let guard = RealHomeGuard::capture();
    install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = CaStore::load_or_create(dir.path()).await.expect("ca");
    let upstream = TlsCapturingUpstream::start(&ca, ANTHROPIC_HOST)
        .await
        .expect("upstream");
    let client = std::sync::Arc::new(client_trusting_proxy_ca(dir.path()).await.expect("client cfg"));

    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel::<ProxyAuditEntry>(64);
    // `EnforcementMode::Observe` maps onto the proxy's `AlertOnly` credential
    // action: findings are computed and audited, the body is forwarded intact.
    let proxy = ProxyHarness::start(
        dir.path(),
        ca,
        CredentialAction::AlertOnly,
        upstream.addr,
        Some(audit_tx),
    )
    .await
    .expect("proxy");

    let prompt = format!("observe-mode payload {SYNTHETIC_SECRET} end");
    drive_emulated_client(proxy.addr, client, &prompt).await.expect("drive");
    assert_eq!(upstream.wait_for_requests(1, Duration::from_secs(10)).await, 1);

    assert_recorded_and_secret_present(&upstream.bodies(), SYNTHETIC_SECRET, "11.10 observe-only");

    // The decision was still computed and audited as a shadow event.
    let entry = audit_rx.recv().await.expect("observe mode still audits");
    assert!(
        !entry.credential_findings.is_empty(),
        "observe mode must still compute and audit the finding",
    );

    let status = StatusReport::compute(&StatusInputs {
        installed: true,
        core_reachable: true,
        observe_only: true,
        evidence: vec![Evidence::Exercised {
            mechanism: "proxy-mitm".to_owned(),
            observation: format!(
                "{} finding(s) audited, payload forwarded",
                entry.credential_findings.len()
            ),
        }],
        ..Default::default()
    });
    assert_eq!(
        status.level,
        ProtectionLevel::Integrated,
        "observe-only must never reach GatewayProtected, even with exercised evidence",
    );
    assert!(!status.claims_sensitive_data_protection());
    assert!(
        status.warnings.iter().any(|w| w.contains("NOT enforced")),
        "observe-only must carry a standing not-enforcing warning: {:?}",
        status.warnings,
    );

    guard.assert_unchanged("11.10");
}

// ── 11.11 Unmanaged launch is a bypass ──────────────────────────────────────

/// A launch outside the managed path is unprotected, and status must attribute
/// that to a bypass rather than to an AASM failure.
#[tokio::test(flavor = "multi_thread")]
async fn scenario_11_11_unmanaged_launch_is_reported_as_a_bypass() {
    let guard = RealHomeGuard::capture();
    let env = TempClaudeEnv::new().expect("temp env");
    let (_receipt, _after) = install(&env).await.expect("install");

    // The integration is installed, but this session never goes through it.
    let mock = AnthropicMock::start().await.expect("mock");
    drive_direct(&mock.url, &format!("unmanaged launch carrying {SYNTHETIC_SECRET}"))
        .await
        .expect("direct");
    assert_eq!(mock.wait_for_requests(1, Duration::from_secs(5)).await, 1);
    assert_recorded_and_secret_present(&mock.bodies(), SYNTHETIC_SECRET, "11.11 unmanaged launch");

    let status = StatusReport::compute(&StatusInputs {
        installed: true,
        core_reachable: true,
        unmanaged_launches: 1,
        evidence: vec![Evidence::ReadBack {
            mechanism: Mechanism::ManagedSettings.as_str().to_owned(),
        }],
        ..Default::default()
    });
    assert_eq!(status.bypasses.len(), 1, "unmanaged launch not reported");
    let rendered = status.render();
    assert!(
        rendered.contains("BYPASS:"),
        "bypass not surfaced in status: {rendered}"
    );
    assert!(
        rendered.contains("not an AASM failure"),
        "status must distinguish a bypass from an AASM failure: {rendered}",
    );
    assert!(
        !status.claims_sensitive_data_protection(),
        "a never-exercised installation must not claim protection",
    );

    guard.assert_unchanged("11.11");
}

// ── Receipt round-trip ──────────────────────────────────────────────────────

/// The receipt must survive a write/read cycle unchanged, or none of the drift
/// and rollback measurements above mean anything across process boundaries.
#[tokio::test]
async fn spike_receipt_round_trips_through_disk() {
    let guard = RealHomeGuard::capture();
    let env = TempClaudeEnv::new().expect("temp env");
    let (receipt, _after) = install(&env).await.expect("install");
    let path = env.home().join("receipt.json");
    receipt.write(&path).expect("write receipt");
    let read_back = SpikeReceipt::read(&path).expect("read receipt");
    assert_eq!(receipt, read_back);
    guard.assert_unchanged("receipt-round-trip");
}
