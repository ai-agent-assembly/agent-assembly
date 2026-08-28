//! AAASM-5283 — the Claude Code Developer Integration conformance suite.
//!
//! `install → protect → drift/repair → remove`, executed end to end against the
//! production lifecycle service, a live `aa-proxy`, a real MitM certificate
//! authority and a TLS-terminating provider that records every body it is given.
//!
//! # What this suite is for
//!
//! Integration completion cannot be inferred from unit tests for settings
//! generation, nor from a successful `aasm run`. The promise spans several
//! components and mutates configuration outside this repository, so the only
//! honest completion gate is an executable one. This is that gate: it is the
//! required check for AAASM-5281 and for every future tool productisation.
//!
//! # The design rule every scenario obeys
//!
//! > A scenario passes on **observed behaviour**, never on the presence of
//! > configuration.
//!
//! `docs/src/devtools/product-brief.md` §11 opens with that rule and it is why
//! the suite carries three assertions that look strange out of context:
//!
//! * **11.3's "at least one request" clause.** A run in which no traffic
//!   reached the provider satisfies "no raw secret was received" while proving
//!   nothing, so every redaction assertion is paired with a positive assertion
//!   that the provider recorded traffic.
//! * **11.10 asserts the secret *does* arrive.** Under the observe-only profile
//!   the payload is forwarded unchanged; that is correct, and asserting it
//!   positively is what stops "monitoring" from ever being displayable as
//!   "protected".
//! * **11.11 asserts an unmanaged launch is unprotected.** The product must be
//!   able to distinguish "we are broken" from "you went around us".
//!
//! # Scenario map
//!
//! | Scenario | Test |
//! |---|---|
//! | 11.1 idempotent install | [`install_is_idempotent_and_records_a_receipt`] |
//! | 11.2 unrelated settings preserved | [`unrelated_user_configuration_survives_install_repair_and_remove`] |
//! | 11.3 / 11.4 secret redacted, placeholder usable | [`the_synthetic_secret_never_reaches_the_provider_and_the_payload_stays_usable`] |
//! | 11.5 no raw secret in any artifact | [`the_raw_secret_is_absent_from_every_artifact_while_the_finding_survives`] |
//! | 11.6 drift in two mechanisms, repaired | [`drift_in_two_mechanisms_is_detected_and_repair_restores_only_owned_state`] |
//! | 11.7 removal restores pre-install state | [`removal_restores_the_pre_install_state_and_leaves_no_artifact`] |
//! | 11.8 level reporting | [`the_ladder_rises_only_on_adjudicated_exercised_evidence`] |
//! | 11.9 core stopped mid-session | [`a_stopped_core_withdraws_the_protection_claim_and_a_restart_restores_it`] |
//! | 11.10 observe-only is never protection | [`observe_only_forwards_the_secret_and_never_claims_protection`] |
//! | 11.11 unmanaged launch is a bypass | [`an_unmanaged_launch_is_unprotected_and_reported_as_a_bypass`] |
//! | C1 CA trust is load-bearing | [`without_the_injected_certificate_authority_protection_cannot_pass`] |
//! | AAASM-5300 adjudicated verification | [`the_shipped_probe_passes_verification_on_an_adjudicated_model_path`] |
//!
//! # Portability
//!
//! Everything above runs on every platform: the adapter, the engine, the
//! receipt store, the proxy, the scanner and the provider are all pure Rust and
//! the tool binary is stood in for by a path plus a version override. The one
//! scenario that needs the real `claude` binary
//! ([`the_real_binary_launched_through_the_installed_environment_is_protected`])
//! prints `SKIP [...]` with the reason and returns, so a skip is visible in the
//! output rather than looking like a pass.
//!
//! There are exactly two things that scenario may decline on — a host that is
//! not macOS, and a host with no `claude`. Past that pair it has **committed to
//! measuring**: a run that then captures no traffic is a failed measurement,
//! not an opt-out, and it fails. Every outcome — measured, skipped, not
//! measured — is also written to the machine-readable ledger described in
//! [`conformance_support::outcome`], because a runner counts a skip as a pass
//! and the summary line alone cannot otherwise distinguish a lane that measured
//! from one that declined to.
//!
//! # Safety
//!
//! See `conformance_support`'s module docs. Every root is an injected temp path,
//! no process-global environment variable is mutated, no keychain operation is
//! performed, and every scenario ends by asserting the developer's real
//! `~/.claude/settings.json` is untouched.

/// The evidence ledger (AAASM-5465), declared once per test binary.
///
/// The support modules re-export it rather than declaring their own, because a
/// binary including two of them would otherwise load the same file twice.
#[path = "evidence/mod.rs"]
pub mod evidence;

#[allow(dead_code, unused_imports)]
mod conformance_support;
#[allow(dead_code, unused_imports)]
mod spike_support;

use std::time::Duration;

use aa_core::integration::{
    EvidenceKind, ExerciseOutcome, ProtectionLevel, ProtectionProfile, ProtectionState, SettingsScope,
    VerificationOutcome,
};
use aa_devtool_claude_code::lifecycle::{CA_ENV_VAR, MANAGED_KEYS, STEP_NODE_EXTRA_CA_CERTS, STEP_PROXY_CA};
use aa_devtool_claude_code::probe::ProtectionProbe as _;
use aa_devtool_claude_code::ProxyAdjudicatedProbe;
use aa_runtime::devint::{ApplyMutation, IntegrationLifecycle};
use conformance_support::{ConformanceHarness, Measurement, SYNTHETIC_SECRET};
use spike_support::proxy_harness::{drive_direct, drive_emulated_client};
use spike_support::{assert_recorded_and_secret_absent, assert_recorded_and_secret_present, AnthropicMock};

/// Unrelated user configuration that must survive every operation.
const USER_THEME: &str = "gruvbox";

// ── 11.1 Clean, idempotent installation ─────────────────────────────────────

/// A plan lists every mutation and puts nothing on disk; the install that
/// follows it records a receipt; a second install changes nothing.
///
/// Idempotence is asserted on the **bytes** of the settings file rather than on
/// a field-by-field JSON compare, because key ordering and serialiser
/// formatting are exactly the class of "no-op" mutation an idempotence claim has
/// to exclude.
#[tokio::test(flavor = "multi_thread")]
async fn install_is_idempotent_and_records_a_receipt() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings(&format!(r#"{{"theme":"{USER_THEME}"}}"#));

    // ── plan ───────────────────────────────────────────────────────────────
    let plan = h.plan(ProtectionProfile::Recommended).await?;
    let rendered = plan.render_dry_run();
    for expected in [
        "settings.json".to_string(),
        "certificate authority".to_string(),
        CA_ENV_VAR.to_string(),
        // The endpoint the launch environment will carry, named in the plan the
        // user approves rather than only in the receipt they never read.
        h.proxy.url(),
        "anthropic.com".to_string(),
    ] {
        assert!(
            rendered.contains(&expected),
            "the plan a user approves must name `{expected}`:\n{rendered}"
        );
    }
    assert!(
        plan.steps.iter().any(|s| s.id.contains(STEP_PROXY_CA))
            && plan.steps.iter().any(|s| s.id.contains(STEP_NODE_EXTRA_CA_CERTS)),
        "condition C1's two halves must both be planned steps: {:?}",
        plan.steps.iter().map(|s| &s.id).collect::<Vec<_>>()
    );
    assert!(
        !h.ca_pem_path().exists() && !h.state().join("store").exists(),
        "a plan is a dry run and must put nothing on disk"
    );
    assert_eq!(
        h.read_settings(),
        serde_json::json!({ "theme": USER_THEME }),
        "a plan must not touch the settings file"
    );

    // ── install ────────────────────────────────────────────────────────────
    let applied = h
        .service()
        .apply(&h.tool(), &plan.plan_id, &h.target())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let receipt = applied.receipt;
    assert_eq!(
        applied.mutation,
        ApplyMutation::Changed,
        "a first install writes the settings file, and the service must say so"
    );
    assert_eq!(receipt.settings_scope, SettingsScope::User);
    assert_eq!(
        receipt.achieved_level,
        ProtectionLevel::Integrated,
        "an apply configures; it does not exercise traffic"
    );
    assert!(
        h.store.receipt_exists(&h.tool(), SettingsScope::User),
        "the install must leave a receipt behind"
    );
    assert!(h.ca_pem_path().is_file(), "condition C1: the CA must be materialised");
    assert_eq!(
        h.injected_env().get(CA_ENV_VAR).map(String::as_str),
        Some(h.ca_pem_path().display().to_string().as_str()),
        "condition C1: NODE_EXTRA_CA_CERTS must point at the materialised CA"
    );
    assert!(
        h.mitm_hosts_path().is_file(),
        "condition C5: the side-channel host list must be written"
    );

    // ── repeat ─────────────────────────────────────────────────────────────
    let before = h.settings_bytes().expect("settings exist after install");
    let reapplied = h.install_reporting(ProtectionProfile::Recommended).await?;
    let again = &reapplied.receipt;
    assert_eq!(
        again.receipt_id, receipt.receipt_id,
        "a no-op reapply is not a new installation"
    );
    // …and reusing the id is precisely why the outcome has to be stated: the
    // two installs are indistinguishable by every field except this one
    // (AAASM-5674).
    assert_eq!(reapplied.mutation, ApplyMutation::Unchanged);
    assert_eq!(
        h.settings_bytes().as_deref(),
        Some(before.as_slice()),
        "the second install mutated the settings file, so install is not idempotent"
    );
    assert!(
        !matches!(h.status().await?.state, ProtectionState::Drifted { .. }),
        "a freshly re-applied install must report no drift"
    );

    h.finish("11.1 idempotent install");
    Ok(())
}

// ── 11.2 Unrelated user configuration preserved ─────────────────────────────

/// User-authored keys survive install, repair and removal, and the install's
/// footprint is exactly the four documented managed keys.
///
/// Pinning the footprint matters as much as preserving the keys: if the adapter
/// grows a fifth managed key without `MANAGED_KEYS` following, this fails rather
/// than silently under-reporting what Agent Assembly owns.
#[tokio::test(flavor = "multi_thread")]
async fn unrelated_user_configuration_survives_install_repair_and_remove() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    let seeded = serde_json::json!({
        "theme": USER_THEME,
        "model": "claude-sonnet-4-5",
        "env": {"USER_AUTHORED": "keep-me"},
        "statusLine": {"type": "command", "command": "echo hi"},
    });
    h.write_settings(&serde_json::to_string_pretty(&seeded)?);
    let before = h.read_settings();

    h.install(ProtectionProfile::Recommended).await?;
    let after_install = h.read_settings();

    for (key, value) in before.as_object().expect("seed is an object") {
        assert_eq!(
            after_install.get(key),
            Some(value),
            "install mutated the user-authored key `{key}`"
        );
    }
    let mut added: Vec<&str> = after_install
        .as_object()
        .expect("object")
        .keys()
        .filter(|k| before.get(k.as_str()).is_none())
        .map(String::as_str)
        .collect();
    added.sort_unstable();
    let mut expected: Vec<&str> = MANAGED_KEYS.to_vec();
    expected.sort_unstable();
    assert_eq!(
        added, expected,
        "the install's settings footprint differs from the documented managed-key set"
    );

    // A key the user adds *after* install is theirs, and repair must not take it.
    let mut doc = h.read_settings();
    doc["editor"] = serde_json::json!("nvim");
    doc["permissions"]["defaultMode"] = serde_json::json!("bypassPermissions");
    h.write_settings(&serde_json::to_string_pretty(&doc)?);
    h.repair().await?;
    let after_repair = h.read_settings();
    assert_eq!(
        after_repair["permissions"]["defaultMode"],
        serde_json::json!("default"),
        "repair did not restore the managed key"
    );
    assert_eq!(
        after_repair["editor"],
        serde_json::json!("nvim"),
        "repair overwrote a user-authored key it does not own"
    );

    // Removal keeps the post-install user change and restores the rest.
    let preview = h.removal_preview().await?;
    h.remove(&preview.plan_id).await?;
    let restored = h.read_settings();
    for (key, value) in before.as_object().expect("object") {
        assert_eq!(
            restored.get(key),
            Some(value),
            "removal did not restore the user-authored key `{key}`"
        );
    }
    assert_eq!(
        restored["editor"],
        serde_json::json!("nvim"),
        "removal discarded a change the user made after install"
    );
    for key in MANAGED_KEYS {
        assert!(
            restored.get(key).is_none(),
            "removal left the Agent Assembly-owned key `{key}` behind: {restored}"
        );
    }

    h.finish("11.2 unrelated user configuration preserved");
    Ok(())
}

// ── 11.7 Removal ────────────────────────────────────────────────────────────

/// Removal restores the pre-install state, leaves no Agent Assembly artifact,
/// and a repeat removal is refused rather than half-performed.
///
/// The restore is asserted as **semantics-exact, not byte-exact**: AAASM-5276
/// condition C3 measured that the settings document is reserialised on write, so
/// a user file in non-canonical formatting cannot survive a cycle byte-for-byte
/// however good the receipt is. That is an accepted, stated constraint — see
/// `spike_claude_code_lifecycle::scenario_11_7_byte_exact_restore_fails_for_non_canonical_formatting`,
/// which pins it as a limitation so a future content-preserving writer inverts a
/// failing test rather than quietly changing an implied guarantee.
#[tokio::test(flavor = "multi_thread")]
async fn removal_restores_the_pre_install_state_and_leaves_no_artifact() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings(&serde_json::to_string_pretty(&serde_json::json!({
        "theme": USER_THEME,
        "statusLine": {"type": "command", "command": "echo hi"},
    }))?);
    let before = h.read_settings();

    h.install(ProtectionProfile::Recommended).await?;
    assert!(h.ca_pem_path().is_file());
    assert!(h.mitm_hosts_path().is_file());
    assert!(h.injected_env().contains_key(CA_ENV_VAR));

    // A preview must show the work without doing any of it.
    let preview = h.removal_preview().await?;
    assert!(!preview.steps.is_empty(), "the preview must show what will be undone");
    let previewed = preview.render_dry_run();
    assert!(previewed.contains(CA_ENV_VAR), "{previewed}");
    assert!(previewed.contains("certificate authority"), "{previewed}");
    assert!(
        h.ca_pem_path().is_file(),
        "a preview must not remove anything: {previewed}"
    );

    let removal = h.remove(&preview.plan_id).await?;
    assert!(
        removal.residual.is_empty(),
        "removal reported something left behind: {:?}",
        removal.residual
    );
    assert!(!h.ca_pem_path().exists(), "the copied certificate authority survived");
    assert!(!h.mitm_hosts_path().exists(), "the MitM host list survived");
    assert!(
        !h.injected_env().contains_key(CA_ENV_VAR),
        "removal must stop injecting the CA variable"
    );
    assert_eq!(
        h.read_settings(),
        before,
        "the post-removal settings document is not what was there before the install"
    );
    // Nothing Agent Assembly wrote may survive anywhere under the state root.
    let residue: Vec<String> = conformance_support::walk(h.state())
        .into_iter()
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        residue.is_empty(),
        "removal left Agent Assembly-owned files behind: {residue:?}"
    );

    // A second removal has nothing to act on and says so, rather than
    // half-performing a reversal against a receipt that no longer exists.
    assert!(
        h.service().remove(&h.tool(), &h.target(), None).await.is_err(),
        "a repeated removal must be refused, not silently repeated"
    );

    h.finish("11.7 removal restores pre-install state");
    Ok(())
}

/// A settings file that held nothing but `{}` before the install is **deleted**
/// by removal rather than restored to `{}`.
///
/// Pinned because it is a deliberate decision with a visible consequence: the
/// engine cannot distinguish "the user had an empty settings file" from "Agent
/// Assembly created this file", and chooses to leave nothing behind. That is the
/// right default for a removal guarantee, and it is the kind of behaviour that
/// must not change without someone noticing.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_settings_file_is_removed_rather_than_left_as_an_artifact() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;
    assert!(h.settings_path().is_file());

    let preview = h.removal_preview().await?;
    h.remove(&preview.plan_id).await?;
    assert!(
        !h.settings_path().exists(),
        "a document holding only Agent Assembly's keys must not be left behind as an empty artifact"
    );

    h.finish("11.7 empty settings document");
    Ok(())
}

// ── 11.9 Runtime failure and recovery ───────────────────────────────────────

/// Stopping the core withdraws the protection claim; restarting it lets a fresh
/// verification restore the claim.
///
/// The endpoint is the same across the restart on purpose: recovery means the
/// *installed* integration works again, and coming back on a different address
/// would be a reinstall dressed up as a recovery.
#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_core_withdraws_the_protection_claim_and_a_restart_restores_it() -> anyhow::Result<()> {
    let mut h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    assert_eq!(h.verify().await?.outcome, VerificationOutcome::Passed);
    assert_eq!(h.status().await?.achieved_level(), ProtectionLevel::GatewayProtected);

    // ── stop ───────────────────────────────────────────────────────────────
    let stopped_at = std::time::Instant::now();
    h.proxy.stop();
    let mut detected = None;
    for _ in 0..200 {
        if !h.proxy.is_reachable().await {
            detected = Some(stopped_at.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let detected = detected.expect("the core must stop accepting connections after stop()");
    println!("MEASURED: core-stop to connections-refused = {detected:?}");

    let after_stop = h.verify().await?;
    assert!(
        !matches!(after_stop.outcome, VerificationOutcome::Passed),
        "a verification against a dead core must not pass: {:?}",
        after_stop.outcome
    );
    let degraded = h.status().await?;
    assert!(
        degraded.achieved_level() < ProtectionLevel::GatewayProtected,
        "a stopped core must withdraw the protection claim, got {:?}",
        degraded.state
    );
    let rendered = serde_json::to_string(&degraded)?.to_lowercase();
    assert!(
        !rendered.contains("\"unknown\""),
        "the state must be reported, never degraded to `unknown`: {rendered}"
    );

    // ── restart ────────────────────────────────────────────────────────────
    h.proxy.restart().await?;
    assert!(h.proxy.is_reachable().await, "the core did not come back");
    let recovered = h.verify().await?;
    assert_eq!(
        recovered.outcome,
        VerificationOutcome::Passed,
        "recovery after a runtime restart must be possible without a reinstall: {:?}",
        recovered.outcome
    );
    assert_eq!(
        h.status().await?.achieved_level(),
        ProtectionLevel::GatewayProtected,
        "the claim must return once the evidence does"
    );

    h.finish("11.9 runtime failure and recovery");
    Ok(())
}

// ── 11.8 Level reporting ────────────────────────────────────────────────────

/// Three readings must be distinguishable, and only the third may claim
/// sensitive-data protection.
///
/// (a) applied but never exercised, (b) exercised and adjudicated, and in both
/// cases (c) host enforcement reported as unreachable rather than omitted.
#[tokio::test(flavor = "multi_thread")]
async fn the_ladder_rises_only_on_adjudicated_exercised_evidence() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    // (a) Configuration applied and readable back — and that is all.
    let configured = h.status().await?;
    assert!(
        !configured.has_exercised_evidence(),
        "configuration alone must never look like traffic evidence"
    );
    assert!(
        configured.achieved_level() < ProtectionLevel::GatewayProtected,
        "a never-exercised installation must not claim protection: {:?}",
        configured.state
    );
    match &configured.state {
        ProtectionState::Degraded { planned, achieved, .. } => {
            assert_eq!(*planned, ProtectionLevel::GatewayProtected);
            assert_eq!(*achieved, ProtectionLevel::Integrated);
        }
        other => panic!("expected a Degraded reading immediately after install, got {other:?}"),
    }
    assert!(configured.next_level.is_some(), "the rung above must always be named");

    // (b) Traffic exercised and adjudicated by the provider.
    let verification = h.verify().await?;
    assert_eq!(verification.outcome, VerificationOutcome::Passed);
    assert!(verification.has_exercised_evidence());
    assert!(
        h.upstream.request_count() > 0,
        "the provider must have recorded a request, or the adjudication is vacuous"
    );
    let exercised = h.status().await?;
    assert_eq!(exercised.achieved_level(), ProtectionLevel::GatewayProtected);
    assert!(
        exercised.exercised_evidence().next().is_some() && exercised.read_back_evidence().next().is_some(),
        "the report must separate exercised evidence from read-back evidence"
    );

    // (c) Host enforcement is never omitted.
    for status in [&configured, &exercised] {
        let json = serde_json::to_string(status)?;
        assert!(
            json.contains("HostEnforcement"),
            "the unreachable rung must be reported, not omitted: {json}"
        );
        assert!(
            json.contains("host enforcement is not active"),
            "the reason host enforcement is not active must be stated, not implied: {json}"
        );
        assert!(
            json.contains("--install-managed-settings"),
            "the reason must name the opt-in that would change it: {json}"
        );
    }

    h.finish("11.8 protection-level reporting");
    Ok(())
}

/// The `ExerciseOutcome` vocabulary is what the ladder is derived from, so the
/// three outcomes must stay distinguishable and only one may be protective.
#[test]
fn only_a_redacted_outcome_is_protective() {
    assert!(ExerciseOutcome::Redacted.is_protective());
    assert!(!ExerciseOutcome::Leaked.is_protective());
    assert!(
        !ExerciseOutcome::Inconclusive.is_protective(),
        "an unadjudicated probe must never read as protection"
    );
}

// ── 11.3 / 11.4 The secret never reaches the provider ───────────────────────

/// Drive secret-bearing traffic through the artifacts the **install** produced —
/// the receipted endpoint and the materialised certificate authority — and
/// assert the provider recorded traffic and never saw the raw value, while the
/// forwarded payload stays a request the provider can serve.
///
/// The client is built from `h.ca_pem_path()` rather than from the proxy's own
/// directory on purpose: that file is the artifact `NODE_EXTRA_CA_CERTS` points
/// at, so a copy step that silently produced the wrong bytes fails here instead
/// of passing on a certificate the tool would never have seen.
#[tokio::test(flavor = "multi_thread")]
async fn the_synthetic_secret_never_reaches_the_provider_and_the_payload_stays_usable() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    let endpoint = h
        .injected_env()
        .get("HTTPS_PROXY")
        .cloned()
        .expect("the install must inject HTTPS_PROXY");
    let addr: std::net::SocketAddr = endpoint
        .trim_start_matches("http://")
        .parse()
        .expect("the injected endpoint must be dialable");
    let client = std::sync::Arc::new(client_trusting(&h.ca_pem_path()).await?);

    let prompt = format!("Please review this config line: ANTHROPIC_API_KEY={SYNTHETIC_SECRET} and explain it.");
    let result = drive_emulated_client(addr, client, &prompt).await?;
    assert!(
        result.connected(),
        "CONNECT through the installed endpoint failed: {}",
        result.connect_status
    );

    // 11.3 — the load-bearing clause first: traffic actually flowed.
    let observed = h.upstream.wait_for_requests(1, Duration::from_secs(10)).await;
    assert_eq!(
        observed, 1,
        "the provider recorded no request, so `no raw secret arrived` would prove nothing"
    );
    assert_recorded_and_secret_absent(&h.upstream.bodies(), SYNTHETIC_SECRET, "11.3 installed model path");

    // 11.4 — the payload the provider got is still one it can serve.
    let forwarded = h.upstream.last_body().expect("forwarded body is utf-8");
    assert!(
        forwarded.contains("[REDACTED:AnthropicKey]"),
        "the forwarded payload lacks the semantics-preserving placeholder: {forwarded}"
    );
    assert!(
        forwarded.contains("Please review this config line:") && forwarded.contains("and explain it."),
        "redaction damaged the surrounding content: {forwarded}"
    );
    serde_json::from_str::<serde_json::Value>(&forwarded)
        .expect("11.4: the redacted body must still be JSON the provider can parse");
    assert_eq!(
        h.upstream.request_lines(),
        vec![("POST".to_owned(), "/v1/messages".to_owned())],
    );
    assert!(
        h.upstream.last_header_names().contains(&"anthropic-version".to_owned()),
        "provider-required headers were dropped in transit: {:?}",
        h.upstream.last_header_names()
    );
    assert!(
        result.inner_response.as_deref().unwrap_or_default().contains("200"),
        "the session did not continue: {:?}",
        result.inner_response
    );

    h.finish("11.3/11.4 secret redacted before the provider");
    Ok(())
}

// ── Tool governance ─────────────────────────────────────────────────────────

/// The profile a user chooses changes what the tool is allowed to do without
/// asking, and re-enabling the mode the install displaced is detected.
///
/// Claude Code expresses "approval required" as `permissions.defaultMode:
/// "plan"` — propose rather than act — which is the closest native equivalent of
/// an approval gate for destructive classes. `Recommended` writes `"default"`,
/// `Strict` writes `"plan"`, and both carry the MCP allow/deny lists, so a
/// governance path is exercised in each of the allow, deny and approval
/// directions.
#[tokio::test(flavor = "multi_thread")]
async fn the_profile_selects_the_tool_action_governance_the_install_writes() -> anyhow::Result<()> {
    for (profile, expected_mode) in [
        (ProtectionProfile::Recommended, "default"),
        (ProtectionProfile::Strict, "plan"),
    ] {
        let h = ConformanceHarness::start().await?;
        h.write_settings("{}");
        h.install(profile).await?;

        let settings = h.read_settings();
        assert_eq!(
            settings["permissions"]["defaultMode"],
            serde_json::json!(expected_mode),
            "{profile:?} must resolve to the `{expected_mode}` action-governance mode: {settings}"
        );
        assert_eq!(
            settings["permissionMode"],
            serde_json::json!(expected_mode),
            "the two surfaces Claude Code reads must agree: {settings}"
        );
        // The allow and deny halves both exist, so a policy has somewhere to
        // land in each direction rather than one being implicit.
        assert!(
            settings["permissions"]["allow"].is_array() && settings["permissions"]["deny"].is_array(),
            "both governance directions must be present: {settings}"
        );
        assert!(
            settings["enabledMcpjsonServers"].is_array() && settings["disabledMcpjsonServers"].is_array(),
            "MCP governance must be written in both directions: {settings}"
        );

        // Re-enabling the bypass mode the install displaced must be visible.
        let mut doc = h.read_settings();
        doc["permissions"]["defaultMode"] = serde_json::json!("bypassPermissions");
        h.write_settings(&serde_json::to_string_pretty(&doc)?);
        let status = h.status().await?;
        let rendered = serde_json::to_string(&status)?;
        assert!(
            rendered.contains("bypassPermissions"),
            "a re-enabled bypass must reach the status a user reads: {rendered}"
        );
        let verification = h.verify().await?;
        assert!(
            !matches!(verification.outcome, VerificationOutcome::Passed),
            "verification must not pass while a known bypass is active: {:?}",
            verification.outcome
        );

        h.finish("tool-action governance");
    }
    Ok(())
}

// ── 11.6 Drift in two mechanisms, repaired ──────────────────────────────────

/// Two independent Agent Assembly-owned mechanisms are perturbed; both are
/// reported; repair restores both and touches nothing else; a subsequent
/// verification re-exercises protection rather than reading configuration back.
///
/// A user-authored key is perturbed **in the same edit** as the managed one.
/// Asserting only that the managed key came back would not distinguish a correct
/// repair from one that rewrote the whole file from the receipt.
#[tokio::test(flavor = "multi_thread")]
async fn drift_in_two_mechanisms_is_detected_and_repair_restores_only_owned_state() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings(&format!(r#"{{"theme":"{USER_THEME}"}}"#));
    h.install(ProtectionProfile::Recommended).await?;
    assert_eq!(h.verify().await?.outcome, VerificationOutcome::Passed);
    assert_eq!(h.status().await?.achieved_level(), ProtectionLevel::GatewayProtected);

    // Mechanism 1 — an Agent Assembly-owned settings key, edited by hand
    // alongside a key of the user's own.
    let mut doc = h.read_settings();
    doc["permissions"]["defaultMode"] = serde_json::json!("bypassPermissions");
    doc["theme"] = serde_json::json!("edited-by-the-user");
    h.write_settings(&serde_json::to_string_pretty(&doc)?);

    // Mechanism 2 — the trust material condition C1 depends on, deleted.
    std::fs::remove_file(h.ca_pem_path())?;

    let drifted = h.status().await?;
    let mismatched = match &drifted.state {
        ProtectionState::Drifted { mismatched, .. } => mismatched.clone(),
        other => panic!("two perturbed mechanisms must read as Drifted, got {other:?}"),
    };
    assert!(
        mismatched.len() >= 2,
        "drift must be reported per mechanism, not collapsed into one finding: {mismatched:?}"
    );
    let joined = mismatched.join(" ");
    assert!(
        joined.contains("settings.json") && joined.contains("aasm-proxy-ca.pem"),
        "both perturbed mechanisms must be named: {mismatched:?}"
    );
    assert!(
        drifted.achieved_level() < ProtectionLevel::GatewayProtected
            || !matches!(drifted.state, ProtectionState::Ladder(_)),
        "the reported level must drop before repair is attempted: {:?}",
        drifted.state
    );

    // ── repair ─────────────────────────────────────────────────────────────
    let (report, repaired) = h.repair().await?;
    assert!(!report.repaired.is_empty(), "repair must name what it restored");
    assert!(
        !matches!(repaired.state, ProtectionState::Drifted { .. }),
        "drift persists after repair: {:?}",
        repaired.state
    );
    assert!(h.ca_pem_path().is_file(), "repair did not restore the trust material");
    let after = h.read_settings();
    assert_eq!(after["permissions"]["defaultMode"], serde_json::json!("default"));
    assert_eq!(
        after["theme"],
        serde_json::json!("edited-by-the-user"),
        "repair overwrote a user-authored key it does not own"
    );

    // ── re-verify ──────────────────────────────────────────────────────────
    let before_requests = h.upstream.request_count();
    assert_eq!(h.verify().await?.outcome, VerificationOutcome::Passed);
    assert!(
        h.upstream.request_count() > before_requests,
        "a verification after repair must re-exercise the path, not read configuration back"
    );
    assert_eq!(h.status().await?.achieved_level(), ProtectionLevel::GatewayProtected);

    h.finish("11.6 drift detected and repaired");
    Ok(())
}

// ── 11.10 Observe-only never reads as protection ────────────────────────────

/// Under the observe-only profile the provider **does** receive the synthetic
/// value, and no reading may call that protection.
///
/// Asserted positively, and deliberately so: the profile that does not protect
/// must not be able to look like the one that does. If this ever starts failing
/// because the secret was redacted, the profile has stopped being observe-only.
#[tokio::test(flavor = "multi_thread")]
async fn observe_only_forwards_the_secret_and_never_claims_protection() -> anyhow::Result<()> {
    let h = ConformanceHarness::with_options(conformance_support::HarnessOptions {
        // `EnforcementMode::Observe` maps onto the proxy's `AlertOnly` action:
        // findings are computed and audited, the body is forwarded intact.
        credential_action: aa_proxy::config::CredentialAction::AlertOnly,
        ..Default::default()
    })
    .await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::ObserveOnly).await?;

    let verification = h.verify().await?;
    assert!(
        h.upstream.request_count() > 0,
        "the probe must have produced traffic for this scenario to mean anything"
    );
    assert_recorded_and_secret_present(&h.upstream.bodies(), SYNTHETIC_SECRET, "11.10 observe-only");
    assert!(
        !matches!(verification.outcome, VerificationOutcome::Passed),
        "a forwarded credential must never read as a passed protection test: {:?}",
        verification.outcome
    );

    let status = h.status().await?;
    assert!(
        status.achieved_level() < ProtectionLevel::GatewayProtected,
        "observe-only must never reach GatewayProtected, even with exercised evidence: {:?}",
        status.state
    );

    h.finish("11.10 observe-only is not protection");
    Ok(())
}

// ── 11.11 Unmanaged launch is a bypass ──────────────────────────────────────

/// A session that never goes through the managed path is unprotected, and the
/// product says so as a bypass rather than as its own failure.
#[tokio::test(flavor = "multi_thread")]
async fn an_unmanaged_launch_is_unprotected_and_reported_as_a_bypass() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    let plan = h.plan(ProtectionProfile::Recommended).await?;
    h.service()
        .apply(&h.tool(), &plan.plan_id, &h.target())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // The integration is installed; this session simply does not use it.
    let mock = AnthropicMock::start().await?;
    drive_direct(&mock.url, &format!("unmanaged launch carrying {SYNTHETIC_SECRET}")).await?;
    assert_eq!(mock.wait_for_requests(1, Duration::from_secs(5)).await, 1);
    assert_recorded_and_secret_present(&mock.bodies(), SYNTHETIC_SECRET, "11.11 unmanaged launch");

    // The plan a user approves states it, in the warning a user reads before
    // consenting rather than in a document they may never open.
    let warnings = plan.warnings.join("\n");
    assert!(
        warnings.contains("is not protected") && warnings.contains("aasm run claude"),
        "the plan must state that a direct launch is unprotected: {warnings}"
    );

    // And the installed state, having never been exercised, claims nothing.
    let status = h.status().await?;
    assert!(
        !status.has_exercised_evidence() && status.achieved_level() < ProtectionLevel::GatewayProtected,
        "an installation that has never been exercised must not claim protection: {:?}",
        status.state
    );
    let rendered = serde_json::to_string(&status)?;
    assert!(
        rendered.contains("known bypasses this integration cannot observe"),
        "status must distinguish what it cannot see from what it has disproved: {rendered}"
    );

    h.finish("11.11 unmanaged launch is a bypass");
    Ok(())
}

// ── Upgrade and incompatibility ─────────────────────────────────────────────

/// Upgrading the tool under an existing installation is a migration, not drift;
/// a version below the adapter's floor is refused rather than integrated.
///
/// Both halves matter. A tool upgrade that read as drift would send users to
/// `repair` for nothing; an unsupported version that installed anyway would
/// produce a receipt for an integration whose mechanisms were never validated.
#[tokio::test(flavor = "multi_thread")]
async fn a_tool_upgrade_is_a_migration_and_an_unsupported_version_is_refused() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings(&format!(r#"{{"theme":"{USER_THEME}"}}"#));
    let receipt = h.install(ProtectionProfile::Recommended).await?;
    assert_eq!(
        receipt.tool_version.as_ref().map(ToString::to_string).as_deref(),
        Some(conformance_support::MEASURED_TOOL_VERSION),
        "the receipt must record the version it was applied against"
    );

    // ── migration ──────────────────────────────────────────────────────────
    let upgraded = h.service_reporting_version("3.4.5");
    let status = upgraded
        .status(&h.tool(), &h.target())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(
        status.compatibility.is_compatible(),
        "a newer tool inside the supported range must stay compatible: {:?}",
        status.compatibility
    );
    assert!(
        !matches!(status.state, ProtectionState::Drifted { .. }),
        "a tool upgrade is not configuration drift: {:?}",
        status.state
    );

    // ── incompatibility ────────────────────────────────────────────────────
    let too_old = h.service_reporting_version("0.9.9");
    let refused = too_old
        .plan(
            aa_core::integration::IntegrationRequest::new(
                h.tool(),
                ProtectionProfile::Recommended,
                SettingsScope::User,
            )
            .with_user_config_home(h.user_config_home()),
        )
        .await;
    assert!(
        refused.is_err(),
        "a version below the adapter's floor must not produce an appliable plan"
    );
    let unsupported_status = too_old
        .status(&h.tool(), &h.target())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(
        !unsupported_status.compatibility.is_compatible(),
        "an undetectable version must never resolve upward to compatible: {:?}",
        unsupported_status.compatibility
    );
    assert!(
        unsupported_status.achieved_level() < ProtectionLevel::GatewayProtected,
        "an unsupported tool version must not carry a protection claim: {:?}",
        unsupported_status.state
    );

    h.finish("upgrade and incompatibility");
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// Security regressions
//
// This set exists to fail loudly on the five ways this integration could look
// healthy while being unsafe: a raw secret reaching a persisted or printed
// surface, a protection claim without exercised evidence, a repair reaching
// into a key the user owns, a removal leaving an Agent Assembly artifact
// behind, and condition C1 silently coming un-wired.
// ════════════════════════════════════════════════════════════════════════════

// ── 11.5 The raw secret reaches no artifact ─────────────────────────────────

/// Collect everything one protected run produces — the proxy's audit entries,
/// the verification result, the status, every file under the state root and the
/// settings document — and assert the raw value is in none of them **while** the
/// finding metadata survives.
///
/// The second half is what separates "detected and redacted" from "never seen".
/// An artifact set carrying neither the secret nor any finding would satisfy a
/// naive absence check while proving the scanner never ran.
#[tokio::test(flavor = "multi_thread")]
async fn the_raw_secret_is_absent_from_every_artifact_while_the_finding_survives() -> anyhow::Result<()> {
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(64);
    let h = ConformanceHarness::with_options(conformance_support::HarnessOptions {
        audit_tx: Some(audit_tx),
        ..Default::default()
    })
    .await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    let verification = h.verify().await?;
    assert_eq!(verification.outcome, VerificationOutcome::Passed);
    let status = h.status().await?;
    assert!(
        h.upstream.request_count() > 0,
        "traffic must have flowed for an absence assertion to mean anything"
    );

    let mut audit_entries = Vec::new();
    while let Ok(entry) = audit_rx.try_recv() {
        audit_entries.push(entry);
    }
    assert!(!audit_entries.is_empty(), "the proxy produced no audit entries");
    let audit_json = serde_json::to_string(&audit_entries)?;

    let mut surfaces = h.persisted_surfaces();
    surfaces.push(("proxy-audit".to_string(), audit_json.clone()));
    surfaces.push(("verification".to_string(), serde_json::to_string(&verification)?));
    surfaces.push(("status".to_string(), serde_json::to_string(&status)?));
    surfaces.push(("status-rendered".to_string(), format!("{status:?}")));
    conformance_support::assert_no_raw_secret(&surfaces, SYNTHETIC_SECRET, "11.5");

    // The finding must still be there: kind and count, never the value.
    let findings: usize = audit_entries.iter().map(|e| e.credential_findings.len()).sum();
    assert!(
        findings > 0,
        "the audit recorded zero findings — the scanner never detected anything"
    );
    assert!(
        audit_json.contains("AnthropicKey"),
        "the audit does not name the detected credential kind: {audit_json}"
    );
    let evidence = serde_json::to_string(&verification.evidence)?;
    assert!(
        evidence.to_lowercase().contains("redacted"),
        "the adjudicated outcome must survive into the evidence: {evidence}"
    );
    println!(
        "MEASURED: {findings} finding(s) across {} audit entries",
        audit_entries.len()
    );

    h.finish("11.5 no raw secret in any artifact");
    Ok(())
}

// ── C1 The injected certificate authority is load-bearing ───────────────────

/// Identical to a passing run in every respect but one: the probe does not trust
/// the certificate authority the install materialised and `NODE_EXTRA_CA_CERTS`
/// points at.
///
/// AAASM-5276 condition C1 is the single highest-value item in the whole Epic —
/// without it the MitM handshake fails, nothing is inspected, and the headline
/// protection claim is a no-op. This pins it so a future change cannot silently
/// un-inject the CA and still look green: the reading must be a *failed TLS
/// handshake*, not a pass and not a generic error.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_injected_certificate_authority_protection_cannot_pass() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    // Establish the baseline: with trust, this run passes.
    assert_eq!(h.verify().await?.outcome, VerificationOutcome::Passed);
    assert_eq!(h.status().await?.achieved_level(), ProtectionLevel::GatewayProtected);

    // Turn the one variable.
    h.set_ca_trust(false);
    let untrusted = h.verify().await?;
    assert!(
        !matches!(untrusted.outcome, VerificationOutcome::Passed),
        "a failed MitM handshake must not read as a pass: {:?}",
        untrusted.outcome
    );
    let reason = format!("{:?}", untrusted.outcome);
    assert!(
        reason.contains("certificate was not trusted"),
        "the reading must name the CA-trust failure, so a regression is diagnosable rather than \
         merely red: {reason}"
    );
    let status = h.status().await?;
    assert!(
        status.achieved_level() < ProtectionLevel::GatewayProtected,
        "with the CA untrusted the model path is not intercepted, so protection must not be \
         claimed: {:?}",
        status.state
    );

    h.finish("C1 injected certificate authority");
    Ok(())
}

// ── A tampered receipt fails safely ─────────────────────────────────────────

/// Editing a receipt in place breaks its integrity hash, and every lifecycle
/// operation refuses rather than acting on it.
///
/// A corrupt receipt must never be reported as "not installed": that reading
/// would invite an install on top of state nobody can account for. It must also
/// never be reported as protected — a receipt is the only record of what was
/// applied, and one that cannot be trusted cannot substantiate a claim.
#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_receipt_is_refused_rather_than_believed() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;
    assert_eq!(h.verify().await?.outcome, VerificationOutcome::Passed);

    // Forge freshness without touching the integrity hash: move the recorded
    // verification far into the future so a status read would answer "verified
    // now" for evidence that is nothing of the sort. That is the exact class of
    // edit a receipt hash exists to catch.
    let path = h.store.receipt_path(&h.tool(), SettingsScope::User);
    let mut envelope: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let recorded = envelope["receipt"]["verified_at_unix_secs"]
        .as_u64()
        .expect("precondition: a passing verification recorded its timestamp");
    envelope["receipt"]["verified_at_unix_secs"] = serde_json::json!(recorded + 86_400 * 365);
    std::fs::write(&path, serde_json::to_string_pretty(&envelope)?)?;

    for (operation, result) in [
        ("status", h.status().await.err()),
        ("verify", h.verify().await.err()),
        ("repair", h.repair().await.err().map(|e| anyhow::anyhow!("{e}"))),
        ("remove", h.removal_preview().await.err()),
    ] {
        let error = result.unwrap_or_else(|| panic!("`{operation}` accepted a forged receipt"));
        let message = error.to_string();
        assert!(
            message.contains("receipt"),
            "`{operation}` must say the receipt is the problem: {message}"
        );
    }

    h.finish("tampered receipt");
    Ok(())
}

// ── An unscoped client cannot perform lifecycle operations ──────────────────

/// A read-only capability token can see the integration and cannot change it,
/// and a token scoped to a different tool cannot touch this one.
///
/// Asserted over a **real** DI-API socket rather than against the scope
/// predicate, because the property under test belongs to the served surface: a
/// check that exists but is not consulted by a handler would pass a unit test on
/// the predicate and fail here.
#[tokio::test(flavor = "multi_thread")]
async fn an_unscoped_client_cannot_drive_the_lifecycle() -> anyhow::Result<()> {
    use aa_runtime::devint::{
        DevIntClient, DevIntServer, DevIntServerConfig, DevIntServices, TargetRequest, TokenScope, TokenStore,
        ToolScope,
    };

    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;
    // Mandatory at user scope now that the service no longer infers it from
    // its own environment (AAASM-5957) — including for an unspecified scope,
    // which may turn out to be the user-scope installation this harness set
    // up above.
    let home = h.user_config_home().to_str().expect("utf-8 tempdir").to_string();

    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("devint.sock");
    let tokens = TokenStore::new();
    let now = aa_core::integration::now_unix_secs();
    // A dashboard-shaped client: it may look, and may change nothing.
    let (read_only, _) = tokens.issue(
        "conformance-read-only",
        TokenScope::read_only(ToolScope::tools(["claude-code"])),
        now,
        3600,
    );
    // A full-lifecycle client for a *different* tool: the blast radius of a
    // stolen per-tool token must stop at that tool.
    let (other_tool, _) = tokens.issue(
        "conformance-other-tool",
        TokenScope::full_lifecycle(ToolScope::tools(["codex"])),
        now,
        3600,
    );

    let services = DevIntServices::new(
        std::sync::Arc::new(h.service_reporting_version(conformance_support::MEASURED_TOOL_VERSION)),
        tokens,
        std::sync::Arc::new(aa_runtime::devint::audit::TracingAuditSink),
    );
    let shutdown = tokio_util::sync::CancellationToken::new();
    let server_token = shutdown.clone();
    let config = DevIntServerConfig {
        socket_path: socket.clone(),
        max_connections: 8,
    };
    let server = DevIntServer::bind(config)?;
    let tracker = tokio_util::task::TaskTracker::new();
    let serving = tokio::spawn({
        let tracker = tracker.clone();
        async move {
            server.run(tracker.clone(), server_token, services).await;
            tracker.close();
            tracker.wait().await;
        }
    });

    for (label, token) in [("read-only", &read_only), ("other-tool", &other_tool)] {
        let mut client = DevIntClient::connect(
            &socket,
            "conformance",
            env!("CARGO_PKG_VERSION"),
            Some(token.expose().to_string()),
        )
        .await?;
        for (verb, outcome) in [
            (
                "plan",
                client
                    .plan(aa_runtime::devint::PlanRequest {
                        tool_id: "claude-code",
                        profile: "recommended",
                        settings_scope: "user",
                        user_config_home: &home,
                        ..Default::default()
                    })
                    .await
                    .err(),
            ),
            (
                "apply",
                client
                    .apply(
                        "claude-code",
                        "any-plan",
                        TargetRequest {
                            user_config_home: &home,
                            ..TargetRequest::default()
                        },
                    )
                    .await
                    .err(),
            ),
            (
                "repair",
                client
                    .repair(
                        "claude-code",
                        TargetRequest {
                            user_config_home: &home,
                            ..TargetRequest::default()
                        },
                    )
                    .await
                    .err(),
            ),
            (
                "remove",
                client
                    .remove(
                        "claude-code",
                        "any-plan",
                        TargetRequest {
                            user_config_home: &home,
                            ..TargetRequest::default()
                        },
                    )
                    .await
                    .err(),
            ),
        ] {
            assert!(outcome.is_some(), "the {label} token performed `{verb}` on claude-code");
        }
    }

    // The read-only token can still do the thing it is for; the other tool's
    // token cannot even look.
    let mut reader = DevIntClient::connect(
        &socket,
        "conformance",
        env!("CARGO_PKG_VERSION"),
        Some(read_only.expose().to_string()),
    )
    .await?;
    assert!(
        reader
            .status(
                "claude-code",
                TargetRequest {
                    user_config_home: &home,
                    ..TargetRequest::default()
                },
            )
            .await
            .is_ok(),
        "a read-only token must still be able to read status"
    );
    let mut stranger = DevIntClient::connect(
        &socket,
        "conformance",
        env!("CARGO_PKG_VERSION"),
        Some(other_tool.expose().to_string()),
    )
    .await?;
    assert!(
        stranger
            .status(
                "claude-code",
                TargetRequest {
                    user_config_home: &home,
                    ..TargetRequest::default()
                },
            )
            .await
            .is_err(),
        "a token scoped to another tool must not read this one's status"
    );

    // A connection with no token at all is denied every verb, with no anonymous
    // tier to fall back to.
    let mut anonymous = DevIntClient::connect(&socket, "conformance", env!("CARGO_PKG_VERSION"), None).await?;
    assert!(anonymous
        .status(
            "claude-code",
            TargetRequest {
                user_config_home: &home,
                ..TargetRequest::default()
            },
        )
        .await
        .is_err());
    assert!(anonymous
        .repair(
            "claude-code",
            TargetRequest {
                user_config_home: &home,
                ..TargetRequest::default()
            },
        )
        .await
        .is_err());

    shutdown.cancel();
    let _ = serving.await;
    h.finish("unscoped client");
    Ok(())
}

// ── Repair must not reach into a key the user owns ──────────────────────────

/// The isolated repair guard: every managed key is drifted at once, alongside a
/// user-authored key with a value repair might plausibly overwrite.
///
/// Kept separate from the drift scenario so its failure message says exactly one
/// thing. A repair that rewrote the document from the receipt would restore the
/// managed keys correctly and still fail here.
#[tokio::test(flavor = "multi_thread")]
async fn repair_restores_every_managed_key_and_touches_no_user_key() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    let user_keys = serde_json::json!({
        "theme": USER_THEME,
        "model": "claude-opus-4-1",
        "env": {"USER_AUTHORED": "keep-me"},
        "statusLine": {"type": "command", "command": "echo hi"},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]},
    });
    h.write_settings(&serde_json::to_string_pretty(&user_keys)?);
    h.install(ProtectionProfile::Recommended).await?;

    // Drift every managed key, and move every user key to a different value in
    // the same write.
    let mut doc = h.read_settings();
    doc["permissions"] = serde_json::json!({"allow": ["Bash"], "deny": [], "defaultMode": "bypassPermissions"});
    doc["permissionMode"] = serde_json::json!("bypassPermissions");
    doc["enabledMcpjsonServers"] = serde_json::json!(["everything"]);
    doc["disabledMcpjsonServers"] = serde_json::json!(["nothing"]);
    for key in ["theme", "model"] {
        doc[key] = serde_json::json!("user-changed-this-after-install");
    }
    doc["env"]["USER_AUTHORED"] = serde_json::json!("user-changed-this-too");
    h.write_settings(&serde_json::to_string_pretty(&doc)?);
    let perturbed = h.read_settings();

    h.repair().await?;
    let repaired = h.read_settings();

    for key in MANAGED_KEYS {
        assert_ne!(
            repaired[key], perturbed[key],
            "repair left the drifted managed key `{key}` as the user set it"
        );
    }
    assert_eq!(repaired["permissionMode"], serde_json::json!("default"));
    for key in ["theme", "model"] {
        assert_eq!(
            repaired[key], perturbed[key],
            "repair overwrote the user-authored key `{key}`, which Agent Assembly does not own"
        );
    }
    assert_eq!(
        repaired["env"]["USER_AUTHORED"],
        serde_json::json!("user-changed-this-too"),
        "repair reached into a nested user-authored value"
    );
    assert_eq!(
        repaired["statusLine"], perturbed["statusLine"],
        "repair mutated an untouched user-authored key"
    );
    assert_eq!(repaired["hooks"], perturbed["hooks"], "repair mutated the user's hooks");

    h.finish("repair touches only owned state");
    Ok(())
}

// ── What now observes the forwarded payload (AAASM-5300) ────────────────────
//
// AAASM-5283 shipped a scenario here named
// `the_shipped_probe_cannot_pass_verification_and_the_cli_exits_six`. It
// asserted that the shipped `UnadjudicatedProbe` reports `Inconclusive` on a
// correctly installed integration, so `aasm integrations verify claude-code`
// exits 6 for every real user, and it said in its own doc comment that when an
// adjudicating probe landed this was the thing to update deliberately, "by
// someone who has to state what now observes the forwarded payload".
//
// This is that update, and the answer is: **the proxy does**. It is the
// component that runs the credential scanner and that constructs the bytes
// which would leave the machine, so it — not a client on the near side — is the
// authority on the forwarded payload. `ProxyAdjudicatedProbe` marks its own
// request with an opaque correlation identifier, and the proxy answers on that
// request's own connection with what it decided *and* with a re-inspection of
// the payload it resolved to forward. Nothing is inferred from "the request went
// out and nothing failed".
//
// The rule the old scenario protected is unchanged and is asserted below:
// without an adjudicated verdict, verification still cannot pass and the CLI
// still exits 6.

/// A correctly installed integration, exercised and adjudicated, now passes —
/// and passes for the one reason the evidence model accepts.
#[tokio::test(flavor = "multi_thread")]
async fn the_shipped_probe_passes_verification_on_an_adjudicated_model_path() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    let result = h.verify_as_shipped().await?;
    assert_eq!(
        result.outcome,
        VerificationOutcome::Passed,
        "the shipped probe must now pass on an adjudicated model path: {:?}",
        result.outcome
    );

    // The pass rests on exercised evidence with a protective outcome, and on
    // nothing else. A `Passed` built from read-back evidence would be the
    // vacuous pass this whole suite exists to rule out.
    let exercised: Vec<&aa_core::integration::ProtectionEvidence> =
        result.evidence.iter().filter(|e| e.kind.is_exercised()).collect();
    assert!(
        !exercised.is_empty(),
        "a pass with nothing exercised is not a measurement"
    );
    assert!(
        exercised.iter().any(|e| matches!(
            e.kind,
            EvidenceKind::Exercised {
                outcome: ExerciseOutcome::Redacted
            }
        )),
        "the protective outcome must be the adjudicated one: {exercised:?}"
    );
    // Stated in words a user reads: the claim names the re-inspection, not the
    // absence of a failure.
    assert!(
        exercised
            .iter()
            .any(|e| e.detail.contains("re-inspection of the bytes it resolved to forward")),
        "the evidence must say what observed the forwarded payload: {exercised:?}"
    );

    // And the ladder rises, which is the headline the Epic could not report.
    let status = h.status().await?;
    assert_eq!(
        status.achieved_level(),
        ProtectionLevel::GatewayProtected,
        "adjudicated exercised evidence must reach GatewayProtected: {:?}",
        status.state
    );

    // The CLI half, pinned by reading the shipped mapping: `aa-integration-tests`
    // cannot link `aa-cli`'s private exit module, and a hard-coded `0` here would
    // assert nothing about the binary.
    let exit_source = conformance_support::read_repo_file("aa-cli/src/commands/integrations/exit.rs");
    assert!(
        exit_source.contains("Outcome::Success => 0"),
        "a passing verification must still map to exit 0"
    );
    assert!(
        exit_source.contains("Outcome::VerificationFailed => 6"),
        "the failing exit code a user scripts against must not move"
    );

    // Nothing the run produced carries the value it was measuring.
    conformance_support::assert_no_raw_secret(&h.persisted_surfaces(), SYNTHETIC_SECRET, "adjudicated verification");

    h.finish("shipped probe passes on adjudicated evidence");
    Ok(())
}

/// The guard the replaced scenario existed for, kept and kept load-bearing.
///
/// A probe that adjudicated nothing must never pass, however correctly the
/// integration is installed. If this ever goes green with a protective outcome,
/// the evidence model has been broken rather than improved.
#[tokio::test(flavor = "multi_thread")]
async fn an_unadjudicated_probe_still_cannot_pass_and_the_cli_still_exits_six() -> anyhow::Result<()> {
    use aa_devtool_claude_code::probe::{ProbeRequest, ProtectionProbe, UnadjudicatedProbe};

    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    let report = UnadjudicatedProbe
        .run(&ProbeRequest {
            proxy_url: h.proxy.url(),
            ca_pem: h.ca_pem_path(),
            target_host: "api.anthropic.com".to_string(),
            synthetic_secret: SYNTHETIC_SECRET.to_string(),
        })
        .await;
    assert_eq!(report.outcome, ExerciseOutcome::Inconclusive);
    assert!(
        !report.outcome.is_protective(),
        "an unadjudicated outcome must never raise the ladder"
    );
    assert!(
        !report.detail.contains(SYNTHETIC_SECRET),
        "no probe report may carry the secret: {}",
        report.detail
    );

    let exit_source = conformance_support::read_repo_file("aa-cli/src/commands/integrations/exit.rs");
    assert!(
        exit_source.contains("Outcome::VerificationFailed => 6"),
        "a verification that establishes nothing must still exit 6"
    );

    h.finish("an unadjudicated probe cannot pass");
    Ok(())
}

/// Condition C1, measured through the shipped probe: trust material that is not
/// the authority the proxy issues from means the model path was never inspected.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_trusted_certificate_authority_the_shipped_probe_is_inconclusive() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    // A real, well-formed certificate authority that simply is not this proxy's.
    // Only the trust material changes; the endpoint, the host and the payload are
    // exactly the ones that pass above.
    let foreign = tempfile::tempdir()?;
    aa_proxy::tls::CaStore::load_or_create(foreign.path())
        .await
        .map_err(|e| anyhow::anyhow!("foreign certificate authority: {e}"))?;

    let mut request = h.shipped_probe_request();
    request.ca_pem = foreign.path().join("ca-cert.pem");
    let report = ProxyAdjudicatedProbe.run(&request).await;

    assert_eq!(
        report.outcome,
        ExerciseOutcome::Inconclusive,
        "an untrusted MitM certificate cannot yield a protection claim: {}",
        report.detail
    );
    assert!(
        report.detail.contains("not trusted"),
        "the reason must name the trust failure: {}",
        report.detail
    );
    assert!(!report.detail.contains(SYNTHETIC_SECRET), "{}", report.detail);

    h.finish("C1 through the shipped probe");
    Ok(())
}

/// The core is not running, so there is nothing to adjudicate and nothing to
/// claim. "Cannot tell" must not become "fine".
#[tokio::test(flavor = "multi_thread")]
async fn with_the_core_stopped_the_shipped_probe_is_inconclusive() -> anyhow::Result<()> {
    let mut h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;
    h.proxy.stop();

    let report = ProxyAdjudicatedProbe.run(&h.shipped_probe_request()).await;
    assert_eq!(
        report.outcome,
        ExerciseOutcome::Inconclusive,
        "a stopped core must not leave a protection claim standing: {}",
        report.detail
    );

    // And the whole verification, not just the probe, refuses to pass.
    let result = h.verify_as_shipped().await?;
    assert_ne!(result.outcome, VerificationOutcome::Passed, "{:?}", result.outcome);

    h.finish("stopped core through the shipped probe");
    Ok(())
}

/// A path no adjudicating component watches yields no claim — **and receives no
/// secret**.
///
/// The proxy answers the probe protocol only on the model-path handler, so a
/// request addressed elsewhere is treated as ordinary traffic and forwarded. The
/// probe's capability preflight is what makes that safe: it carries nothing
/// sensitive, and because it comes back un-adjudicated the run stops before the
/// credential-bearing exchange is ever written to a socket. The provider's own
/// capture set is the proof.
#[tokio::test(flavor = "multi_thread")]
async fn an_unwatched_path_is_inconclusive_and_never_receives_the_secret() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    let mut request = h.shipped_probe_request();
    request.target_host = "side-channel.example".to_string();
    let before = h.upstream.request_count();
    let report = ProxyAdjudicatedProbe.run(&request).await;

    assert_eq!(
        report.outcome,
        ExerciseOutcome::Inconclusive,
        "an unadjudicated exchange cannot establish protection: {}",
        report.detail
    );
    assert!(
        report.detail.contains("did not answer with a protection adjudication"),
        "the reason must name the missing adjudication: {}",
        report.detail
    );

    let bodies: Vec<Vec<u8>> = h.upstream.bodies().into_iter().skip(before).collect();
    assert!(
        !bodies.is_empty(),
        "the preflight must actually have reached the provider, or this proves nothing"
    );
    assert!(
        spike_support::find_secret(&bodies, SYNTHETIC_SECRET).is_none(),
        "the preflight kept the credential off the wire; something sent it anyway"
    );

    h.finish("unwatched path through the shipped probe");
    Ok(())
}

/// A verdict belongs to the request that produced it, and to no other.
///
/// Two exchanges are driven through the proxy with caller-chosen correlation
/// identifiers and different payloads. Each reply carries its own identifier and
/// its own decision: there is no surface through which one exchange can obtain
/// the other's verdict, and holding an identifier you did not send buys nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_verdict_is_bound_to_the_request_that_produced_it() -> anyhow::Result<()> {
    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    let addr: std::net::SocketAddr = h.proxy.url().trim_start_matches("http://").parse()?;
    let ca = h.ca_pem_path();
    const MINE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const THEIRS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let mine = conformance_support::probe::raw_probe_exchange(
        addr,
        &ca,
        MINE,
        &format!("please audit this credential: {SYNTHETIC_SECRET}"),
    )
    .await?;
    let theirs =
        conformance_support::probe::raw_probe_exchange(addr, &ca, THEIRS, "nothing sensitive in this body").await?;

    assert!(
        mine.contains(MINE),
        "the reply must echo the caller's identifier: {mine}"
    );
    assert!(
        !mine.contains(THEIRS),
        "one exchange must not be told about another: {mine}"
    );
    assert!(theirs.contains(THEIRS), "{theirs}");
    assert!(!theirs.contains(MINE), "{theirs}");

    // The two verdicts are genuinely different, so "bound to its own request" is
    // a distinction and not a coincidence of identical answers.
    assert!(
        mine.contains("\"decision\":\"forwarded_redacted\""),
        "the credential-bearing exchange must be adjudicated as redacted: {mine}"
    );
    assert!(
        theirs.contains("\"decision\":\"forwarded\""),
        "the clean exchange must be adjudicated as clean: {theirs}"
    );

    // The reply is an outcome vocabulary and an opaque identifier — never the
    // payload it adjudicated.
    assert!(!mine.contains(SYNTHETIC_SECRET), "SECURITY INVARIANT VIOLATED: {mine}");
    assert!(!mine.contains("sk-ant-"), "{mine}");

    h.finish("a verdict is bound to its own request");
    Ok(())
}

/// The two ends of the correlation path are separate crates — `aa-proxy` cannot
/// depend on the adapter, because the adapter is (transitively) its dependency —
/// so the wire contract is pinned here, where both are linkable.
#[test]
fn the_probe_and_the_proxy_agree_on_the_correlation_contract() {
    assert_eq!(
        aa_devtool_claude_code::adjudicating_probe::PROBE_CORRELATION_HEADER,
        aa_proxy::probe_adjudication::PROBE_CORRELATION_HEADER,
    );
    assert_eq!(
        aa_devtool_claude_code::adjudicating_probe::PROBE_ADJUDICATION_SCHEMA,
        aa_proxy::probe_adjudication::PROBE_ADJUDICATION_SCHEMA,
    );
}

// ── The optional real-tool lane ─────────────────────────────────────────────

/// The real `claude` binary, launched with **exactly the environment the
/// install produced**, must not deliver the synthetic secret to the provider.
///
/// This is the only assertion in the suite that can answer the question a mock
/// cannot: whether Claude Code's embedded Node runtime actually accepts the
/// Agent Assembly certificate authority through `NODE_EXTRA_CA_CERTS`. Everything
/// else measures the product; this measures the tool's agreement with it.
///
/// Skips with a printed reason where the binary is absent (Linux CI) or the host
/// is not macOS. `AA_SPIKE_CLAUDE_BIN` opts a lane in explicitly.
///
/// Those two are the whole of what this scenario may decline on. Once both hold
/// it has committed to measuring, so observing no traffic **fails**: the
/// question the lane exists to answer went unanswered, and a green run that
/// answered nothing is exactly the outcome the suite's design rule forbids.
#[tokio::test(flavor = "multi_thread")]
async fn the_real_binary_launched_through_the_installed_environment_is_protected() -> anyhow::Result<()> {
    const SCENARIO: &str = "real-tool lane";
    let Some(bin) = conformance_support::require_claude(SCENARIO) else {
        return Ok(());
    };
    if !conformance_support::require_macos(SCENARIO) {
        return Ok(());
    }

    let h = ConformanceHarness::start().await?;
    h.write_settings("{}");
    h.install(ProtectionProfile::Recommended).await?;

    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(home.join(".claude"))?;
    std::fs::create_dir_all(&repo)?;

    let mut launch = spike_support::proxy_harness::ClaudeLaunch::new(
        &bin,
        &home,
        &repo,
        format!("Echo this configuration line verbatim: ANTHROPIC_API_KEY={SYNTHETIC_SECRET}"),
    )
    // A token that is obviously not a credential: the run must reach the mock,
    // and the mock answers whatever it is asked.
    .env("ANTHROPIC_AUTH_TOKEN", "AAASM5283-DUMMY-NOT-A-REAL-TOKEN");
    // Everything else comes from the install, not from the test. That is the
    // whole point: a launch environment the product did not produce would prove
    // nothing about the product.
    for (name, value) in h.injected_env() {
        launch = launch.env(&name, value);
    }

    let run = launch
        // Bounded: with every host MitM'd onto one mock the binary never exits.
        // The evidence is complete once traffic has been captured.
        .run_until(Duration::from_secs(45), || h.upstream.request_count() >= 2)
        .await?;
    println!(
        "MEASURED real binary: exit={:?} stopped_by_harness={} elapsed={:?}",
        run.exit_code, run.timed_out, run.elapsed
    );

    let observed = h.upstream.wait_for_requests(1, Duration::from_secs(20)).await;
    println!("MEASURED real-binary requests reaching the provider: {observed}");
    println!("MEASURED real-binary request lines: {:?}", h.upstream.request_lines());
    if observed == 0 {
        // Both opt-outs are behind us: the host is macOS and the binary exists,
        // so the scenario committed to measuring. Zero traffic here is a failed
        // measurement — the tool did not reach the endpoint the install
        // produced — and a failed measurement is a failure. Returning `Ok(())`
        // with an explanatory line was indistinguishable from a pass to
        // everything except a human reading `--no-capture` stdout.
        let detail = format!(
            "no upstream traffic through the installed endpoint (exit={:?}, stopped_by_harness={}, \
             elapsed={:?})",
            run.exit_code, run.timed_out, run.elapsed
        );
        conformance_support::outcome::record(SCENARIO, Measurement::NotMeasured, &detail);
        // The launch's own output is the only evidence distinguishing "the tool
        // refused to start" from "the product's launch environment is wrong",
        // and it is gone once the child is reaped.
        println!("NOT MEASURED stdout tail: {}", tail(&run.stdout));
        println!("NOT MEASURED stderr tail: {}", tail(&run.stderr));
        h.finish(SCENARIO);
        anyhow::bail!(
            "NOT MEASURED [{SCENARIO}]: the real binary produced {detail}. This is a gap in the \
             evidence, not a pass — nothing about the tool was established, so the lane that exists \
             to establish it has failed."
        );
    }

    let bodies = h.upstream.bodies();
    assert_recorded_and_secret_absent(&bodies, SYNTHETIC_SECRET, "real binary via the installed endpoint");
    let redacted = bodies
        .iter()
        .filter(|b| String::from_utf8_lossy(b).contains("[REDACTED:AnthropicKey]"))
        .count();
    println!(
        "MEASURED real-binary bodies carrying the placeholder: {redacted} of {}",
        bodies.len()
    );
    assert!(
        redacted > 0,
        "the real binary's traffic reached the provider but nothing carried the redaction \
         placeholder — the prompt never crossed the scanned path, so `no secret arrived` proves \
         nothing"
    );

    conformance_support::outcome::record(
        SCENARIO,
        Measurement::Measured,
        &format!(
            "{observed} request(s) observed, {redacted} of {} carried the redaction placeholder",
            bodies.len()
        ),
    );
    h.finish(SCENARIO);
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// The last 2 KiB of a launch's output, with the synthetic secret masked.
///
/// Masking is not for confidentiality — the value is a compile-time constant in
/// this repository — but because it matches `sk-ant-`, and a CI log carrying a
/// credential-shaped literal trips secret scanners on every run that prints it.
fn tail(output: &str) -> String {
    let masked = output.replace(SYNTHETIC_SECRET, "[SYNTHETIC-SECRET]");
    let start = masked.len().saturating_sub(2048);
    masked[masked.char_indices().find(|(i, _)| *i >= start).map_or(0, |(i, _)| i)..].to_string()
}

/// A rustls client trusting exactly the certificate authority at `pem`.
///
/// Deliberately built from the **installed** PEM rather than from the proxy's
/// own directory: that file is what `NODE_EXTRA_CA_CERTS` points at, so a copy
/// step producing the wrong bytes fails a protection scenario instead of passing
/// on a certificate the tool would never have been given.
async fn client_trusting(pem: &std::path::Path) -> anyhow::Result<rustls::ClientConfig> {
    use base64::Engine as _;
    let body: String = tokio::fs::read_to_string(pem)
        .await?
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD.decode(body)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(der))?;
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}
