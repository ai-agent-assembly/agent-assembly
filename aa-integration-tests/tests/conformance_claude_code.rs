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
//!
//! # Portability
//!
//! Everything above runs on every platform: the adapter, the engine, the
//! receipt store, the proxy, the scanner and the provider are all pure Rust and
//! the tool binary is stood in for by a path plus a version override. The two
//! scenarios that need the real `claude` binary print `SKIP [...]` with the
//! reason and return, so a skip is visible in the output rather than looking
//! like a pass.
//!
//! # Safety
//!
//! See `conformance_support`'s module docs. Every root is an injected temp path,
//! no process-global environment variable is mutated, no keychain operation is
//! performed, and every scenario ends by asserting the developer's real
//! `~/.claude/settings.json` is untouched.

#[allow(dead_code, unused_imports)]
mod conformance_support;
#[allow(dead_code, unused_imports)]
mod spike_support;

use std::time::Duration;

use aa_core::integration::{
    ExerciseOutcome, ProtectionLevel, ProtectionProfile, ProtectionState, SettingsScope, VerificationOutcome,
};
use aa_devtool_claude_code::lifecycle::{CA_ENV_VAR, MANAGED_KEYS, STEP_NODE_EXTRA_CA_CERTS, STEP_PROXY_CA};
use aa_runtime::devint::IntegrationLifecycle;
use conformance_support::{ConformanceHarness, SYNTHETIC_SECRET};
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
    let receipt = h
        .service()
        .apply(&h.tool(), &plan.plan_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
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
    let again = h.install(ProtectionProfile::Recommended).await?;
    assert_eq!(
        again.receipt_id, receipt.receipt_id,
        "a no-op reapply is not a new installation"
    );
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
        h.service().remove(&h.tool(), None).await.is_err(),
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
            json.contains("host enforcement is unavailable"),
            "the reason host enforcement is unreachable must be stated, not implied: {json}"
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
        .apply(&h.tool(), &plan.plan_id)
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
    let status = upgraded.status(&h.tool()).await.map_err(|e| anyhow::anyhow!("{e}"))?;
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
        .plan(aa_core::integration::IntegrationRequest::new(
            h.tool(),
            ProtectionProfile::Recommended,
            SettingsScope::User,
        ))
        .await;
    assert!(
        refused.is_err(),
        "a version below the adapter's floor must not produce an appliable plan"
    );
    let unsupported_status = too_old.status(&h.tool()).await.map_err(|e| anyhow::anyhow!("{e}"))?;
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

// ── Helpers ─────────────────────────────────────────────────────────────────

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
