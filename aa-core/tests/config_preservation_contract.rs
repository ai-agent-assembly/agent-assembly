//! The permanent AAASM-6091 §10 release gate: nine named invariants every
//! productized Developer Integration's config mutation must satisfy.
//!
//! # Why this is its own file, not scattered assertions
//!
//! Every one of these invariants is already exercised, piecemeal, by
//! `aa-core::integration::engine`'s own unit tests. This file exists so the
//! nine invariants AAASM-6091 names are individually discoverable
//! (`cargo nextest list -p aa-core --test config_preservation_contract`) and
//! individually reportable as a release gate, rather than living only as
//! prose in a Jira ticket that a future change could regress without any
//! test naming the thing it broke. A new adapter or a new mutation path is
//! not considered AAASM-6091-complete until it can pass an equivalent of
//! every test in this file.
//!
//! Built entirely on `aa_core::integration`'s public surface — the same
//! `FilesystemExecutor` + `IntegrationEngine` every native adapter
//! (`aa-devtool-claude-code`, `aa-devtool-codex`) shares — so this is a
//! contract on the shared engine, not a claim about any one adapter's glue
//! code around it.

use aa_core::dev_tool::{DevToolKind, GovernanceLevel};
use aa_core::integration::{
    core_version, ApplyContext, ComponentVersions, DocumentFormat, EngineError, FilesystemExecutor, IntegrationEngine,
    IntegrationPlan, IntegrationRequest, IntegrationStep, ProtectionLevel, ProtectionProfile, ReceiptStore,
    SettingsMerge, SettingsScope, StepAction, StepReceipt, ToolVersion,
};

const MANAGED_CONTENT: &str = r#"{"permissions":{"allow":["Bash"],"deny":[]},"permissionMode":"default"}"#;

struct Fixture {
    _dir: tempfile::TempDir,
    settings: std::path::PathBuf,
    store: ReceiptStore,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    Fixture {
        settings: dir.path().join("tool").join("settings.json"),
        store: ReceiptStore::at(dir.path().join("state")),
        _dir: dir,
    }
}

fn plan(f: &Fixture) -> IntegrationPlan {
    let request = IntegrationRequest::new(
        DevToolKind::ClaudeCode,
        ProtectionProfile::Recommended,
        SettingsScope::User,
    );
    IntegrationPlan::new(
        "plan-1",
        &request,
        ProtectionLevel::Integrated,
        GovernanceLevel::L2Enforce,
    )
    .with_step(IntegrationStep::new(
        "settings",
        StepAction::WriteManagedSettings {
            scope: SettingsScope::User,
            path: f.settings.clone(),
            managed_keys: vec!["permissions".to_string(), "permissionMode".to_string()],
            content_sha256: aa_core::integration::sha256_hex(MANAGED_CONTENT),
            merge: SettingsMerge::MergeManagedKeys,
            format: DocumentFormat::Json,
        },
        "write the managed settings block",
    ))
}

fn engine(f: &Fixture) -> IntegrationEngine<FilesystemExecutor> {
    IntegrationEngine::new(
        FilesystemExecutor::new().with_content("settings", MANAGED_CONTENT),
        f.store.clone(),
    )
}

fn context(now: u64) -> ApplyContext {
    ApplyContext {
        receipt_id: format!("receipt-{now}"),
        versions: ComponentVersions {
            core: core_version(),
            adapter: ToolVersion::new(0, 1, 0),
            lifecycle_schema: aa_core::integration::LIFECYCLE_SCHEMA_VERSION,
        },
        tool_version: Some(ToolVersion::new(2, 1, 220)),
        now_unix_secs: now,
    }
}

fn write(f: &Fixture, raw: &str) {
    std::fs::create_dir_all(f.settings.parent().unwrap()).unwrap();
    std::fs::write(&f.settings, raw).unwrap();
}

fn read(f: &Fixture) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(&f.settings).unwrap()).unwrap()
}

#[test]
fn preexisting_config_is_preserved() {
    let f = fixture();
    write(&f, r#"{"theme":"dark","customField":{"nested":[1,2,3]}}"#);
    engine(&f).apply(&plan(&f), &context(1_000)).unwrap();

    let after = read(&f);
    assert_eq!(after["theme"], "dark");
    assert_eq!(after["customField"], serde_json::json!({"nested": [1, 2, 3]}));
}

#[test]
fn post_install_user_changes_are_preserved() {
    let f = fixture();
    let mut e = engine(&f);
    e.apply(&plan(&f), &context(1_000)).unwrap();

    let mut edited = read(&f);
    edited["addedAfterInstall"] = serde_json::json!("kept");
    write(&f, &edited.to_string());

    e.remove(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();
    assert_eq!(read(&f)["addedAfterInstall"], "kept");
}

#[test]
fn unknown_keys_are_preserved() {
    let f = fixture();
    write(&f, r#"{"aFutureKeyNoSchemaKnowsAboutYet":{"deep":{"nesting":true}}}"#);
    let mut e = engine(&f);
    e.apply(&plan(&f), &context(1_000)).unwrap();
    e.remove(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();

    assert_eq!(
        read(&f)["aFutureKeyNoSchemaKnowsAboutYet"],
        serde_json::json!({"deep": {"nesting": true}})
    );
}

#[test]
fn repair_touches_only_aasm_state() {
    let f = fixture();
    write(&f, r#"{"theme":"dark"}"#);
    let mut e = engine(&f);
    e.apply(&plan(&f), &context(1_000)).unwrap();

    let mut drifted = read(&f);
    drifted["permissionMode"] = serde_json::json!("bypassPermissions"); // AASM-owned drift
    drifted["theme"] = serde_json::json!("gruvbox"); // user's own key, unrelated to AASM
    write(&f, &drifted.to_string());

    e.apply(&plan(&f), &context(2_000)).unwrap();
    let after = read(&f);
    assert_eq!(after["permissionMode"], "default", "AASM-owned drift is corrected");
    assert_eq!(
        after["theme"], "gruvbox",
        "the user's own key is left exactly as they set it"
    );
}

#[test]
fn remove_touches_only_aasm_state() {
    let f = fixture();
    write(&f, r#"{"theme":"dark","hooks":{"PreToolUse":[]}}"#);
    let mut e = engine(&f);
    e.apply(&plan(&f), &context(1_000)).unwrap();
    e.remove(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();

    let after = read(&f);
    assert_eq!(after["theme"], "dark");
    assert_eq!(after["hooks"], serde_json::json!({"PreToolUse": []}));
    assert!(after.get("permissions").is_none(), "AASM's own key is gone");
}

#[test]
fn stale_receipt_cannot_overwrite_current_config() {
    let f = fixture();
    let mut e = engine(&f);
    e.apply(&plan(&f), &context(1_000)).unwrap();

    // The user changes an AASM-owned key after install (this is the receipt
    // going "stale" relative to the file). Repair must read the file's
    // *current* content, not reapply a cached snapshot from install time.
    let mut current = read(&f);
    current["permissionMode"] = serde_json::json!("bypassPermissions");
    current["userKeyAddedAfterInstall"] = serde_json::json!("must-survive");
    write(&f, &current.to_string());

    e.apply(&plan(&f), &context(2_000)).unwrap();
    let after = read(&f);
    assert_eq!(after["permissionMode"], "default");
    assert_eq!(
        after["userKeyAddedAfterInstall"], "must-survive",
        "current content wins over the stale receipt"
    );
}

#[test]
fn shared_config_is_never_deleted_by_default() {
    let f = fixture();
    write(&f, r#"{"theme":"dark"}"#);
    let mut e = engine(&f);
    e.apply(&plan(&f), &context(1_000)).unwrap();
    e.remove(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();

    assert!(
        f.settings.exists(),
        "a file that predates AASM is never deleted, only its own keys are removed"
    );
    assert_eq!(read(&f)["theme"], "dark");
}

#[test]
fn shared_config_is_never_deleted_by_a_settings_step_with_no_prior_state() {
    // The specific, previously-latent path: a WriteManagedSettings step with
    // reversal = Some(ManageArtifact::Remove) and no prior_state must refuse,
    // not delete the file the ManageArtifact::Remove reversal names.
    let f = fixture();
    std::fs::create_dir_all(f.settings.parent().unwrap()).unwrap();
    std::fs::write(&f.settings, r#"{"theme":"dark"}"#).unwrap();

    let step = IntegrationStep::new(
        "settings",
        StepAction::WriteManagedSettings {
            scope: SettingsScope::User,
            path: f.settings.clone(),
            managed_keys: vec!["permissions".to_string()],
            content_sha256: aa_core::integration::sha256_hex(MANAGED_CONTENT),
            merge: SettingsMerge::MergeManagedKeys,
            format: DocumentFormat::Json,
        },
        "write the managed settings block",
    )
    .with_reversal(StepAction::ManageArtifact {
        operation: aa_core::integration::ArtifactOperation::Remove,
        path: f.settings.clone(),
    });
    let receipt = StepReceipt::applied(&step, Some("sha256:whatever".to_string()));

    let mut executor = FilesystemExecutor::new().with_content("settings", MANAGED_CONTENT);
    use aa_core::integration::StepExecutor;
    assert!(executor.reverse(&receipt).is_err());
    assert!(f.settings.exists());
    assert_eq!(read(&f)["theme"], "dark");
}

#[test]
fn failed_mutation_is_atomic() {
    // A required step that fails must leave the target exactly as it was —
    // no partial write, no residue from the attempt.
    let f = fixture();
    write(&f, r#"{"theme":"dark"}"#);
    let mut e = engine(&f);

    // Two steps sharing an id makes the plan invalid, so apply must refuse
    // before writing anything at all.
    let broken = plan(&f).with_step(IntegrationStep::new(
        "settings",
        StepAction::WriteManagedSettings {
            scope: SettingsScope::User,
            path: f.settings.clone(),
            managed_keys: vec!["permissions".to_string()],
            content_sha256: aa_core::integration::sha256_hex(MANAGED_CONTENT),
            merge: SettingsMerge::MergeManagedKeys,
            format: DocumentFormat::Json,
        },
        "duplicate step id",
    ));
    assert!(matches!(
        e.apply(&broken, &context(1_000)),
        Err(EngineError::InvalidPlan(_))
    ));
    assert_eq!(
        read(&f),
        serde_json::json!({"theme": "dark"}),
        "an invalid plan writes nothing at all"
    );
}

#[test]
fn legacy_ownership_unknown_fails_safe() {
    let f = fixture();
    write(&f, r#"{"theme":"dark"}"#);
    let mut e = engine(&f);
    e.apply(&plan(&f), &context(1_000)).unwrap();

    // Simulate a legacy receipt: load it, strip prior_state as a pre-AAASM-5278
    // receipt would never have had it, save it back.
    let mut receipt = f
        .store
        .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
        .unwrap()
        .unwrap();
    for step in &mut receipt.steps {
        step.prior_state = None;
    }
    assert!(receipt.steps[0].is_legacy_ownership_unknown());
    f.store.save_receipt(&receipt).unwrap();

    // The step has no recorded reversal either (a bare legacy receipt), so
    // the executor cannot even attempt one — this fails safe as a hard
    // error, not a silent success with a residual: the receipt and journal
    // both survive on disk (recoverable via `Engine::recover`), and neither
    // the file nor its unrelated content is touched.
    let result = e.remove(&DevToolKind::ClaudeCode, SettingsScope::User);
    assert!(
        matches!(result, Err(EngineError::ReversalFailed { .. })),
        "a legacy-ownership-unknown step with no reversal must fail loudly, not silently restore or delete: {result:?}"
    );
    assert!(
        f.store
            .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .is_some(),
        "the receipt survives a failed removal, so it can be recovered rather than lost"
    );
    assert_eq!(
        read(&f)["theme"],
        "dark",
        "removal must not have guessed at or destroyed the file"
    );
}
