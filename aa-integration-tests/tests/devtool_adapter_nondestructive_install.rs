//! AAASM-6297 (ST-10, campaign AAASM-6174) -- is a dev-tool adapter's config
//! install NON-DESTRUCTIVE? (preserves the user's pre-existing config,
//! idempotent, reversible, independent of what else is installed)
//!
//! Scope, stated so no result here is over-read:
//!
//! * **Codex** is driven through the real lifecycle engine
//!   (`IntegrationEngine` + `CodexIntegration` + its real step executor) over a
//!   throwaway `$HOME`. Claude Code's equivalent is already covered by
//!   `conformance_claude_code.rs` / `aa-cli/tests/integrations_command.rs`
//!   (journey J70) and is not repeated.
//! * **Copilot** has a native receipted lifecycle (AAASM-6297) and is driven
//!   through the same engine in `mod copilot_lifecycle`. Its legacy
//!   `apply_*` surface is still exercised in `mod copilot`.
//! * **Windsurf** still has NO receipted lifecycle (no plan / receipt / remove
//!   -- see `no_receipted_lifecycle_exists_for_windsurf`). Its `apply_*`
//!   methods are exercised directly over throwaway paths and every
//!   destructive behaviour is *characterised* rather than endorsed.
//! * Nothing here launches a real dev tool, reads a real config, or touches
//!   `$HOME`: every root is an injected temp path built with `with_paths` /
//!   `CodexPaths::with_home`, never `::new()`.
//!
//! Tests prefixed `desired_` pin the contract the product SHOULD meet; one that
//! the product does not yet meet is `#[ignore]`d so a defect found by this pass
//! can be reproduced with `--ignored`. The Codex ones are no longer ignored:
//! the managed-value defect (AAASM-6319) and the comment/byte-exact-restore
//! defect (AAASM-6322) are fixed.

use std::path::{Path, PathBuf};

use aa_core::integration::{
    core_version, ApplyContext, ComponentVersions, IntegrationEngine, ReceiptStore, ToolVersion,
    LIFECYCLE_SCHEMA_VERSION,
};
use aa_devtool_codex::{CodexIntegration, CodexPaths};
use aa_devtool_contract::{DevToolIntegration, DevToolKind, IntegrationRequest, ProtectionProfile, SettingsScope};

/// A user's hand-written `config.toml`: comments, an unrelated table, a
/// nested profile, and a value of the user's OWN for a key Agent Assembly
/// also manages.
const USER_CONFIG: &str = "\
# my codex config -- hand written, do not lose this comment
model = \"o4-mini\"   # trailing comment on an unmanaged key
sandbox_mode = \"danger-full-access\"   # the user's OWN choice for a managed key

[mcp_servers.docs]
command = \"npx\"
args = [\"-y\", \"docs-server\"]

[profiles.work]
approval_policy = \"never\"
";

struct World {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
}

impl World {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let state = tmp.path().join("state");
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        // a CA source so the plan has the full GatewayProtected step set
        let ca = tmp.path().join("ca-cert.pem");
        std::fs::write(&ca, "-----BEGIN CERTIFICATE-----\nSTUB-NOT-A-REAL-CA\n").unwrap();
        std::fs::write(tmp.path().join("ca-path"), ca.to_string_lossy().as_bytes()).unwrap();
        Self { _tmp: tmp, home, state }
    }

    fn config(&self) -> PathBuf {
        self.home.join(".codex").join("config.toml")
    }

    fn integration(&self) -> CodexIntegration {
        let ca = PathBuf::from(std::fs::read_to_string(self.home.parent().unwrap().join("ca-path")).unwrap());
        CodexIntegration::with_paths(
            CodexPaths::default()
                .with_home(&self.home)
                .with_state(&self.state)
                .with_ca_source(ca),
        )
    }

    fn engine(
        &self,
        plan_executor: aa_devtool_codex::executor::CodexStepExecutor,
    ) -> IntegrationEngine<aa_devtool_codex::executor::CodexStepExecutor> {
        IntegrationEngine::new(plan_executor, ReceiptStore::at(self.state.join("store")))
    }
}

fn request() -> IntegrationRequest {
    IntegrationRequest::new(DevToolKind::Codex, ProtectionProfile::Recommended, SettingsScope::User)
}

fn context(now: u64) -> ApplyContext {
    ApplyContext {
        receipt_id: format!("receipt-{now}"),
        versions: ComponentVersions {
            core: core_version(),
            adapter: ToolVersion::new(0, 1, 0),
            lifecycle_schema: LIFECYCLE_SCHEMA_VERSION,
        },
        tool_version: Some(ToolVersion::new(0, 1, 0)),
        now_unix_secs: now,
    }
}

async fn install(w: &World, now: u64) -> Result<aa_core::integration::ApplyOutcome, String> {
    let integration = w.integration();
    let plan = integration
        .plan_integration(&request())
        .await
        .map_err(|e| e.to_string())?;
    let content = integration.step_content(&plan).await.map_err(|e| e.to_string())?;
    let mut engine = w.engine(integration.scoped_executor(content));
    engine.apply(&plan, &context(now)).map_err(|e| e.to_string())
}

fn remove(w: &World) -> aa_core::integration::RemovalOutcome {
    let integration = w.integration();
    let mut engine = w.engine(integration.scoped_executor(Default::default()));
    engine.remove(&DevToolKind::Codex, SettingsScope::User).expect("remove")
}

fn parse(path: &Path) -> toml::Table {
    std::fs::read_to_string(path)
        .unwrap()
        .parse()
        .expect("config.toml must stay valid TOML")
}

// ── Codex ───────────────────────────────────────────────────────────────────

/// POSITIVE: every key / table the user wrote that Agent Assembly does not
/// manage survives an install, structurally (parsed, not string-matched).
#[tokio::test]
async fn codex_install_preserves_every_unmanaged_key_and_table() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    let out = install(&w, 1_000).await.expect("install");
    assert!(out.mutated);

    let after = parse(&w.config());
    let before: toml::Table = USER_CONFIG.parse().unwrap();
    assert_eq!(after["model"], before["model"]);
    assert_eq!(
        after["mcp_servers"], before["mcp_servers"],
        "user's MCP server table lost"
    );
    assert_eq!(after["profiles"], before["profiles"], "user's profile table lost");
    // adversarial control: the managed keys really did change (the install did something)
    assert_ne!(
        after["sandbox_mode"], before["sandbox_mode"],
        "control: the managed key must have been overwritten, else this test proves nothing"
    );
}

/// A second install over an installed config changes nothing and says so.
#[tokio::test]
async fn codex_second_install_is_a_byte_identical_no_op() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    let first = std::fs::read(w.config()).unwrap();
    let again = install(&w, 2_000).await.unwrap();
    assert!(!again.mutated, "a repeated install must report it changed nothing");
    assert_eq!(
        std::fs::read(w.config()).unwrap(),
        first,
        "repeat install rewrote the file"
    );
}

/// Remove restores the user's own VALUES -- including the user's OWN value
/// for a key Agent Assembly overwrote -- compared structurally (parsed TOML).
#[tokio::test]
async fn codex_remove_restores_the_users_original_values() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    assert_ne!(
        parse(&w.config()),
        USER_CONFIG.parse::<toml::Table>().unwrap(),
        "control: install changed the file"
    );

    let out = remove(&w);
    assert!(out.residual.is_empty(), "{:?}", out.residual);
    assert_eq!(
        parse(&w.config()),
        USER_CONFIG.parse::<toml::Table>().unwrap(),
        "remove must restore the user's pre-install values exactly"
    );
}

/// AAASM-6327: install over an approval value AA cannot rank (`never`, a granular
/// table) must refuse and leave the file byte-for-byte alone -- replacing either
/// could only relax what the user chose.
#[tokio::test]
async fn codex_install_refuses_to_replace_an_unrankable_approval_policy() {
    for cfg in [
        "approval_policy = \"never\"\n",
        "[approval_policy.granular]\nsandbox_approval = true\n",
    ] {
        let w = World::new();
        std::fs::write(w.config(), cfg).unwrap();
        let err = install(&w, 1_000).await.expect_err(cfg);
        assert!(err.contains("approval_policy"), "{err}");
        assert_eq!(
            std::fs::read_to_string(w.config()).unwrap(),
            cfg,
            "file must be untouched"
        );
    }
}

/// The user may edit the file between reviewing the plan and applying it; the
/// apply-time content derivation must re-check (TOCTOU), and a refused install
/// must leave no receipt or state behind.
#[tokio::test]
async fn codex_apply_time_recheck_refuses_an_edit_made_after_planning() {
    let w = World::new();
    std::fs::write(w.config(), "sandbox_mode = \"workspace-write\"\n").unwrap();
    let integration = w.integration();
    let plan = integration
        .plan_integration(&request())
        .await
        .expect("clean at plan time");
    std::fs::write(w.config(), "approval_policy = \"never\"\n").unwrap();
    let err = integration
        .step_content(&plan)
        .await
        .expect_err("edited after planning");
    assert!(err.to_string().contains("approval_policy"), "{err}");
    assert_eq!(
        std::fs::read_to_string(w.config()).unwrap(),
        "approval_policy = \"never\"\n"
    );
    assert!(
        !w.state.join("store").exists(),
        "a refused install must write no receipt"
    );
}

/// The refusal reads the top level only: `[profiles.work] approval_policy =
/// "never"` (in `USER_CONFIG`) is user-owned and must not block an install.
#[tokio::test]
async fn codex_install_ignores_unrankable_values_inside_profiles() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.expect("profiles.* is not compared");
}

/// Install over a config that is already at the strictest values is a no-op
/// and must not be mistaken for a relaxation (kills a `>` instead of `>=`).
#[tokio::test]
async fn codex_install_over_the_strictest_values_succeeds() {
    let w = World::new();
    std::fs::write(
        w.config(),
        "sandbox_mode = \"read-only\"\napproval_policy = \"on-request\"\n",
    )
    .unwrap();
    install(&w, 1_000).await.unwrap();
    let t = parse(&w.config());
    assert_eq!(t["sandbox_mode"].as_str(), Some("read-only"));
    assert_eq!(t["approval_policy"].as_str(), Some("on-request"));
}

/// An install from before AAASM-6319 wrote retired spellings; update/repair of
/// it must still go through and write the loadable values.
#[tokio::test]
async fn codex_update_of_a_pre_6319_install_writes_loadable_values() {
    let w = World::new();
    std::fs::write(
        w.config(),
        "sandbox_mode = \"suggest\"\n[approval_policy]\nfile_writes = \"auto\"\nshell_exec = \"prompt\"\nnetwork = \"auto\"\nmcp_calls = \"auto\"\n",
    )
    .unwrap();
    install(&w, 1_000).await.unwrap();
    let t = parse(&w.config());
    assert_eq!(t["sandbox_mode"].as_str(), Some("read-only"));
    assert_eq!(t["approval_policy"].as_str(), Some("on-request"));
}

/// AAASM-6331 rollback: the user's own `read-only` / `on-request` must survive a
/// full `aasm run codex` -> install -> remove cycle unchanged. The run path
/// (`apply_settings` with an all-Allow policy) is the one that used to lower them.
#[tokio::test]
async fn codex_run_then_install_then_remove_never_relaxes_and_restores_the_users_values() {
    use aa_devtool_codex::CodexAdapter;
    use aa_devtool_contract::{DevToolAdapter, PolicyDecision, PolicyDocument, PolicyRule};

    let w = World::new();
    let cfg = "model = \"o4-mini\"\nsandbox_mode = \"read-only\"\napproval_policy = \"on-request\"\n";
    std::fs::write(w.config(), cfg).unwrap();
    let original: toml::Table = cfg.parse().unwrap();

    // 1. `aasm run codex` under a permissive policy.
    let adapter = CodexAdapter::default().with_home_dir(w.home.clone());
    let allow_all = PolicyDocument {
        version: 1,
        name: "allow-all".into(),
        enforcement_mode: aa_devtool_contract::EnforcementMode::default(),
        rules: vec![PolicyRule {
            action_pattern: "*".into(),
            decision: PolicyDecision::Allow,
        }],
    };
    let settings = adapter.generate_managed_settings(&allow_all).await.unwrap();
    adapter.apply_settings(&settings).await.unwrap();
    let after_run = parse(&w.config());
    assert_eq!(
        after_run["sandbox_mode"].as_str(),
        Some("read-only"),
        "run must not relax"
    );
    assert_eq!(
        after_run["approval_policy"].as_str(),
        Some("on-request"),
        "run must not relax"
    );
    assert_eq!(after_run["model"].as_str(), Some("o4-mini"));

    // 2. install, then 3. remove: back to exactly what the user had.
    install(&w, 1_000).await.unwrap();
    let out = remove(&w);
    assert!(out.residual.is_empty(), "{:?}", out.residual);
    assert_eq!(
        parse(&w.config()),
        original,
        "the user's original values must come back"
    );
}

/// DESIRED: remove restores the user's file byte for byte.
#[tokio::test]
async fn desired_codex_remove_restores_the_original_bytes() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    remove(&w);
    assert_eq!(std::fs::read_to_string(w.config()).unwrap(), USER_CONFIG);
}

/// Install-then-user-edit-then-remove: an edit the USER made to an unmanaged
/// key after install is theirs and must survive removal.
#[tokio::test]
async fn codex_user_edit_made_after_install_survives_remove() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();

    let mut t = parse(&w.config());
    t.insert(
        "model".into(),
        toml::Value::String("user-changed-model-after-install".into()),
    );
    std::fs::write(w.config(), toml::to_string(&t).unwrap()).unwrap();

    remove(&w);
    let after = parse(&w.config());
    assert_eq!(
        after["model"].as_str(),
        Some("user-changed-model-after-install"),
        "post-install user edit lost"
    );
    assert_eq!(
        after["sandbox_mode"].as_str(),
        Some("danger-full-access"),
        "the user's own prior value of a managed key must come back"
    );
    assert!(after.contains_key("mcp_servers"));
}

/// ADVERSARIAL: a config the adapter cannot parse is refused and left alone;
/// no receipt is written for an install that did not happen.
#[tokio::test]
async fn codex_install_over_a_malformed_config_refuses_and_changes_nothing() {
    let w = World::new();
    let bad = "this = is [ not valid toml\n# but it is the user's file\n";
    std::fs::write(w.config(), bad).unwrap();
    let r = install(&w, 1_000).await;
    assert!(r.is_err(), "malformed config.toml must be refused, got {r:?}");
    assert_eq!(
        std::fs::read_to_string(w.config()).unwrap(),
        bad,
        "refused install must not touch the file"
    );
    let receipts = std::fs::read_dir(w.state.join("store")).map(|d| d.count()).unwrap_or(0);
    assert_eq!(
        receipts, 0,
        "no receipt may be written for an install that did not happen"
    );
}

/// Install onto NO pre-existing config creates one; remove deletes it again
/// (nothing of ours left behind) and the user's directory survives.
#[tokio::test]
async fn codex_first_install_then_remove_leaves_no_config_artifact() {
    let w = World::new();
    assert!(!w.config().exists());
    install(&w, 1_000).await.unwrap();
    assert!(w.config().is_file());
    remove(&w);
    assert!(!w.config().exists(), "an AA-created config must be removed again");
    assert!(w.home.join(".codex").is_dir());
}

/// Codex's comments are the user's. CHARACTERISATION of whether install keeps
/// them: this test PASSES while the product behaves as observed, and states
/// the observed behaviour so a change is noticed either way.
#[tokio::test]
async fn codex_install_comment_preservation_is_characterised() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    let after = std::fs::read_to_string(w.config()).unwrap();
    let kept = after.contains("hand written, do not lose this comment");
    eprintln!("OBSERVED: install keeps the user's comments = {kept}\n---\n{after}---");
    // Whatever is observed is asserted by the sibling `desired_` test; here we
    // only pin that the observation is stable.
    assert_eq!(kept, COMMENTS_SURVIVE_INSTALL_TODAY);
}

/// Observed value for the characterisation test above. See the report.
const COMMENTS_SURVIVE_INSTALL_TODAY: bool = true;

/// DESIRED contract: the user's comments survive install.
#[tokio::test]
async fn desired_codex_install_preserves_the_users_comments() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    let after = std::fs::read_to_string(w.config()).unwrap();
    assert!(after.contains("hand written, do not lose this comment"));
    assert!(after.contains("trailing comment on an unmanaged key"));
}

/// A trailing comment on a key Agent Assembly manages is the user's: it
/// survives the install (next to the new value) and the removal brings back the
/// prior value and the same comment, byte for byte.
#[tokio::test]
async fn codex_trailing_comment_on_a_managed_key_survives_install_and_remove() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    let installed = std::fs::read_to_string(w.config()).unwrap();
    let line = installed.lines().find(|l| l.starts_with("sandbox_mode")).unwrap();
    assert!(line.contains("# the user's OWN choice for a managed key"), "{line}");
    assert!(
        !line.contains("danger-full-access"),
        "install must replace the value: {line}"
    );
    remove(&w);
    assert_eq!(std::fs::read_to_string(w.config()).unwrap(), USER_CONFIG);
}

/// After install the user edits an unmanaged key and adds a comment; removal
/// keeps both and still puts the prior managed value back.
#[tokio::test]
async fn codex_edits_and_comments_added_after_install_survive_remove() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    let edited = std::fs::read_to_string(w.config())
        .unwrap()
        .replace("model = \"o4-mini\"", "model = \"edited-after\"")
        .replace("[profiles.work]", "# added after install\n[profiles.work]");
    std::fs::write(w.config(), edited).unwrap();
    remove(&w);
    let after = std::fs::read_to_string(w.config()).unwrap();
    assert!(after.contains("# added after install"));
    let t = parse(&w.config());
    assert_eq!(t["model"].as_str(), Some("edited-after"));
    assert_eq!(t["sandbox_mode"].as_str(), Some("danger-full-access"));
    assert!(!t.contains_key("approval_policy"), "a key Agent Assembly added must go");
}

/// STATED LIMITATION: restore is semantic, not a re-quote. A prior value the
/// user wrote with single quotes comes back equal in meaning but spelled with
/// double quotes.
#[tokio::test]
async fn codex_single_quoted_prior_value_is_restored_semantically_not_byte_for_byte() {
    let w = World::new();
    std::fs::write(w.config(), "sandbox_mode = 'danger-full-access'  # mine\n").unwrap();
    install(&w, 1_000).await.unwrap();
    remove(&w);
    let after = std::fs::read_to_string(w.config()).unwrap();
    assert_eq!(after, "sandbox_mode = \"danger-full-access\"  # mine\n");
    assert_eq!(parse(&w.config())["sandbox_mode"].as_str(), Some("danger-full-access"));
}

/// Nested tables and dotted keys keep the order the user wrote.
#[tokio::test]
async fn codex_nested_tables_and_dotted_keys_keep_their_order() {
    let w = World::new();
    let user = "\
zeta = 1
alpha.beta = 2

[z.last]
x = 1

[a.first]
y = 2
";
    std::fs::write(w.config(), user).unwrap();
    install(&w, 1_000).await.unwrap();
    let installed = std::fs::read_to_string(w.config()).unwrap();
    assert!(installed.find("zeta").unwrap() < installed.find("alpha.beta").unwrap());
    assert!(installed.find("[z.last]").unwrap() < installed.find("[a.first]").unwrap());
    remove(&w);
    assert_eq!(std::fs::read_to_string(w.config()).unwrap(), user);
}

/// A pre-6319 install left `[approval_policy]` as a table. The adapter will not
/// lower or replace a value it cannot rank, so the install is refused with a
/// message naming the key and the user's file is left byte-for-byte untouched.
#[tokio::test]
async fn codex_legacy_approval_policy_table_is_refused_and_left_untouched() {
    let w = World::new();
    let user = "model = \"m\"\n\n[approval_policy]\nfile_writes = \"auto\"\nshell_exec = \"prompt\"\n";
    std::fs::write(w.config(), user).unwrap();
    let err = install(&w, 1_000)
        .await
        .expect_err("an unrankable legacy table must be refused");
    assert!(err.contains("approval_policy"), "{err}");
    assert_eq!(std::fs::read_to_string(w.config()).unwrap(), user);
}

/// CHARACTERISATION (observed limitation): a CRLF file stays valid TOML and its
/// comments survive install and remove, and it is restored in meaning, but its
/// line endings are NOT preserved -- the installed file is LF-only. Exact-byte
/// restore therefore holds for LF files; CRLF files are restored in meaning.
#[tokio::test]
async fn codex_crlf_file_keeps_comments_and_meaning_but_not_line_endings() {
    let w = World::new();
    let user = "# crlf\r\nmodel = \"m\"\r\nsandbox_mode = \"danger-full-access\" # mine\r\n";
    std::fs::write(w.config(), user).unwrap();
    let before = parse(&w.config());
    install(&w, 1_000).await.unwrap();
    let installed = std::fs::read_to_string(w.config()).unwrap();
    assert!(
        installed.contains("# crlf") && installed.contains("# mine"),
        "{installed:?}"
    );
    assert!(
        !installed.contains('\r'),
        "line endings were expected to be normalised: {installed:?}"
    );
    remove(&w);
    assert_eq!(parse(&w.config()), before);
    let after = std::fs::read_to_string(w.config()).unwrap();
    assert!(after.contains("# crlf") && after.contains("# mine"), "{after:?}");
}

/// A second install over an installed file changes nothing and says so.
#[tokio::test]
async fn codex_second_install_is_byte_identical_and_reports_no_mutation() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    let first = std::fs::read_to_string(w.config()).unwrap();
    let second = install(&w, 2_000).await.unwrap();
    assert_eq!(std::fs::read_to_string(w.config()).unwrap(), first);
    assert!(!second.mutated, "a repeat install must not report a mutation");
}

/// A file AASM created and the user then annotated with a comment is not an
/// empty artifact: removal keeps it.
#[tokio::test]
async fn codex_aa_created_file_with_a_user_comment_survives_remove() {
    let w = World::new();
    install(&w, 1_000).await.unwrap();
    let mut text = std::fs::read_to_string(w.config()).unwrap();
    text.push_str("# written by the user after install\n");
    std::fs::write(w.config(), text).unwrap();
    remove(&w);
    assert!(w.config().is_file(), "a user-annotated file must not be deleted");
    assert!(std::fs::read_to_string(w.config())
        .unwrap()
        .contains("# written by the user after install"));
}

/// The bytes written onto a missing config are the canonical rendering, as
/// before the comment-preserving edit existed.
#[tokio::test]
async fn codex_fresh_install_writes_the_canonical_bytes() {
    let w = World::new();
    install(&w, 1_000).await.unwrap();
    let text = std::fs::read_to_string(w.config()).unwrap();
    assert_eq!(text, toml::to_string(&parse(&w.config())).unwrap());
}

/// The managed values are ones the current Codex CLI accepts.
///
/// AAASM-6297 found the install wrote `sandbox_mode = "suggest"` and an
/// `[approval_policy]` table, each of which makes codex-cli 0.160.0 fail to load
/// its configuration; AAASM-6319 fixed it. codex-cli 0.160.0 loads exactly
/// `read-only` / `workspace-write` / `danger-full-access` for `sandbox_mode`
/// and, for `approval_policy`, a string of `on-failure` / `on-request` /
/// `never` (or a `granular` object); `untrusted` is "no longer supported".
/// This pins the written values against that list; the `live_*` test below
/// runs the real binary over the same file.
#[tokio::test]
async fn codex_managed_values_are_accepted_by_the_current_codex_cli() {
    let w = World::new();
    install(&w, 1_000).await.unwrap();
    let t = parse(&w.config());
    let sandbox = t["sandbox_mode"].as_str().unwrap_or("<not a string>");
    assert!(
        ["read-only", "workspace-write"].contains(&sandbox),
        "sandbox_mode={sandbox}: must be a value codex 0.160 loads, and never the unsandboxed one"
    );
    let approval = t["approval_policy"].as_str().unwrap_or("<not a string>");
    assert!(
        ["on-failure", "on-request"].contains(&approval),
        "approval_policy={approval}: must be a string codex 0.160 loads; `never` and the retired `untrusted` are not written"
    );
}

/// LIVE: the real `codex` binary loads the config this install writes.
///
/// `#[ignore]`d because it needs a `codex` on PATH, and it PANICS when there is
/// none -- an absent binary must never read as a pass. It uses a throwaway
/// `CODEX_HOME` holding only the generated file and runs `codex mcp list`, a
/// configuration load that starts no agent and needs no account, so it never
/// touches the real `~/.codex`.
#[tokio::test]
#[ignore = "needs a codex-cli binary on PATH; run with --run-ignored only (AAASM-6319)"]
async fn live_codex_loads_the_config_the_install_writes() {
    let w = World::new();
    install(&w, 1_000).await.unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::copy(w.config(), home.path().join("config.toml")).unwrap();
    let out = std::process::Command::new("codex")
        .args(["mcp", "list"])
        .env("CODEX_HOME", home.path())
        .output()
        .expect("`codex` must be on PATH for this test; it does not skip");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success() && !text.contains("failed to load"),
        "codex could not load the installed config: {text}\n--- config ---\n{}",
        std::fs::read_to_string(home.path().join("config.toml")).unwrap()
    );
}

/// Install-order / coexistence: Codex's and Claude Code's owned roots and
/// settings files are structurally disjoint, so installing or removing one
/// cannot touch the other's artifacts regardless of order.
#[tokio::test]
async fn codex_and_claude_code_own_disjoint_paths_under_one_shared_state_root() {
    use aa_devtool_claude_code::ClaudeCodePaths;
    let w = World::new();
    let codex = w.integration();
    let claude_paths = ClaudeCodePaths::default()
        .with_home(&w.home)
        .with_config_dir(w.home.join(".claude"))
        .with_state(&w.state);

    let cx = codex.paths();
    let s = SettingsScope::User;
    let codex_set = [
        cx.settings_path(s).unwrap(),
        cx.owned_root(s).unwrap(),
        cx.proxy_ca_pem(s).unwrap(),
        cx.launch_env_dir(s).unwrap(),
    ];
    let claude_set = [
        claude_paths.settings_path(s).unwrap(),
        claude_paths.owned_root(s).unwrap(),
        claude_paths.proxy_ca_pem(s).unwrap(),
        claude_paths.launch_env_dir(s).unwrap(),
    ];
    for c in &codex_set {
        for l in &claude_set {
            assert!(
                !c.starts_with(l) && !l.starts_with(c),
                "codex path {} overlaps claude-code path {}",
                c.display(),
                l.display()
            );
        }
    }
    // and a Codex install+remove leaves a Claude-owned file we planted untouched
    let planted = claude_paths.settings_path(s).unwrap();
    std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
    std::fs::write(&planted, "{\"theme\":\"claude-users-own\"}").unwrap();
    install(&w, 1_000).await.unwrap();
    remove(&w);
    assert_eq!(
        std::fs::read_to_string(&planted).unwrap(),
        "{\"theme\":\"claude-users-own\"}"
    );
}

// ── Copilot / Windsurf ──────────────────────────────────────────────────────

fn deny_all_mcp_policy(denied_tool: &str) -> aa_devtool_contract::PolicyDocument {
    aa_devtool_contract::PolicyDocument {
        version: 1,
        name: "aaasm6297".to_string(),
        rules: vec![aa_devtool_contract::PolicyRule {
            action_pattern: format!("mcp_tool:{denied_tool}"),
            decision: aa_devtool_contract::PolicyDecision::Deny,
        }],
        enforcement_mode: Default::default(),
    }
}

/// Windsurf exposes only `apply_*`: there is no plan, receipt or remove, so
/// "uninstall" is UNSUPPORTED for it. Pinned by scanning its source for an
/// `impl DevToolIntegration` (the `include_str!` reads `lib.rs` only, so a
/// lifecycle added in another module would escape it -- update this row if
/// Windsurf grows a `lifecycle.rs`); Copilot, which now has one, is pinned at
/// the type level as the control that the check can say yes.
#[test]
fn no_receipted_lifecycle_exists_for_windsurf() {
    fn implements_lifecycle<T: DevToolIntegration>() {}
    implements_lifecycle::<CodexIntegration>();
    implements_lifecycle::<aa_devtool_copilot::CopilotIntegration>();
    let src = include_str!("../../aa-devtool-windsurf/src/lib.rs");
    assert!(
        !src.contains("impl DevToolIntegration"),
        "windsurf gained a lifecycle: update the QA row"
    );
    assert!(
        !std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aa-devtool-windsurf/src/lifecycle.rs"
        ))
        .exists(),
        "windsurf gained a lifecycle module: update the QA row"
    );
}

/// Copilot's native lifecycle (AAASM-6297) driven through the real engine over a
/// throwaway settings file, mirroring the Codex tests above.
mod copilot_lifecycle {
    use std::path::PathBuf;

    use aa_core::integration::{FilesystemExecutor, IntegrationEngine, ReceiptStore};
    use aa_devtool_contract::{
        DevToolIntegration, DevToolKind, IntegrationRequest, ProtectionLevel, ProtectionProfile, SettingsScope,
        VerificationOutcome,
    };
    use aa_devtool_copilot::{CopilotAdapter, CopilotIntegration};

    const KEY: &str = "chat.tools.global.autoApprove";

    struct World {
        _tmp: tempfile::TempDir,
        settings: PathBuf,
        state: PathBuf,
    }

    impl World {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let settings = tmp.path().join("Code").join("User").join("settings.json");
            std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
            let state = tmp.path().join("state");
            // status derivation needs Copilot to be detectable
            let ext = state.join("ext").join("github.copilot-1.300.0");
            std::fs::create_dir_all(&ext).unwrap();
            std::fs::write(ext.join("package.json"), r#"{"version":"1.300.0"}"#).unwrap();
            Self {
                _tmp: tmp,
                settings,
                state,
            }
        }

        fn integration(&self) -> CopilotIntegration {
            CopilotIntegration::with_adapter(CopilotAdapter::with_paths(self.state.join("ext"), &self.settings))
        }

        fn engine(&self, executor: FilesystemExecutor) -> IntegrationEngine<FilesystemExecutor> {
            IntegrationEngine::new(executor, ReceiptStore::at(self.state.join("store")))
        }

        fn write(&self, body: &str) {
            std::fs::write(&self.settings, body).unwrap();
        }

        fn json(&self) -> serde_json::Value {
            serde_json::from_str(&std::fs::read_to_string(&self.settings).unwrap()).expect("settings must stay JSON")
        }
    }

    fn request() -> IntegrationRequest {
        IntegrationRequest::new(
            DevToolKind::GitHubCopilot,
            ProtectionProfile::Recommended,
            SettingsScope::User,
        )
    }

    async fn install(w: &World, now: u64) -> Result<aa_core::integration::ApplyOutcome, String> {
        let integration = w.integration();
        let plan = integration
            .plan_integration(&request())
            .await
            .map_err(|e| e.to_string())?;
        let mut executor = FilesystemExecutor::new();
        for (id, content) in integration.step_content(&plan).await.map_err(|e| e.to_string())? {
            executor = executor.with_content(id, content);
        }
        w.engine(executor)
            .apply(&plan, &super::context(now))
            .map_err(|e| e.to_string())
    }

    fn remove(w: &World) -> aa_core::integration::RemovalOutcome {
        w.engine(FilesystemExecutor::new())
            .remove(&DevToolKind::GitHubCopilot, SettingsScope::User)
            .expect("remove")
    }

    const USER: &str = r#"{"editor.fontSize": 14, "chat.mcp.servers": {"docs": {"command": "npx"}}, "chat.tools.global.autoApprove": true}"#;

    #[tokio::test]
    async fn install_preserves_every_unmanaged_key() {
        let w = World::new();
        w.write(USER);
        let before: serde_json::Value = serde_json::from_str(USER).unwrap();
        assert!(install(&w, 1_000).await.unwrap().mutated);
        let after = w.json();
        assert_eq!(after["editor.fontSize"], before["editor.fontSize"]);
        assert_eq!(after["chat.mcp.servers"], before["chat.mcp.servers"]);
        assert_eq!(after[KEY], false, "control: the managed key was tightened");
    }

    #[tokio::test]
    async fn second_install_is_byte_identical_and_reports_no_mutation() {
        let w = World::new();
        w.write(USER);
        install(&w, 1_000).await.unwrap();
        let first = std::fs::read(&w.settings).unwrap();
        let again = install(&w, 2_000).await.unwrap();
        assert!(!again.mutated);
        assert_eq!(std::fs::read(&w.settings).unwrap(), first);
    }

    #[tokio::test]
    async fn remove_restores_the_users_prior_value() {
        let w = World::new();
        w.write(USER);
        install(&w, 1_000).await.unwrap();
        let out = remove(&w);
        assert!(out.residual.is_empty(), "{:?}", out.residual);
        assert_eq!(w.json(), serde_json::from_str::<serde_json::Value>(USER).unwrap());
    }

    /// `absent_keys`: a key the user never had must be deleted again, not left as
    /// `false`, and what they did have stays.
    #[tokio::test]
    async fn install_then_remove_leaves_no_key_the_user_never_had() {
        let w = World::new();
        w.write(r#"{"editor.fontSize": 14}"#);
        install(&w, 1_000).await.unwrap();
        assert_eq!(w.json()[KEY], false, "control: install added the key");
        remove(&w);
        let after = w.json();
        assert!(after.get(KEY).is_none(), "key AASM added must go: {after}");
        assert_eq!(after["editor.fontSize"], 14);
    }

    #[tokio::test]
    async fn fresh_install_with_no_file_then_remove_leaves_no_file() {
        let w = World::new();
        assert!(!w.settings.exists());
        install(&w, 1_000).await.unwrap();
        assert_eq!(w.json()[KEY], false);
        remove(&w);
        assert!(!w.settings.exists(), "an AASM-created settings file must be removed");
    }

    /// A user value already at `false` is never owned: the plan claims no key, and
    /// a loosening the USER makes after install is theirs, so removal must not
    /// "restore" `false` over it.
    #[tokio::test]
    async fn a_stricter_user_value_survives_install_and_remove_and_is_never_owned() {
        let w = World::new();
        w.write(r#"{"editor.fontSize": 14, "chat.tools.global.autoApprove": false}"#);
        let plan = w.integration().plan_integration(&request()).await.unwrap();
        let aa_devtool_contract::StepAction::WriteManagedSettings { managed_keys, .. } = &plan.steps[0].action else {
            panic!("expected a settings step")
        };
        assert!(
            managed_keys.is_empty(),
            "the plan must not claim a key the user holds: {managed_keys:?}"
        );

        install(&w, 1_000).await.unwrap();
        assert_eq!(w.json()[KEY], false, "install must not loosen it");

        // the user's own later choice
        w.write(r#"{"editor.fontSize": 14, "chat.tools.global.autoApprove": true}"#);
        remove(&w);
        assert_eq!(
            w.json()[KEY],
            true,
            "removal touched a key AASM never owned and overwrote the user's later edit"
        );

        let w2 = World::new();
        w2.write(r#"{"chat.tools.global.autoApprove": false}"#);
        install(&w2, 1_000).await.unwrap();
        remove(&w2);
        assert_eq!(w2.json()[KEY], false, "remove must not loosen it");
    }

    #[tokio::test]
    async fn a_jsonc_settings_file_is_refused_at_plan_time_and_left_byte_identical() {
        let w = World::new();
        let jsonc = "{\n  // my font\n  \"editor.fontSize\": 14,\n}\n";
        w.write(jsonc);
        let err = w
            .integration()
            .plan_integration(&request())
            .await
            .expect_err("a JSONC file must be refused when planning, not at apply")
            .to_string();
        assert!(err.contains("not strict JSON"), "{err}");
        assert!(install(&w, 1_000).await.is_err());
        assert_eq!(std::fs::read_to_string(&w.settings).unwrap(), jsonc);
        assert!(
            !w.state.join("store").exists(),
            "no receipt for an install that did not happen"
        );
    }

    #[tokio::test]
    async fn an_edit_made_after_planning_is_refused_at_apply() {
        // an unrankable value appearing after the plan was reviewed
        let w = World::new();
        w.write(USER);
        let integration = w.integration();
        let plan = integration.plan_integration(&request()).await.unwrap();
        let edited = r#"{"chat.tools.global.autoApprove": {"x": 1}}"#;
        w.write(edited);
        let err = integration
            .step_content(&plan)
            .await
            .expect_err("edited after planning");
        assert!(err.to_string().contains(KEY), "{err}");
        assert_eq!(std::fs::read_to_string(&w.settings).unwrap(), edited);

        // the user tightening it themselves changes what would be written; the
        // executor's digest check refuses the stale plan
        let w = World::new();
        w.write(USER);
        let integration = w.integration();
        let plan = integration.plan_integration(&request()).await.unwrap();
        w.write(r#"{"chat.tools.global.autoApprove": false}"#);
        let mut executor = FilesystemExecutor::new();
        for (id, content) in integration.step_content(&plan).await.unwrap() {
            executor = executor.with_content(id, content);
        }
        assert!(w.engine(executor).apply(&plan, &super::context(1_000)).is_err());
        assert_eq!(
            std::fs::read_to_string(&w.settings).unwrap(),
            r#"{"chat.tools.global.autoApprove": false}"#
        );
        assert!(
            ReceiptStore::at(w.state.join("store"))
                .load_receipt(&DevToolKind::GitHubCopilot, SettingsScope::User)
                .unwrap()
                .is_none(),
            "a refused install must write no receipt"
        );
    }

    async fn verify_outcome(w: &World, receipt: &aa_core::integration::IntegrationReceipt) -> VerificationOutcome {
        w.integration().verify_integration(receipt, None).await.unwrap().outcome
    }

    #[tokio::test]
    async fn verify_is_unverifiable_normally_and_failed_after_drift() {
        let w = World::new();
        w.write(USER);
        let receipt = install(&w, 1_000).await.unwrap().receipt;
        assert!(
            matches!(
                verify_outcome(&w, &receipt).await,
                VerificationOutcome::Unverifiable { .. }
            ),
            "read-back matches but no probe exists"
        );
        w.write(r#"{"editor.fontSize": 14, "chat.tools.global.autoApprove": true}"#);
        assert!(matches!(
            verify_outcome(&w, &receipt).await,
            VerificationOutcome::Failed { .. }
        ));
    }

    /// An install over an already-`false` value claims no key, so the managed
    /// fingerprint covers nothing. Status and verify must still notice the user
    /// loosening or deleting it, rather than report Installed forever.
    #[tokio::test]
    async fn an_already_strict_install_reports_truthfully_and_notices_later_loosening() {
        for (later, label) in [
            (r#"{"chat.tools.global.autoApprove": true}"#, "loosened"),
            (r#"{"editor.fontSize": 14}"#, "deleted"),
        ] {
            let w = World::new();
            w.write(r#"{"chat.tools.global.autoApprove": false}"#);
            let receipt = install(&w, 1_000).await.unwrap().receipt;

            let status = w.integration().integration_status(Some(&receipt), None).await.unwrap();
            assert_eq!(status.state.achieved_level(), ProtectionLevel::Integrated, "{label}");
            assert!(matches!(
                verify_outcome(&w, &receipt).await,
                VerificationOutcome::Unverifiable { .. }
            ));

            w.write(later);
            let verdict = verify_outcome(&w, &receipt).await;
            assert!(
                matches!(&verdict, VerificationOutcome::Failed { reason } if reason.contains("no longer false")),
                "{label}: {verdict:?}"
            );
            let status = w.integration().integration_status(Some(&receipt), None).await.unwrap();
            assert!(
                status.state.achieved_level() < ProtectionLevel::Integrated,
                "{label}: still reports {:?}",
                status.state
            );
        }
    }

    #[tokio::test]
    async fn project_and_managed_scopes_are_refused() {
        let w = World::new();
        for scope in [SettingsScope::Project, SettingsScope::Managed] {
            let mut req = request();
            req.settings_scope = scope;
            assert!(w.integration().plan_integration(&req).await.is_err(), "{scope}");
        }
        assert!(!w.settings.exists());
    }
}

mod copilot {
    use aa_devtool_contract::DevToolAdapter;
    use aa_devtool_copilot::CopilotAdapter;

    /// A deny-only policy (one denied MCP tool, no `RequireApproval` rule)
    /// used to WRITE `chat.tools.autoApprove: true` and
    /// `chat.mcp.requireApproval: "never"` over the user's stricter values,
    /// with no record to undo it (AAASM-6321). The stricter user values must
    /// now survive, and unmanaged keys stay untouched.
    #[tokio::test]
    async fn apply_of_a_deny_only_policy_keeps_the_users_stricter_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let settings = tmp.path().join("settings.json");
        std::fs::write(
            &settings,
            r#"{"chat.tools.autoApprove": false, "chat.mcp.requireApproval": "always", "editor.fontSize": 14}"#,
        )
        .unwrap();
        let a = CopilotAdapter::with_paths(tmp.path(), &settings);
        let json = a
            .generate_managed_settings(&super::deny_all_mcp_policy("github:push"))
            .await
            .unwrap();
        a.apply_settings(&json).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["editor.fontSize"], 14, "unmanaged key preserved");
        assert_eq!(
            v["chat.tools.autoApprove"], false,
            "the user's stricter `false` must survive"
        );
        assert_eq!(
            v["chat.mcp.requireApproval"], "always",
            "the user's `always` must survive"
        );
    }

    /// DESIRED: governance never loosens a setting the user already made
    /// stricter.
    #[tokio::test]
    async fn desired_apply_never_loosens_a_stricter_user_setting() {
        let tmp = tempfile::tempdir().unwrap();
        let settings = tmp.path().join("settings.json");
        std::fs::write(&settings, r#"{"chat.tools.autoApprove": false}"#).unwrap();
        let a = CopilotAdapter::with_paths(tmp.path(), &settings);
        let json = a
            .generate_managed_settings(&super::deny_all_mcp_policy("github:push"))
            .await
            .unwrap();
        a.apply_settings(&json).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["chat.tools.autoApprove"], false);
    }

    /// VS Code's settings.json is JSONC: comments are legal. The adapter parses
    /// strict JSON, so a perfectly valid VS Code file makes apply REFUSE. That
    /// is non-destructive (file untouched) but means the adapter cannot govern
    /// a real-world settings file that has a comment in it.
    #[tokio::test]
    async fn apply_refuses_a_valid_vscode_jsonc_settings_file_and_leaves_it_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let settings = tmp.path().join("settings.json");
        let jsonc = "{\n  // my font\n  \"editor.fontSize\": 14,\n}\n";
        std::fs::write(&settings, jsonc).unwrap();
        let a = CopilotAdapter::with_paths(tmp.path(), &settings);
        let json = a
            .generate_managed_settings(&super::deny_all_mcp_policy("x:y"))
            .await
            .unwrap();
        assert!(a.apply_settings(&json).await.is_err());
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), jsonc);
    }

    /// MCP governance permanently deletes the user's denied servers (the whole
    /// entry, command and args) with no copy kept.
    #[tokio::test]
    async fn mcp_governance_permanently_deletes_a_denied_user_server_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let settings = tmp.path().join("settings.json");
        std::fs::write(
            &settings,
            r#"{"chat.mcp.servers":{"github":{"command":"npx","args":["-y","gh"]},"keep":{"command":"x","args":[]}}}"#,
        )
        .unwrap();
        let a = CopilotAdapter::with_paths(tmp.path(), &settings);
        a.apply_mcp_governance(&[], &["github".to_string()]).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert!(v["chat.mcp.servers"].get("github").is_none());
        assert!(
            v["chat.mcp.servers"].get("keep").is_some(),
            "control: an allowed server survives"
        );
        assert!(
            walk(tmp.path()).into_iter().all(|p| p == settings),
            "no backup of the deleted entry exists"
        );
    }

    fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = vec![];
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out
    }
}

mod windsurf {
    use aa_devtool_contract::DevToolAdapter;
    use aa_devtool_windsurf::WindsurfCascadeAdapter;

    /// Windsurf's `apply_settings` keeps unknown top-level keys (AAASM-6091)
    /// and is idempotent, but, like Copilot, overwrites a managed key with no
    /// prior-value record.
    #[tokio::test]
    async fn apply_preserves_unknown_keys_is_idempotent_and_keeps_no_undo() {
        let tmp = tempfile::tempdir().unwrap();
        let (admin, mcp) = (
            tmp.path().join("admin_settings.json"),
            tmp.path().join("mcp_settings.json"),
        );
        std::fs::write(
            &admin,
            r#"{"userOwnedTopLevel":{"x":1},"terminal":{"commandAllowlist":["rm"]}}"#,
        )
        .unwrap();
        let a = WindsurfCascadeAdapter::with_paths(&admin, &mcp);
        let json = a
            .generate_managed_settings(&super::deny_all_mcp_policy("a:b"))
            .await
            .unwrap();
        a.apply_settings(&json).await.unwrap();
        let first = std::fs::read(&admin).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(v["userOwnedTopLevel"]["x"], 1, "unknown top-level key preserved");
        assert_ne!(
            v["terminal"]["commandAllowlist"],
            serde_json::json!(["rm"]),
            "control: the managed key changed"
        );
        a.apply_settings(&json).await.unwrap();
        assert_eq!(
            std::fs::read(&admin).unwrap(),
            first,
            "second apply must be byte-identical"
        );
        // the user's prior allowlist ["rm"] is not recorded anywhere
        let others: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| *p != admin)
            .collect();
        assert!(others.is_empty(), "no backup / receipt exists: {others:?}");
    }

    #[tokio::test]
    async fn apply_refuses_a_malformed_admin_settings_file() {
        let tmp = tempfile::tempdir().unwrap();
        let (admin, mcp) = (
            tmp.path().join("admin_settings.json"),
            tmp.path().join("mcp_settings.json"),
        );
        std::fs::write(&admin, "{ // jsonc comment\n}").unwrap();
        let a = WindsurfCascadeAdapter::with_paths(&admin, &mcp);
        let json = a
            .generate_managed_settings(&super::deny_all_mcp_policy("a:b"))
            .await
            .unwrap();
        assert!(a.apply_settings(&json).await.is_err());
        assert_eq!(std::fs::read_to_string(&admin).unwrap(), "{ // jsonc comment\n}");
    }
}
