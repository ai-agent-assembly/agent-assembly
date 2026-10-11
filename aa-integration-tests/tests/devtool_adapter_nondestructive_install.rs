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
//! * **Copilot** and **Windsurf** have NO receipted lifecycle (no plan / receipt
//!   / remove -- see `no_receipted_lifecycle_exists_for_copilot_or_windsurf`).
//!   Their `apply_*` methods are exercised directly over throwaway paths and
//!   every destructive behaviour is *characterised* rather than endorsed.
//! * Nothing here launches a real dev tool, reads a real config, or touches
//!   `$HOME`: every root is an injected temp path built with `with_paths` /
//!   `CodexPaths::with_home`, never `::new()`.
//!
//! Tests prefixed `desired_` are `#[ignore]`d on purpose: they pin the
//! contract the product SHOULD meet and currently does not (a defect found by
//! this pass). Run with `--ignored` to reproduce. (The Codex managed-value
//! defect, AAASM-6319, is fixed, so its test is no longer ignored.)

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

/// CHARACTERISATION: the file after install+remove is NOT the user's original
/// bytes -- comments are gone and tables are re-serialised in sorted key order
/// (`args` before `command`). Pins the observed bytes so a change is noticed.
#[tokio::test]
async fn codex_install_then_remove_does_not_restore_the_original_bytes() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    remove(&w);
    let after = std::fs::read_to_string(w.config()).unwrap();
    assert_ne!(after, USER_CONFIG, "OBSERVED: byte-exact restoration does not happen");
    assert!(
        !after.contains("hand written, do not lose this comment"),
        "OBSERVED: comments permanently lost"
    );
    assert!(
        after.find("args =").unwrap() < after.find("command =").unwrap(),
        "OBSERVED: keys re-serialised in sorted order"
    );
}

/// DESIRED: remove restores the user's file byte for byte.
#[tokio::test]
#[ignore = "AAASM-6297 finding: install+remove round-trips config.toml through toml::Table, so comments and key order are permanently lost; desired contract (byte-exact restore) not met"]
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
const COMMENTS_SURVIVE_INSTALL_TODAY: bool = false;

/// DESIRED contract: the user's comments survive install. `#[ignore]`d --
/// the engine round-trips TOML through `toml::Table`, which discards comments.
#[tokio::test]
#[ignore = "AAASM-6297 finding: TOML merge discards the user's comments (aa-core engine toml::Table round-trip); desired contract, not yet met"]
async fn desired_codex_install_preserves_the_users_comments() {
    let w = World::new();
    std::fs::write(w.config(), USER_CONFIG).unwrap();
    install(&w, 1_000).await.unwrap();
    let after = std::fs::read_to_string(w.config()).unwrap();
    assert!(after.contains("hand written, do not lose this comment"));
    assert!(after.contains("trailing comment on an unmanaged key"));
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

/// Copilot and Windsurf expose only `apply_*`: there is no plan, receipt or
/// remove, so "uninstall" is UNSUPPORTED for them. Pinned by asserting the
/// lifecycle trait is not implemented for them.
#[test]
fn no_receipted_lifecycle_exists_for_copilot_or_windsurf() {
    fn implements_lifecycle<T: DevToolIntegration>() {}
    implements_lifecycle::<CodexIntegration>(); // control: the check can say yes
                                                // The absence for the other two is a compile-time fact: the following
                                                // would fail to compile, so it is documented rather than expressed:
                                                //   implements_lifecycle::<aa_devtool_copilot::CopilotAdapter>();
                                                //   implements_lifecycle::<aa_devtool_windsurf::WindsurfCascadeAdapter>();
    let src = include_str!("../../aa-devtool-copilot/src/lib.rs");
    assert!(
        !src.contains("impl DevToolIntegration"),
        "copilot gained a lifecycle: update the QA row"
    );
    let src = include_str!("../../aa-devtool-windsurf/src/lib.rs");
    assert!(
        !src.contains("impl DevToolIntegration"),
        "windsurf gained a lifecycle: update the QA row"
    );
}

mod copilot {
    use aa_devtool_contract::DevToolAdapter;
    use aa_devtool_copilot::CopilotAdapter;

    /// A deny-only policy (one denied MCP tool, no `RequireApproval` rule)
    /// makes the adapter WRITE `chat.tools.autoApprove: true` and
    /// `chat.mcp.requireApproval: "never"`. A user who had chosen the stricter
    /// values loses them, and nothing records the prior values, so there is no
    /// way back. CHARACTERISATION of a destructive, weakening edge.
    #[tokio::test]
    async fn apply_of_a_deny_only_policy_weakens_the_users_stricter_settings_with_no_undo() {
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
            v["chat.tools.autoApprove"], true,
            "OBSERVED: the user's stricter `false` was overwritten with true"
        );
        assert_eq!(
            v["chat.mcp.requireApproval"], "never",
            "OBSERVED: the user's `always` was overwritten with never"
        );
        let leftovers: Vec<_> = walk(tmp.path()).into_iter().filter(|p| p != &settings).collect();
        assert!(
            leftovers.is_empty(),
            "no receipt/backup is written, so the old values are unrecoverable: {leftovers:?}"
        );
    }

    /// DESIRED: governance never loosens a setting the user already made
    /// stricter.
    #[tokio::test]
    #[ignore = "AAASM-6297 finding: aa-devtool-copilot generate_managed_settings/auto_approve (src/lib.rs:233) defaults autoApprove to true and mcp requireApproval to never when no RequireApproval rule exists, and apply_settings overwrites the user's stricter values"]
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
