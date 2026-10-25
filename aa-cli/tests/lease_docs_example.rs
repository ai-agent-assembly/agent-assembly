//! The worked example in `docs/src/cli/lease.md` must keep working (AAASM-6385).
//!
//! The policy and the runtime start recipe are extracted from the page itself, so
//! editing either block without the code (or the code without the page) fails
//! here instead of shipping a doc that does not run. Deleted from the published
//! tree with the gate it consults (`.ci/strip-for-publish.sh`).
#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use aa_runtime::lease::decide::{decide, LeaseGovernance};
use aa_runtime::lease::governed::DEFAULT_LEASE_TTL_SECONDS;
use aa_runtime::pipeline::LeaseVerdict;
use assert_cmd::prelude::*;

const SUBJECT: &str = "my-agent";

/// The fenced block that follows `<!-- lease-example:{name} -->` in the page.
fn doc_block(name: &str) -> String {
    let page = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/src/cli/lease.md");
    let text = std::fs::read_to_string(&page).unwrap_or_else(|e| panic!("{}: {e}", page.display()));
    let marker = format!("<!-- lease-example:{name} -->");
    let after = text
        .split_once(&marker)
        .unwrap_or_else(|| panic!("marker {marker} not found in {}", page.display()))
        .1;
    let body = after.split_once("```").expect("opening fence").1;
    let body = body.split_once('\n').expect("fence info line").1;
    body.split_once("```").expect("closing fence").0.to_string()
}

/// `NAME=value` words of a recipe, with `\`-continuations joined.
fn env_assignments(recipe: &str) -> BTreeMap<String, String> {
    recipe
        .replace("\\\n", " ")
        .split_whitespace()
        .filter_map(|w| w.split_once('='))
        .filter(|(k, _)| k.starts_with("AA_"))
        .map(|(k, v)| (k.to_string(), v.trim_matches(|c| c == '"' || c == '\'').to_string()))
        .collect()
}

fn aasm(home: &Path) -> Command {
    let mut c = Command::cargo_bin("aasm").expect("aasm binary");
    c.env("HOME", home).env_remove("AA_LEASE_STATE");
    c
}

fn stderr_of(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

struct Rig {
    dir: tempfile::TempDir,
    policy: PathBuf,
    state: PathBuf,
    init_stdout: String,
}

fn rig(policy_yaml: &str) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.yaml");
    std::fs::write(&policy, policy_yaml).unwrap();
    let state_dir = dir.path().join("lease");
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = state_dir.join("lease.json");
    let init = aasm(dir.path())
        .args(["lease", "init", "--subject", SUBJECT, "--policy"])
        .arg(&policy)
        .arg("--state")
        .arg(&state)
        .output()
        .unwrap();
    assert!(init.status.success(), "{}", stderr_of(&init));
    Rig {
        dir,
        policy,
        state,
        init_stdout: String::from_utf8_lossy(&init.stdout).into_owned(),
    }
}

/// The verdict the runtime's gate gives `tool`, built the way `aa-runtime`
/// builds its governance at startup (`LeaseGovernance::from_state`).
fn verdict(rig: &Rig, tool: &str) -> LeaseVerdict {
    use aa_proto::assembly::common::v1::ActionType;
    use aa_proto::assembly::policy::v1::action_context::Action;
    use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};
    use std::collections::BTreeSet;

    let resolution = aa_policy::resolve::load(&rig.policy);
    let state = aa_runtime::lease::state::load(&rig.state).unwrap();
    let governance = LeaseGovernance::from_state(&resolution, SUBJECT, DEFAULT_LEASE_TTL_SECONDS, "docs-test", &state)
        .expect("the documented policy and record are accepted for governed mode");
    let req = CheckActionRequest {
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: tool.to_string(),
                ..Default::default()
            })),
        }),
        ..Default::default()
    };
    decide(&governance, &BTreeSet::<String>::new(), &req, SystemTime::now())
}

#[test]
fn the_documented_policy_validates_and_the_runtime_gate_admits_what_the_page_says() {
    let policy = doc_block("policy");
    let r = rig(&policy);

    let validate = aasm(r.dir.path())
        .args(["policy", "validate"])
        .arg(&r.policy)
        .output()
        .unwrap();
    assert!(validate.status.success(), "{}", stderr_of(&validate));
    assert!(
        !stderr_of(&validate).contains("warning:"),
        "the worked example must not trip the governed-lease warnings: {}",
        stderr_of(&validate)
    );

    assert_eq!(verdict(&r, "write_note"), LeaseVerdict::Permit, "leased capability");
    assert_eq!(verdict(&r, "calc"), LeaseVerdict::Permit, "`none` needs no lease");
    assert!(
        matches!(verdict(&r, "undeclared_tool"), LeaseVerdict::Deny { .. }),
        "an undeclared tool is denied"
    );
}

/// Negative control: the same page policy without its `authority.leases` is
/// refused for `write_note`, so the test above can fail.
#[test]
fn without_its_lease_the_documented_tool_is_denied() {
    let policy = doc_block("policy");
    let without_leases = policy.split("authority:").next().unwrap().to_string();
    assert_ne!(without_leases, policy, "the example must contain an authority section");
    let r = rig(&without_leases);
    assert!(matches!(verdict(&r, "write_note"), LeaseVerdict::Deny { .. }));
}

#[test]
fn the_documented_recipe_is_what_init_prints() {
    let r = rig(&doc_block("policy"));
    let doc = env_assignments(&doc_block("recipe"));
    let printed = env_assignments(&r.init_stdout);

    let keys = |m: &BTreeMap<String, String>| m.keys().cloned().collect::<Vec<_>>();
    assert_eq!(
        keys(&doc),
        keys(&printed),
        "page recipe vs `lease init` output:\n{}",
        r.init_stdout
    );
    assert_eq!(
        keys(&doc),
        ["AA_AGENT_ID", "AA_LEASE_POLICY", "AA_LEASE_STATE", "AA_METRICS_ADDR"]
    );
    assert_eq!(doc["AA_AGENT_ID"], SUBJECT);
    assert_eq!(printed["AA_AGENT_ID"], SUBJECT);
    assert_eq!(doc["AA_METRICS_ADDR"], printed["AA_METRICS_ADDR"]);
    assert!(doc["AA_METRICS_ADDR"].starts_with("127.0.0.1:"), "must be loopback");
    // The page's `$PWD` paths, expanded for the directory the test ran in, are the
    // ones `init` printed.
    let pwd = std::fs::canonicalize(r.dir.path()).unwrap();
    let expand = |v: &str| PathBuf::from(v.replace("$PWD", &pwd.display().to_string()));
    assert_eq!(
        expand(&doc["AA_LEASE_POLICY"]),
        PathBuf::from(&printed["AA_LEASE_POLICY"])
    );
    assert_eq!(
        expand(&doc["AA_LEASE_STATE"]),
        PathBuf::from(&printed["AA_LEASE_STATE"])
    );
    // The printed paths are the ones this command just validated.
    assert_eq!(
        Path::new(&printed["AA_LEASE_STATE"]),
        std::fs::canonicalize(&r.state).unwrap()
    );
    assert_eq!(
        Path::new(&printed["AA_LEASE_POLICY"]),
        std::fs::canonicalize(&r.policy).unwrap()
    );
    assert!(r.init_stdout.contains("aa-runtime"), "{}", r.init_stdout);
}
