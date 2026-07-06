//! Coverage for `aasm policy simulate` and the filesystem-backed
//! `policy history` / `rollback` / `diff` handlers (AAASM-3812).
//!
//! The existing simulate tests only exercise the early-return failure arms
//! (bad policy, missing `--against`, `--live`). Here we drive the full
//! replay path: parse an audit-log JSONL, evaluate it against a real
//! `PolicyEngine`, write the JSON report, and assert both the report
//! contents and the exit-code contract (denials → FAILURE). The history
//! handlers use `FsHistoryStore` rooted at `$AA_DATA_DIR`, so an isolated
//! empty data dir lets us cover the empty-listing and not-found error arms
//! deterministically.

use std::io::Write;
use std::process::ExitCode;
use std::sync::{Mutex, MutexGuard};

use aa_cli::commands::policy::history::{self, DiffArgs, HistoryArgs, RollbackArgs};
use aa_cli::commands::policy::simulate::{self, SimulateArgs};

/// Minimal allow-everything policy (section-based schema, AAASM-3351).
const ALLOW_ALL_POLICY: &str = "version: \"1.0\"\n";
/// Policy that denies the `bash` tool, forcing a simulated denial.
const DENY_BASH_POLICY: &str = "version: \"1.0\"\ntools:\n  bash:\n    allow: false\n";

/// Serialize one audit-log line wrapping a `ToolCall` governance action.
fn tool_call_jsonl(tool: &str) -> String {
    let payload = serde_json::to_string(&aa_core::GovernanceAction::ToolCall {
        name: tool.to_string(),
        args: "{}".to_string(),
    })
    .unwrap();
    serde_json::to_string(&serde_json::json!({
        "event_type": "ToolCallIntercepted",
        "agent_id": "test-agent",
        "payload": payload,
    }))
    .unwrap()
}

/// Serialize one audit-log line whose `payload` is not a valid
/// `GovernanceAction`, so the replay yields a per-event `decision = "error"`
/// outcome (a malformed / schema-drifted event).
fn unparseable_jsonl() -> String {
    serde_json::to_string(&serde_json::json!({
        "event_type": "ToolCallIntercepted",
        "agent_id": "test-agent",
        "payload": "this is not a serialized governance action",
    }))
    .unwrap()
}

fn write_temp(contents: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

// ── policy simulate: full replay path ─────────────────────────────────

#[test]
fn simulate_allow_all_succeeds_and_writes_report() {
    let policy = write_temp(ALLOW_ALL_POLICY);
    let log = write_temp(&format!(
        "{}\n{}\n",
        tool_call_jsonl("read_file"),
        tool_call_jsonl("write_file")
    ));
    let report_path = tempfile::NamedTempFile::new().unwrap();

    let args = SimulateArgs {
        policy: policy.path().to_path_buf(),
        against: Some(log.path().to_path_buf()),
        live: false,
        duration: None,
        output_file: Some(report_path.path().to_path_buf()),
    };
    assert_eq!(simulate::run(args), ExitCode::SUCCESS);

    // The report file was written and reflects the two allowed events.
    let written = std::fs::read_to_string(report_path.path()).unwrap();
    let report: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(report["total_events"], 2);
    assert_eq!(report["allowed"], 2);
    assert_eq!(report["denied"], 0);
}

#[test]
fn simulate_with_denials_returns_failure() {
    let policy = write_temp(DENY_BASH_POLICY);
    let log = write_temp(&format!("{}\n", tool_call_jsonl("bash")));

    let args = SimulateArgs {
        policy: policy.path().to_path_buf(),
        against: Some(log.path().to_path_buf()),
        live: false,
        duration: None,
        output_file: None,
    };
    // A denied event drives the `denied > 0` exit-code branch (and the
    // flagged-outcomes print loop).
    assert_eq!(simulate::run(args), ExitCode::FAILURE);
}

#[test]
fn simulate_unreadable_against_file_returns_failure() {
    let policy = write_temp(ALLOW_ALL_POLICY);
    let args = SimulateArgs {
        policy: policy.path().to_path_buf(),
        against: Some(std::path::PathBuf::from("/nonexistent/aaasm-3812/audit-log.jsonl")),
        live: false,
        duration: None,
        output_file: None,
    };
    assert_eq!(simulate::run(args), ExitCode::FAILURE);
}

#[test]
fn simulate_unparseable_events_return_failure() {
    // AAASM-4175: a fully-unparseable / schema-drifted audit log must fail the
    // exit gate. Previously the exit code keyed only on `denied`, so every
    // event erroring out still yielded exit 0 — CI gating on the exit status
    // treated a broken log as PASS.
    let policy = write_temp(ALLOW_ALL_POLICY);
    let log = write_temp(&format!("{}\n{}\n", unparseable_jsonl(), unparseable_jsonl()));
    let report_path = tempfile::NamedTempFile::new().unwrap();

    let args = SimulateArgs {
        policy: policy.path().to_path_buf(),
        against: Some(log.path().to_path_buf()),
        live: false,
        duration: None,
        output_file: Some(report_path.path().to_path_buf()),
    };
    assert_eq!(simulate::run(args), ExitCode::FAILURE);

    // The report tallies the unparseable events as errored, with no denials —
    // the errored count, not denied, is what drives the failure here.
    let written = std::fs::read_to_string(report_path.path()).unwrap();
    let report: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(report["total_events"], 2);
    assert_eq!(report["errored"], 2);
    assert_eq!(report["denied"], 0);
}

#[test]
fn simulate_one_unparseable_among_allowed_returns_failure() {
    // A single unparseable event among otherwise-allowed events must still
    // fail: the old `denied > 0` gate would have passed this log as SUCCESS.
    let policy = write_temp(ALLOW_ALL_POLICY);
    let log = write_temp(&format!("{}\n{}\n", tool_call_jsonl("read_file"), unparseable_jsonl()));

    let args = SimulateArgs {
        policy: policy.path().to_path_buf(),
        against: Some(log.path().to_path_buf()),
        live: false,
        duration: None,
        output_file: None,
    };
    assert_eq!(simulate::run(args), ExitCode::FAILURE);
}

// ── policy history / rollback / diff against an isolated store ─────────

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Point `AA_DATA_DIR` at a fresh empty temp dir for the guard's lifetime so
/// `FsHistoryStore::default_config()` resolves to an isolated, empty store.
struct DataDir {
    _lock: MutexGuard<'static, ()>,
    _tmp: tempfile::TempDir,
    prior: Option<String>,
}

impl DataDir {
    fn new() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let prior = std::env::var("AA_DATA_DIR").ok();
        std::env::set_var("AA_DATA_DIR", tmp.path());
        Self {
            _lock: lock,
            _tmp: tmp,
            prior,
        }
    }
}

impl Drop for DataDir {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var("AA_DATA_DIR", v),
            None => std::env::remove_var("AA_DATA_DIR"),
        }
    }
}

#[test]
fn history_empty_store_succeeds() {
    let _dd = DataDir::new();
    // No versions have been applied in the isolated data dir → the empty
    // listing arm is taken and the command still exits 0.
    assert_eq!(history::run_history(HistoryArgs { limit: 10 }), ExitCode::SUCCESS);
}

#[test]
fn rollback_nonexistent_version_returns_failure() {
    let _dd = DataDir::new();
    assert_eq!(
        history::run_rollback(RollbackArgs {
            version: "deadbeefdeadbeef".to_string(),
        }),
        ExitCode::FAILURE
    );
}

#[test]
fn diff_nonexistent_versions_returns_failure() {
    let _dd = DataDir::new();
    assert_eq!(
        history::run_diff(DiffArgs {
            version_a: "aaaaaaaaaaaa".to_string(),
            version_b: "bbbbbbbbbbbb".to_string(),
        }),
        ExitCode::FAILURE
    );
}
