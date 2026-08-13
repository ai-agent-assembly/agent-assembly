//! Tests for the command-routing layer and the live SIGTERM stop paths
//! (AAASM-3804).
//!
//! The per-command `run()` functions are covered directly elsewhere; here we go
//! through the top-level `commands::dispatch` router (and each group's
//! `dispatch`) to prove the parsed `Commands` enum is wired to the right
//! handler. We also exercise `gateway stop` / `proxy stop` against a real
//! short-lived child process so the actual SIGTERM-and-reap path runs (the
//! existing unit tests only cover the "no PID file" / "already dead" arms).

use std::process::ExitCode;
use std::sync::{Mutex, MutexGuard};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::commands::{self, Commands};
use aa_cli::output::OutputFormat;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

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

/// Spawn a long-lived child so the SIGTERM stop path has a real process to
/// terminate. The caller is responsible for ensuring it is reaped (the stop
/// dispatch does this on success).
fn spawn_sleeper() -> std::process::Child {
    std::process::Command::new("sleep")
        .arg("30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn 'sleep'")
}

// ── top-level router (`commands::dispatch`) ───────────────────────────

#[tokio::test]
async fn dispatch_routes_agent_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [], "page": 1, "per_page": 20, "total": 0
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let code = std::thread::spawn(move || {
        let cmd = Commands::Agent(aa_cli::commands::agent::AgentArgs {
            command: aa_cli::commands::agent::AgentCommands::List(aa_cli::commands::agent::list::ListArgs {
                status: None,
                framework: None,
                watch: false,
            }),
        });
        commands::dispatch(cmd, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
}

#[tokio::test]
async fn dispatch_routes_policy_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [], "page": 1, "per_page": 20, "total": 0
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let code = std::thread::spawn(move || {
        let cmd = Commands::Policy(aa_cli::commands::policy::PolicyArgs {
            command: aa_cli::commands::policy::PolicyCommands::List(aa_cli::commands::policy::list::ListArgs {}),
        });
        commands::dispatch(cmd, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
}

#[tokio::test]
async fn dispatch_routes_approvals_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/approvals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [], "page": 1, "per_page": 20, "total": 0
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let code = std::thread::spawn(move || {
        let cmd = Commands::Approvals(aa_cli::commands::approvals::ApprovalsArgs {
            command: aa_cli::commands::approvals::ApprovalsSubcommand::List(
                aa_cli::commands::approvals::list::ListArgs {
                    output: None,
                    status: None,
                    agent: None,
                },
            ),
        });
        commands::dispatch(cmd, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
}

#[tokio::test]
async fn dispatch_routes_audit_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [], "page": 1, "per_page": 50, "total": 0
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let code = std::thread::spawn(move || {
        let cmd = Commands::Audit(aa_cli::commands::audit::AuditArgs {
            command: aa_cli::commands::audit::AuditCommands::List(aa_cli::commands::audit::list::ListArgs {
                agent: None,
                action: None,
                result: None,
                since: None,
                until: None,
                limit: 50,
                dry_run_only: false,
            }),
        });
        commands::dispatch(cmd, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn dispatch_routes_proxy_status() {
    let _dd = DataDir::new();
    let cmd = Commands::Proxy(aa_cli::commands::proxy::ProxyArgs {
        command: aa_cli::commands::proxy::ProxyCommands::Status(aa_cli::commands::proxy::status::StatusArgs {
            json: true,
        }),
    });
    // No PID file in the isolated data dir → "not running" → SUCCESS.
    assert_eq!(
        commands::dispatch(cmd, &make_context("http://127.0.0.1:1"), OutputFormat::Table),
        ExitCode::SUCCESS
    );
}

// ── live SIGTERM stop paths ───────────────────────────────────────────

#[test]
fn gateway_stop_terminates_live_process() {
    let _dd = DataDir::new();
    let child = spawn_sleeper();
    let pid = child.id();
    // Reap the child as soon as it dies so the stop poll loop sees it exit
    // promptly (an un-reaped zombie still answers `kill(pid, 0)`).
    let reaper = std::thread::spawn(move || {
        let mut c = child;
        let _ = c.wait();
    });
    aa_cli::commands::gateway::pid::write_pid(pid, "127.0.0.1:50051", "2026-05-18T00:00:00Z").unwrap();

    assert_eq!(aa_cli::commands::gateway::stop::dispatch(), ExitCode::SUCCESS);
    reaper.join().unwrap();
    // The SIGTERM path removes the PID file once the process is gone.
    assert!(aa_cli::commands::gateway::pid::read_pid().is_none());
}

#[test]
fn proxy_stop_terminates_live_process() {
    let _dd = DataDir::new();
    let child = spawn_sleeper();
    let pid = child.id();
    let reaper = std::thread::spawn(move || {
        let mut c = child;
        let _ = c.wait();
    });
    std::fs::write(
        aa_cli::commands::proxy::pid::pid_path(),
        format!("{pid}\n127.0.0.1:8899\n"),
    )
    .unwrap();

    assert_eq!(aa_cli::commands::proxy::stop::dispatch(), ExitCode::SUCCESS);
    reaper.join().unwrap();
    assert!(aa_cli::commands::proxy::pid::read_pid().is_none());
}
