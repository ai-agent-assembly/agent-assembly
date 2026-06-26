//! Integration tests for `aasm context`, `aasm version`, `aasm sandbox`, and
//! `aasm config` — covering the config-file CRUD path, the gateway version
//! probe (reachable / unreachable / malformed body), and the WASM sandbox
//! entry points.
//!
//! Two harness rules apply here:
//!
//! - `context`/`config` resolve paths from `dirs::home_dir()` → `~/.aa/`. Tests
//!   redirect `$HOME` to a tempdir, serialized through `HOME_LOCK` so the
//!   single-process `cargo test` harness (used by the coverage job) cannot race
//!   on the shared process environment.
//! - `version::run` builds its own tokio runtime internally, so it is invoked on
//!   a dedicated `std::thread` to avoid a nested-runtime panic — mirroring
//!   `tests/topology.rs`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::output::OutputFormat;

/// Serializes every test that mutates the process `HOME` variable.
static HOME_LOCK: Mutex<()> = Mutex::new(());

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

/// Run `f` with `$HOME` pointed at a fresh tempdir, restoring the prior value
/// afterwards. Serialized through `HOME_LOCK`.
fn with_temp_home<R>(f: impl FnOnce(&std::path::Path) -> R) -> R {
    let _guard = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let prev = std::env::var_os("HOME");
    std::env::set_var("HOME", tmp.path());
    let out = f(tmp.path());
    match prev {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
    out
}

// ── context ───────────────────────────────────────────────────────────

#[test]
fn context_set_writes_config_and_marks_first_as_default() {
    with_temp_home(|home| {
        let args = aa_cli::commands::context::ContextArgs {
            command: aa_cli::commands::context::ContextCommands::Set(aa_cli::commands::context::SetArgs {
                name: "prod".to_string(),
                api_url: "https://api.example.com".to_string(),
                api_key: Some("k".to_string()),
            }),
        };
        assert_eq!(aa_cli::commands::context::dispatch(args), ExitCode::SUCCESS);

        // The config file must have landed under the redirected HOME.
        let cfg_path = home.join(".aa/config.yaml");
        assert!(cfg_path.exists(), "config.yaml must be written under $HOME/.aa");

        let cfg = aa_cli::config::load().unwrap();
        assert!(cfg.contexts.contains_key("prod"));
        assert_eq!(cfg.contexts["prod"].api_url, "https://api.example.com");
        // First context created becomes the default.
        assert_eq!(cfg.default_context.as_deref(), Some("prod"));
    });
}

#[test]
fn context_set_second_keeps_first_default() {
    with_temp_home(|_| {
        for (name, url) in [("prod", "https://prod"), ("staging", "https://staging")] {
            let args = aa_cli::commands::context::ContextArgs {
                command: aa_cli::commands::context::ContextCommands::Set(aa_cli::commands::context::SetArgs {
                    name: name.to_string(),
                    api_url: url.to_string(),
                    api_key: None,
                }),
            };
            assert_eq!(aa_cli::commands::context::dispatch(args), ExitCode::SUCCESS);
        }
        let cfg = aa_cli::config::load().unwrap();
        assert_eq!(cfg.contexts.len(), 2);
        // Adding a second context must NOT steal the default.
        assert_eq!(cfg.default_context.as_deref(), Some("prod"));
    });
}

#[test]
fn context_list_empty_succeeds() {
    with_temp_home(|_| {
        let args = aa_cli::commands::context::ContextArgs {
            command: aa_cli::commands::context::ContextCommands::List,
        };
        assert_eq!(aa_cli::commands::context::dispatch(args), ExitCode::SUCCESS);
    });
}

#[test]
fn context_list_with_entries_succeeds() {
    with_temp_home(|_| {
        let set = aa_cli::commands::context::ContextArgs {
            command: aa_cli::commands::context::ContextCommands::Set(aa_cli::commands::context::SetArgs {
                name: "prod".to_string(),
                api_url: "https://prod".to_string(),
                api_key: Some("secret".to_string()),
            }),
        };
        assert_eq!(aa_cli::commands::context::dispatch(set), ExitCode::SUCCESS);

        let list = aa_cli::commands::context::ContextArgs {
            command: aa_cli::commands::context::ContextCommands::List,
        };
        assert_eq!(aa_cli::commands::context::dispatch(list), ExitCode::SUCCESS);
    });
}

#[test]
fn context_use_switches_default() {
    with_temp_home(|_| {
        for name in ["prod", "staging"] {
            let args = aa_cli::commands::context::ContextArgs {
                command: aa_cli::commands::context::ContextCommands::Set(aa_cli::commands::context::SetArgs {
                    name: name.to_string(),
                    api_url: format!("https://{name}"),
                    api_key: None,
                }),
            };
            aa_cli::commands::context::dispatch(args);
        }
        let use_args = aa_cli::commands::context::ContextArgs {
            command: aa_cli::commands::context::ContextCommands::Use(aa_cli::commands::context::UseArgs {
                name: "staging".to_string(),
            }),
        };
        assert_eq!(aa_cli::commands::context::dispatch(use_args), ExitCode::SUCCESS);
        let cfg = aa_cli::config::load().unwrap();
        assert_eq!(cfg.default_context.as_deref(), Some("staging"));
    });
}

#[test]
fn context_use_unknown_fails() {
    with_temp_home(|_| {
        let use_args = aa_cli::commands::context::ContextArgs {
            command: aa_cli::commands::context::ContextCommands::Use(aa_cli::commands::context::UseArgs {
                name: "ghost".to_string(),
            }),
        };
        assert_eq!(aa_cli::commands::context::dispatch(use_args), ExitCode::FAILURE);
    });
}

// ── version ───────────────────────────────────────────────────────────

fn run_version(uri: String, output: OutputFormat) -> ExitCode {
    std::thread::spawn(move || aa_cli::commands::version::run(&make_context(&uri), output))
        .join()
        .unwrap()
}

#[tokio::test]
async fn version_reachable_gateway_table_and_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok",
            "version": "0.3.2",
            "api_version": "v1",
            "uptime_secs": 3,
            "active_connections": 0,
            "pipeline_lag_ms": 0,
            "checks": {}
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    assert_eq!(run_version(uri.clone(), OutputFormat::Table), ExitCode::SUCCESS);
    assert_eq!(run_version(uri, OutputFormat::Json), ExitCode::SUCCESS);
}

#[tokio::test]
async fn version_unreachable_when_gateway_errors_still_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    // A non-2xx health response degrades to "unreachable" rows but exits 0.
    assert_eq!(run_version(server.uri(), OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn version_malformed_health_body_degrades_to_unreachable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;
    assert_eq!(run_version(server.uri(), OutputFormat::Yaml), ExitCode::SUCCESS);
}

// ── sandbox ───────────────────────────────────────────────────────────

#[test]
fn sandbox_info_succeeds() {
    let args = aa_cli::commands::sandbox::SandboxArgs {
        subcommand: aa_cli::commands::sandbox::SandboxSubcommand::Info,
    };
    assert_eq!(aa_cli::commands::sandbox::dispatch(args), ExitCode::SUCCESS);
}

#[test]
fn sandbox_run_missing_file_fails() {
    let args = aa_cli::commands::sandbox::SandboxArgs {
        subcommand: aa_cli::commands::sandbox::SandboxSubcommand::Run(aa_cli::commands::sandbox::RunArgs {
            wasm: PathBuf::from("/tmp/definitely-missing-module-xyz.wasm"),
            fuel: None,
            memory_pages: None,
            wall_clock_ms: None,
        }),
    };
    assert_eq!(aa_cli::commands::sandbox::dispatch(args), ExitCode::FAILURE);
}

#[test]
fn sandbox_run_invalid_wasm_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = dir.path().join("garbage.wasm");
    std::fs::write(&wasm, b"\x00not a real wasm module\x00").unwrap();
    let args = aa_cli::commands::sandbox::SandboxArgs {
        subcommand: aa_cli::commands::sandbox::SandboxSubcommand::Run(aa_cli::commands::sandbox::RunArgs {
            wasm,
            fuel: Some(1_000_000),
            memory_pages: Some(16),
            wall_clock_ms: Some(1000),
        }),
    };
    // The bytes are read successfully, but the sandbox must trap/refuse the
    // non-module input rather than execute it.
    assert_eq!(aa_cli::commands::sandbox::dispatch(args), ExitCode::FAILURE);
}

// ── config validate (via dispatch) ────────────────────────────────────

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")).join(name)
}

#[test]
fn config_validate_dispatch_valid_succeeds() {
    let args = aa_cli::commands::config::ConfigArgs {
        command: aa_cli::commands::config::ConfigCommands::Validate(aa_cli::commands::config::validate::ValidateArgs {
            file: fixture("storage_valid.toml"),
        }),
    };
    assert_eq!(aa_cli::commands::config::dispatch(args), ExitCode::SUCCESS);
}

#[test]
fn config_validate_dispatch_missing_file_fails() {
    let args = aa_cli::commands::config::ConfigArgs {
        command: aa_cli::commands::config::ConfigCommands::Validate(aa_cli::commands::config::validate::ValidateArgs {
            file: PathBuf::from("/tmp/nonexistent-aasm-config-zzz.toml"),
        }),
    };
    assert_eq!(aa_cli::commands::config::dispatch(args), ExitCode::FAILURE);
}
