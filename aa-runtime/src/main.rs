//! `aa-runtime` sidecar binary entry point.

fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().json())
        .init();
}

/// Meta-flag the binary handles before doing any real work.
///
/// `aa-runtime` takes no positional arguments and is configured entirely through
/// environment variables, but `--help`/`--version` must still short-circuit
/// *before* config load — otherwise an operator inspecting the image gets a Rust
/// panic on the required `AA_AGENT_ID` instead of documented usage (AAASM-5012).
enum CliAction {
    Help,
    Version,
    Run,
}

/// Scan CLI args for `--help`/`--version` meta-flags.
///
/// `--help` wins over `--version` when both are present, matching the convention
/// of clap and most CLIs. Unknown flags are ignored here so normal startup
/// proceeds to env-based configuration.
fn parse_cli_action(args: impl IntoIterator<Item = String>) -> CliAction {
    let mut version = false;
    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => return CliAction::Help,
            "--version" | "-V" => version = true,
            _ => {}
        }
    }
    if version {
        CliAction::Version
    } else {
        CliAction::Run
    }
}

fn print_usage() {
    let bin = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    println!(
        "{bin} {version}
Authoritative enforcement sidecar for Agent Assembly.

USAGE:
    {bin} [OPTIONS]

OPTIONS:
    -h, --help       Print this help and exit
    -V, --version    Print version and exit

CONFIGURATION:
    aa-runtime takes no positional arguments; it is configured entirely through
    environment variables.

    Required:
      AA_AGENT_ID              Unique agent identifier (must not contain '/' or '..')

    Common:
      AA_GATEWAY_ENDPOINT      Gateway URL for policy/event RPCs (e.g. http://gateway:50051)
      AA_POLICY_PATH           Path to policy.toml (default: /etc/aa/policy.toml)
      AA_METRICS_ADDR          Prometheus metrics bind address (default: 0.0.0.0:8080)
      AA_GATEWAY_FAIL_CLOSED   Deny when the gateway is unreachable (default: true)

    See the aa-runtime documentation for the full list of AA_* variables."
    );
}

fn main() {
    // Handle meta-flags before tracing init, privilege enforcement, or config
    // load so `--help`/`--version` always print and exit 0 — even in an
    // unconfigured image where `AA_AGENT_ID` is unset (AAASM-5012).
    match parse_cli_action(std::env::args().skip(1)) {
        CliAction::Help => {
            print_usage();
            return;
        }
        CliAction::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            return;
        }
        CliAction::Run => {}
    }

    init_tracing();

    // AAASM-3605: the runtime must hold NO BPF-class capabilities — probe
    // loading is delegated to the privileged aa-ebpf-loaderd daemon. Drop and
    // assert before doing anything else, so a misconfigured deployment that
    // granted CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON fails fast instead of running
    // as an over-privileged target for an adversarial agent.
    aa_runtime::privilege::enforce_least_privilege().expect("least-privilege self-check failed");

    let config = aa_runtime::config::RuntimeConfig::from_env().expect("failed to load runtime configuration");

    tracing::info!(
        agent_id = %config.agent_id,
        worker_threads = config.worker_threads,
        shutdown_timeout_secs = config.shutdown_timeout_secs,
        ipc_max_connections = config.ipc_max_connections,
        "configuration loaded"
    );

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    if config.worker_threads > 0 {
        builder.worker_threads(config.worker_threads);
    }

    builder
        .build()
        .expect("failed to build Tokio runtime")
        .block_on(aa_runtime::run(config));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(args: &[&str]) -> CliAction {
        parse_cli_action(args.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn no_flags_runs() {
        assert!(matches!(action(&[]), CliAction::Run));
        assert!(matches!(action(&["--unknown", "positional"]), CliAction::Run));
    }

    #[test]
    fn help_flags_detected() {
        assert!(matches!(action(&["--help"]), CliAction::Help));
        assert!(matches!(action(&["-h"]), CliAction::Help));
    }

    #[test]
    fn version_flags_detected() {
        assert!(matches!(action(&["--version"]), CliAction::Version));
        assert!(matches!(action(&["-V"]), CliAction::Version));
    }

    #[test]
    fn help_takes_precedence_over_version() {
        assert!(matches!(action(&["--version", "--help"]), CliAction::Help));
        assert!(matches!(action(&["--help", "--version"]), CliAction::Help));
    }
}
