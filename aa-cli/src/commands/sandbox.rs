//! `aasm sandbox` subcommand — execute WebAssembly tools inside the
//! Agent Assembly tool-execution sandbox (highlight ④ of the product
//! spec). Surfaces [`aa_sandbox::SandboxRuntime`] to OSS users so the
//! filesystem + CPU + memory + wall-clock budgets enforced by
//! `aa-sandbox` are reachable from the `aasm` CLI without going
//! through the cloud `aa-api` `/dispatch_tool` HTTP route.
//!
//! Issue: AAASM-2340.

use std::path::PathBuf;
use std::process::ExitCode;

use aa_sandbox::policy::{SandboxConfig, SandboxLimits};
use aa_sandbox::runtime::SandboxRuntime;

/// Arguments for `aasm sandbox`.
#[derive(Debug, clap::Args)]
pub struct SandboxArgs {
    #[command(subcommand)]
    pub subcommand: SandboxSubcommand,
}

/// Subcommands available under `aasm sandbox`.
#[derive(Debug, clap::Subcommand)]
pub enum SandboxSubcommand {
    /// Run a WebAssembly module inside a fresh sandbox and report the outcome.
    Run(RunArgs),
    /// Show the default sandbox runtime limits.
    Info,
}

/// Arguments for `aasm sandbox run`.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Path to a `.wasm` module to execute under WASI preview 1.
    pub wasm: PathBuf,

    /// Wasmtime instruction-fuel budget. Defaults to the safe-by-default
    /// 10M units; pass a larger value for long-running tools.
    #[arg(long)]
    pub fuel: Option<u64>,

    /// Maximum linear-memory pages (1 page = 64 KiB). Defaults to 16 (1 MiB).
    #[arg(long)]
    pub memory_pages: Option<u32>,

    /// Wall-clock deadline in milliseconds. Defaults to 5000 (5s).
    #[arg(long)]
    pub wall_clock_ms: Option<u64>,
}

/// Dispatch the `sandbox` subcommand.
pub fn dispatch(args: SandboxArgs) -> ExitCode {
    match args.subcommand {
        SandboxSubcommand::Run(run) => run_wasm(run),
        SandboxSubcommand::Info => print_info(),
    }
}

fn run_wasm(args: RunArgs) -> ExitCode {
    let bytes = match std::fs::read(&args.wasm) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: failed to read {}: {e}", args.wasm.display());
            return ExitCode::FAILURE;
        }
    };

    let limits = SandboxLimits {
        fuel: args.fuel.unwrap_or(SandboxLimits::default().fuel),
        memory_pages: args.memory_pages.unwrap_or(SandboxLimits::default().memory_pages),
        wall_clock_ms: args.wall_clock_ms.unwrap_or(SandboxLimits::default().wall_clock_ms),
    };
    let config = SandboxConfig {
        preopened_dirs: Vec::new(),
        limits,
        ..Default::default()
    };

    let runtime = match SandboxRuntime::new(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to build sandbox runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.run_tool(&bytes, &[]) {
        Ok(output) => {
            println!("sandbox exited cleanly (exit_code={})", output.exit_code);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sandbox refused or trapped the module: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_info() -> ExitCode {
    let limits = SandboxLimits::default();
    println!("aasm sandbox — WASI preview 1 tool-execution sandbox");
    println!("  fuel (instructions):      {}", limits.fuel);
    println!(
        "  memory ceiling:           {} pages ({} KiB)",
        limits.memory_pages,
        (limits.memory_pages as usize) * 64
    );
    println!("  wall-clock deadline (ms): {}", limits.wall_clock_ms);
    println!("  preopened dirs:           (none — fully sealed FS)");
    ExitCode::SUCCESS
}
