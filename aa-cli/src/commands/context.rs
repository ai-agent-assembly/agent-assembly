//! `aasm context` — manage named API contexts.

use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::config;

/// Environment variable that supplies the API key for `aasm context set`
/// without exposing it on the command line.
///
/// Argv is world-readable via `ps`, `/proc/<pid>/cmdline`, and shell history,
/// so passing `--api-key` leaks the operator bearer token to any local user.
const API_KEY_ENV: &str = "AASM_API_KEY";

/// Resolve the API key for `context set`, preferring the `AASM_API_KEY`
/// environment variable over the `--api-key` flag.
///
/// The flag still works to avoid breaking existing scripts, but because it
/// leaks the secret into argv we emit a warning recommending the env var when
/// it is used. An empty env var is treated as unset.
fn resolve_set_api_key(flag: Option<String>) -> Option<String> {
    if let Some(key) = flag {
        eprintln!(
            "warning: passing --api-key exposes the key in process listings \
             (ps, /proc/<pid>/cmdline) and shell history; prefer the \
             {API_KEY_ENV} environment variable instead"
        );
        return Some(key);
    }
    std::env::var(API_KEY_ENV).ok().filter(|key| !key.is_empty())
}

/// Arguments for the `aasm context` subcommand group.
#[derive(Args)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub command: ContextCommands,
}

/// Available context subcommands.
#[derive(Subcommand)]
pub enum ContextCommands {
    /// List all configured contexts.
    List,
    /// Set or create a named context.
    Set(SetArgs),
    /// Switch the default context.
    Use(UseArgs),
}

/// Arguments for `aasm context set`.
#[derive(Args)]
pub struct SetArgs {
    /// Name of the context to create or update.
    pub name: String,
    /// API URL for this context.
    #[arg(long)]
    pub api_url: String,
    /// API key for this context (optional). Prefer the `AASM_API_KEY`
    /// environment variable: passing `--api-key` leaks the key into argv
    /// (`ps`, `/proc/<pid>/cmdline`, shell history).
    #[arg(long)]
    pub api_key: Option<String>,
}

/// Arguments for `aasm context use`.
#[derive(Args)]
pub struct UseArgs {
    /// Name of the context to set as default.
    pub name: String,
}

/// Dispatch a context subcommand.
pub fn dispatch(args: ContextArgs) -> ExitCode {
    match args.command {
        ContextCommands::List => run_list(),
        ContextCommands::Set(set_args) => run_set(set_args),
        ContextCommands::Use(use_args) => run_use(use_args),
    }
}

/// List all configured contexts with their API URLs.
fn run_list() -> ExitCode {
    let cfg = match config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if cfg.contexts.is_empty() {
        println!("No contexts configured. Use `aasm context set` to add one.");
        return ExitCode::SUCCESS;
    }

    let default_name = cfg.default_context.as_deref().unwrap_or("");
    for (name, ctx) in &cfg.contexts {
        let marker = if name == default_name { " *" } else { "" };
        let key_status = if ctx.api_key.is_some() { " (key set)" } else { "" };
        println!("{name}{marker}  {}{key_status}", ctx.api_url);
    }
    ExitCode::SUCCESS
}

/// Create or update a named context in the config file.
fn run_set(args: SetArgs) -> ExitCode {
    let mut cfg = match config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    cfg.contexts.insert(
        args.name.clone(),
        config::ContextConfig {
            api_url: args.api_url,
            api_key: resolve_set_api_key(args.api_key),
        },
    );

    // If this is the first context, make it the default.
    if cfg.contexts.len() == 1 {
        cfg.default_context = Some(args.name.clone());
    }

    if let Err(e) = config::save(&cfg) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    println!("Context '{}' saved.", args.name);
    ExitCode::SUCCESS
}

/// Switch the default context.
fn run_use(args: UseArgs) -> ExitCode {
    let mut cfg = match config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !cfg.contexts.contains_key(&args.name) {
        eprintln!("error: context '{}' not found", args.name);
        eprintln!("Available contexts:");
        for name in cfg.contexts.keys() {
            eprintln!("  {name}");
        }
        return ExitCode::FAILURE;
    }

    cfg.default_context = Some(args.name.clone());

    if let Err(e) = config::save(&cfg) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    println!("Switched to context '{}'.", args.name);
    ExitCode::SUCCESS
}
