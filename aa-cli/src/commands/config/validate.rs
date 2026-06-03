//! `aasm config validate` — local validation of `agent-assembly.toml`.

use std::path::PathBuf;
use std::process::ExitCode;

use aa_storage::{Registry, StorageConfig};
use clap::Args;
use serde::Deserialize;

/// Arguments for `aasm config validate`.
#[derive(Args)]
pub struct ValidateArgs {
    /// Path to the `agent-assembly.toml` file to validate.
    pub file: PathBuf,
}

/// Minimal view of `agent-assembly.toml` covering the sections this command
/// validates. Unknown sections are ignored.
#[derive(Deserialize)]
struct RuntimeConfig {
    storage: Option<StorageConfig>,
}

/// Execute `aasm config validate`.
///
/// Parses the TOML file and resolves every `[storage]` driver name against the
/// built-in driver registry. Exits 0 when valid; 1 with the error on stderr
/// otherwise.
pub fn run(args: ValidateArgs) -> ExitCode {
    let contents = match std::fs::read_to_string(&args.file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to read {}: {e}", args.file.display());
            return ExitCode::FAILURE;
        }
    };

    let config: RuntimeConfig = match toml::from_str(&contents) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: invalid TOML in {}: {e}", args.file.display());
            return ExitCode::FAILURE;
        }
    };

    let Some(storage) = config.storage else {
        eprintln!("error: {} has no [storage] section", args.file.display());
        return ExitCode::FAILURE;
    };

    let mut registry = Registry::new();
    aa_storage::builtin::register_builtin_drivers(&mut registry);

    match registry.validate(&storage) {
        Ok(()) => {
            println!("Config is valid: {}", args.file.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
