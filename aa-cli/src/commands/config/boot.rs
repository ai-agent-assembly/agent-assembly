//! `aasm config boot` — build the storage backends declared in
//! `agent-assembly.toml` and serve a sample policy lookup, proving the config
//! wires up end-to-end. Smoke-tests an all-`"memory"` (or any) deployment.

use std::path::PathBuf;
use std::process::ExitCode;

use aa_storage::{AgentId, Registry, StorageConfig, StorageError};
use clap::Args;
use serde::Deserialize;

/// Arguments for `aasm config boot`.
#[derive(Args)]
pub struct BootArgs {
    /// Path to the `agent-assembly.toml` file to boot from.
    pub file: PathBuf,
}

/// Minimal view of `agent-assembly.toml` covering the sections this command
/// reads. Unknown sections are ignored.
#[derive(Deserialize)]
struct RuntimeConfig {
    storage: Option<StorageConfig>,
}

/// Execute `aasm config boot`.
///
/// Resolves every `[storage]` driver through the registry (built-in driver
/// names plus the real in-memory driver), builds each backend, and performs a
/// sample policy lookup. Exits 0 on success; 1 with the error on stderr.
pub fn run(args: BootArgs) -> ExitCode {
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

    // Built-in driver names, then the real OSS drivers — `register_*` is
    // last-write-wins, so these replace the matching placeholders. The Redis
    // driver only registers the L2 kinds it backs (policy / session /
    // rate-limit); the durable kinds stay on the placeholder.
    let mut registry = Registry::new();
    aa_storage::builtin::register_builtin_drivers(&mut registry);
    aa_storage_memory::register(&mut registry);
    aa_storage_redis::register(&mut registry);

    if let Err(e) = registry.validate(&storage) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    let policy_store = match registry.build_policy_store(&storage) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Build the remaining five backends so a misconfigured kind fails the boot.
    let others = [
        ("audit_sink", registry.build_audit_sink(&storage).map(drop)),
        ("session_store", registry.build_session_store(&storage).map(drop)),
        ("credential_store", registry.build_credential_store(&storage).map(drop)),
        (
            "rate_limit_counter",
            registry.build_rate_limit_counter(&storage).map(drop),
        ),
        ("lifecycle_store", registry.build_lifecycle_store(&storage).map(drop)),
    ];
    for (kind, result) in others {
        if let Err(e) = result {
            eprintln!("error: failed to build {kind}: {e}");
            return ExitCode::FAILURE;
        }
    }

    // Serve a sample policy lookup end-to-end (config commands run outside a
    // runtime, so build a small one for the async trait call).
    let agent = AgentId::from_bytes([0u8; 16]);
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let lookup = runtime.block_on(policy_store.get_policy(&agent));

    println!("Booted storage from {}", args.file.display());
    println!("  policy_store       = {}", storage.policy_store);
    println!("  audit_sink         = {}", storage.audit_sink);
    println!("  session_store      = {}", storage.session_store);
    println!("  credential_store   = {}", storage.credential_store);
    println!("  rate_limit_counter = {}", storage.rate_limit_counter);
    println!("  lifecycle_store    = {}", storage.lifecycle_store);

    let agent_hex = hex::encode(agent.as_bytes());
    match lookup {
        Ok(policy) => println!("  policy lookup for agent {agent_hex}: found policy {:?}", policy.name),
        Err(StorageError::NotFound(_)) => {
            println!("  policy lookup for agent {agent_hex}: no policy on record (empty store)")
        }
        Err(e) => {
            eprintln!("error: policy lookup failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")).join(name)
    }

    #[test]
    fn all_memory_config_boots_successfully() {
        let args = BootArgs {
            file: fixture("storage_all_memory.toml"),
        };
        assert_eq!(run(args), ExitCode::SUCCESS);
    }

    #[test]
    fn missing_file_exits_failure() {
        let args = BootArgs {
            file: PathBuf::from("/tmp/nonexistent-aaasm-boot-xyz.toml"),
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }
}
