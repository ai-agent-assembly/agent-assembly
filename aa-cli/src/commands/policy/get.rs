//! `aasm policy get` — display the currently active (or a specific) policy.

use std::process::ExitCode;

use aa_gateway::policy::history::{FsHistoryStore, HistoryConfig, PolicyHistoryStore};
use clap::Args;
use serde::Deserialize;

use crate::config::ResolvedContext;

/// Arguments for `aasm policy get`.
#[derive(Args)]
pub struct GetArgs {
    /// Version identifier (SHA-256 prefix) to retrieve.
    /// Shows the currently active policy when omitted.
    #[arg(long)]
    pub version: Option<String>,
}

/// Response from `GET /api/v1/policies/active`. Only the YAML is consumed here.
#[derive(Debug, Deserialize)]
struct ActivePolicyResponse {
    /// Raw YAML content of the currently active governance policy.
    policy_yaml: String,
}

/// Execute the `aasm policy get` command.
///
/// When `--version` is provided, retrieves that specific policy version from
/// the local version-history store. Otherwise, resolves the currently active
/// policy from the gateway (the same source `apply` and `list` use), so a
/// policy that was just applied is found instead of reporting "no versions".
pub fn run(args: GetArgs, ctx: &ResolvedContext) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        match args.version {
            Some(version) => get_by_version(&version, HistoryConfig::default_config()).await,
            None => get_active(ctx).await,
        }
    })
}

/// Resolve the currently active policy from the gateway and print its YAML.
async fn get_active(ctx: &ResolvedContext) -> ExitCode {
    match crate::client::get_json::<ActivePolicyResponse>(ctx, "/api/v1/policies/active").await {
        Ok(resp) => {
            print!("{}", resp.policy_yaml);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Retrieve a specific policy version from the local history store.
async fn get_by_version(version: &str, config: HistoryConfig) -> ExitCode {
    let store = FsHistoryStore::new(config);
    match store.get(version).await {
        Ok(snapshot) => {
            print!("{}", snapshot.yaml_content);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(dir: &std::path::Path) -> HistoryConfig {
        HistoryConfig {
            history_dir: dir.join("policy-history"),
            max_versions: 100,
        }
    }

    #[test]
    fn get_by_version_after_save_exits_success() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let store = FsHistoryStore::new(config.clone());
        let yaml = "tier: low\nrules:\n  - id: r1\n    description: test\n    match:\n      actions: [\"*\"]\n    effect: allow\n    audit: true\n";
        let meta = rt.block_on(store.save(yaml, Some("test"))).unwrap();

        let exit = rt.block_on(get_by_version(&meta.sha256[..12], config));
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[test]
    fn get_unknown_version_exits_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let exit = rt.block_on(get_by_version("nonexistent123", config));
        assert_eq!(exit, ExitCode::FAILURE);
    }
}
