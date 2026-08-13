//! `aasm uninstall` — thin wrapper over the installer's uninstall engine.
//!
//! The curl installer (`scripts/install-cli.sh`) is the single source of truth
//! for the manifest-driven removal + `--purge` logic (AAASM-3957, shell-primary
//! by design). On install it persists a runnable copy at
//! `${AASM_STATE_DIR:-~/.aasm}/aasm-uninstall`; this command forwards to it so
//! the CLI, the curl installer, and the offline fallback all share one engine
//! (no divergent rm/purge logic to keep in sync). Homebrew-managed installs are
//! detected *by the engine* and redirected to `brew uninstall`.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// `aasm uninstall` command-line arguments (forwarded verbatim to the engine).
#[derive(Debug, clap::Args)]
pub struct UninstallArgs {
    /// Remove only these components (comma-separated: cli,runtime,proxy,ebpf).
    #[arg(long)]
    pub components: Option<String>,

    /// Remove a single component; repeat the flag for several.
    #[arg(long)]
    pub component: Vec<String>,

    /// Also remove Agent Assembly-owned local data (config + state).
    #[arg(long)]
    pub purge: bool,

    /// Uninstall all components (the default scope; accepted for explicitness).
    #[arg(long)]
    pub all: bool,

    /// Show what would be removed without changing anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the `--purge` confirmation prompt (non-interactive).
    #[arg(short = 'y', long)]
    pub yes: bool,
}

/// Resolve the persisted uninstaller path (`${AASM_STATE_DIR:-~/.aasm}/aasm-uninstall`).
///
/// Returns `None` only when no home directory can be resolved and
/// `AASM_STATE_DIR` is unset (rare; sandboxed environments).
fn uninstaller_path() -> Option<PathBuf> {
    let base = match std::env::var_os("AASM_STATE_DIR") {
        Some(v) => PathBuf::from(v),
        None => dirs::home_dir()?.join(".aasm"),
    };
    Some(base.join("aasm-uninstall"))
}

/// Entry point for `aasm uninstall`. Forwards flags to the persisted engine.
pub fn dispatch(args: UninstallArgs) -> ExitCode {
    let helper = match uninstaller_path() {
        Some(p) if p.exists() => p,
        _ => {
            eprintln!(
                "aasm uninstall: no local uninstaller found.\n\
                 If you installed via Homebrew, run:  brew uninstall aasm\n\
                 Otherwise use the fallback:\n  \
                 curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --uninstall"
            );
            return ExitCode::FAILURE;
        }
    };

    let mut cmd = Command::new("sh");
    cmd.arg(&helper).arg("--uninstall");
    if let Some(c) = &args.components {
        cmd.arg("--components").arg(c);
    }
    for c in &args.component {
        cmd.arg("--component").arg(c);
    }
    if args.all {
        cmd.arg("--all");
    }
    if args.purge {
        cmd.arg("--purge");
    }
    if args.dry_run {
        cmd.arg("--dry-run");
    }
    if args.yes {
        cmd.arg("--yes");
    }

    match cmd.status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("aasm uninstall: failed to run {}: {e}", helper.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `AASM_STATE_DIR` overrides `~/.aasm` so custom layouts (and tests) resolve
    /// the engine deterministically. nextest runs each test in its own process,
    /// so the env mutation is isolated.
    #[test]
    fn uninstaller_path_honors_state_dir_override() {
        std::env::set_var("AASM_STATE_DIR", "/tmp/aa-state-xyz");
        let p = uninstaller_path().expect("path resolves when AASM_STATE_DIR is set");
        std::env::remove_var("AASM_STATE_DIR");
        assert_eq!(p, PathBuf::from("/tmp/aa-state-xyz/aasm-uninstall"));
    }
}
