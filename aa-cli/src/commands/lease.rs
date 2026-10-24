//! `aasm lease` — operator commands for the capability-lease state record
//! (AAASM-6259).
//!
//! These commands create, revoke against and print the record defined in
//! [`aa_runtime::lease::state`]; the format, locking and atomic-write rules
//! live there so the CLI and the runtime cannot drift. The runtime does not
//! consult the record yet, so nothing here changes what a running agent may
//! do.

use std::path::PathBuf;
use std::process::ExitCode;

/// Arguments for `aasm lease`.
#[derive(Debug, clap::Args)]
pub struct LeaseArgs {
    #[command(subcommand)]
    pub subcommand: LeaseSubcommand,
}

/// Subcommands available under `aasm lease`.
#[derive(Debug, clap::Subcommand)]
pub enum LeaseSubcommand {
    /// Create the state record for a new run (never overwrites without --force).
    Init(InitArgs),
    /// Revoke lease ids in an existing state record.
    Revoke(RevokeArgs),
    /// Print the state record as JSON.
    Status(StatusArgs),
}

/// Arguments for `aasm lease init`.
#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Path of the lease state record to create.
    #[arg(long, env = "AA_LEASE_STATE")]
    pub state: PathBuf,

    /// Agent id the run's leases are issued to.
    #[arg(long)]
    pub subject: String,

    /// Digest of the policy this run is bound to (lowercase hex, at least 12 characters).
    #[arg(long)]
    pub policy_digest: String,

    /// Replace an existing record: a new run at generation 1 with an empty
    /// revocation set and a new issue time, so every earlier lease id is retired.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `aasm lease revoke`.
#[derive(Debug, clap::Args)]
pub struct RevokeArgs {
    /// Path of an existing lease state record.
    #[arg(long, env = "AA_LEASE_STATE")]
    pub state: PathBuf,

    /// Lease id(s) to revoke; repeatable.
    #[arg(long = "lease-id", required = true, num_args = 1..)]
    pub lease_id: Vec<String>,
}

/// Arguments for `aasm lease status`.
#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// Path of the lease state record.
    #[arg(long, env = "AA_LEASE_STATE")]
    pub state: PathBuf,
}

/// Dispatch the `lease` subcommand.
pub fn dispatch(args: LeaseArgs) -> ExitCode {
    let result = match args.subcommand {
        LeaseSubcommand::Init(a) => imp::init(&a),
        LeaseSubcommand::Revoke(a) => imp::revoke(&a),
        LeaseSubcommand::Status(a) => imp::status(&a),
    };
    match result {
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
mod imp {
    use super::{InitArgs, RevokeArgs, StatusArgs};
    use aa_runtime::lease::state;

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn init(a: &InitArgs) -> Result<String, state::LeaseStateError> {
        let s = state::init_run(&a.state, &a.subject, &a.policy_digest, now_unix(), a.force)?;
        let prefix = s.lease_id_prefix();
        Ok(format!(
            "initialized lease state at {} (generation {})\n\
             lease ids for this run have the form {}<domain>\n",
            a.state.display(),
            s.generation(),
            prefix
        ))
    }

    pub fn revoke(a: &RevokeArgs) -> Result<String, state::LeaseStateError> {
        let s = state::revoke_ids(&a.state, &a.lease_id)?;
        Ok(format!("generation {}\n", s.generation()))
    }

    pub fn status(a: &StatusArgs) -> Result<String, state::LeaseStateError> {
        let bytes = state::load(&a.state)?.to_bytes();
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(not(unix))]
mod imp {
    use super::{InitArgs, RevokeArgs, StatusArgs};

    fn unsupported() -> Result<String, String> {
        Err("`aasm lease` is only supported on Unix hosts".to_string())
    }
    pub fn init(_: &InitArgs) -> Result<String, String> {
        unsupported()
    }
    pub fn revoke(_: &RevokeArgs) -> Result<String, String> {
        unsupported()
    }
    pub fn status(_: &StatusArgs) -> Result<String, String> {
        unsupported()
    }
}
