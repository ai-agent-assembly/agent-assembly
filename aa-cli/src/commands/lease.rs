//! `aasm lease` — operator commands for the capability-lease state record
//! (AAASM-6259).
//!
//! These commands create, revoke against and print the record defined in
//! [`aa_runtime::lease::state`]; the format, locking and atomic-write rules
//! live there so the CLI and the runtime cannot drift. A runtime started with
//! `AA_LEASE_POLICY` reads the record (startup binding, then a ~100 ms reload),
//! so `revoke` takes effect there on the runtime's next reload; `--wait-health`
//! makes `revoke` block until the runtime reports it has applied it.

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
    #[arg(long, env = "AA_LEASE_STATE", hide_env_values = true)]
    pub state: PathBuf,

    /// Agent id the run's leases are issued to.
    #[arg(long)]
    pub subject: String,

    /// Digest of the policy this run is bound to (lowercase hex, at least 12 characters).
    #[arg(long, required_unless_present = "policy", conflicts_with = "policy")]
    pub policy_digest: Option<String>,

    /// Policy file to bind to: the digest is computed exactly as the runtime
    /// computes it at startup (`AA_LEASE_POLICY`), so the two cannot disagree.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Replace an existing record: a new run at generation 1 with an empty
    /// revocation set and a new issue time, so every earlier lease id is retired.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `aasm lease revoke`.
#[derive(Debug, clap::Args)]
pub struct RevokeArgs {
    /// Path of an existing lease state record.
    #[arg(long, env = "AA_LEASE_STATE", hide_env_values = true)]
    pub state: PathBuf,

    /// Lease id(s) to revoke; repeatable.
    #[arg(long = "lease-id", required = true, num_args = 1..)]
    pub lease_id: Vec<String>,

    /// Base URL of the runtime's health endpoint (e.g. `http://127.0.0.1:8080`).
    /// When given, `revoke` returns only after `GET /health` reports the new
    /// generation (or `denied_all`), and fails if that does not happen within
    /// `--wait-timeout-secs`. Without it the revocation is recorded but is
    /// applied by the runtime only on its next reload (about 100 ms).
    #[arg(long, env = "AA_LEASE_HEALTH_URL")]
    pub wait_health: Option<String>,

    /// How long `--wait-health` waits for the runtime to acknowledge.
    #[arg(long, default_value_t = 5)]
    pub wait_timeout_secs: u64,
}

/// Arguments for `aasm lease status`.
#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// Path of the lease state record.
    #[arg(long, env = "AA_LEASE_STATE", hide_env_values = true)]
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

    fn policy_digest(a: &InitArgs) -> Result<String, String> {
        if let Some(d) = &a.policy_digest {
            return Ok(d.clone());
        }
        let path = a.policy.as_ref().ok_or("--policy or --policy-digest is required")?;
        let resolution = aa_policy::resolve::load(path);
        match resolution.content_digest() {
            Some(d) if matches!(resolution, aa_policy::resolve::PolicyResolution::Enforced { .. }) => {
                Ok(d.strip_prefix("sha256:").unwrap_or(d).to_string())
            }
            _ => Err(format!(
                "{} is not an enforced policy: {}",
                path.display(),
                resolution.summary()
            )),
        }
    }

    pub fn init(a: &InitArgs) -> Result<String, String> {
        let digest = policy_digest(a)?;
        let s = state::init_run(&a.state, &a.subject, &digest, now_unix(), a.force).map_err(|e| e.to_string())?;
        let prefix = s.lease_id_prefix();
        Ok(format!(
            "initialized lease state at {} (generation {})\n\
             lease ids for this run have the form {}<domain>\n",
            a.state.display(),
            s.generation(),
            prefix
        ))
    }

    /// Poll `/health` until the runtime reports `generation` (or `denied_all`,
    /// which denies everything and so also covers the revocation).
    fn wait_for_runtime(base: &str, generation: u64, timeout: std::time::Duration) -> Result<String, String> {
        let url = format!("{}/health", base.trim_end_matches('/'));
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .map_err(|e| e.to_string())?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let last = match client.get(&url).send().and_then(|r| r.json::<serde_json::Value>()) {
                Ok(v) => match v.get("lease_governance") {
                    None => {
                        return Err(format!(
                            "{url} reports no lease_governance: that runtime is not in governed lease mode, \
                             so the revocation is recorded but nothing applied it"
                        ))
                    }
                    Some(g) => {
                        let gen = g.get("generation").and_then(|x| x.as_u64()).unwrap_or(0);
                        let st = g.get("state").and_then(|x| x.as_str()).unwrap_or("");
                        if st == "denied_all" {
                            return Ok("runtime is denying all requests (lease state anomaly)".to_string());
                        }
                        if gen >= generation {
                            return Ok(format!("runtime applied generation {gen}"));
                        }
                        format!("runtime at generation {gen}")
                    }
                },
                Err(e) => e.to_string(),
            };
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "revocation recorded at generation {generation}, but the runtime did not acknowledge it \
                     within {}s ({last}); treat the lease as still usable until it does",
                    timeout.as_secs()
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    pub fn revoke(a: &RevokeArgs) -> Result<String, String> {
        let s = state::revoke_ids(&a.state, &a.lease_id).map_err(|e| e.to_string())?;
        let mut out = format!("generation {}\n", s.generation());
        if let Some(base) = &a.wait_health {
            let note = wait_for_runtime(
                base,
                s.generation(),
                std::time::Duration::from_secs(a.wait_timeout_secs),
            )?;
            out.push_str(&note);
            out.push('\n');
        }
        Ok(out)
    }

    pub fn status(a: &StatusArgs) -> Result<String, String> {
        let bytes = state::load(&a.state).map_err(|e| e.to_string())?.to_bytes();
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
