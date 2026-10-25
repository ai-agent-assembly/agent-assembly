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
    #[arg(long, env = "AA_LEASE_HEALTH_URL", hide_env_values = true)]
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
            eprintln!("error: {}", e.msg);
            ExitCode::from(e.code)
        }
    }
}

/// Exit status of `aasm lease revoke --wait-health` when the runtime reports
/// `denied_all`. The revocation is recorded and everything is refused, but the
/// runtime is no longer governing by lease; a script must not read that as the
/// plain success of "revoked and applied".
pub const EXIT_RUNTIME_DENYING_ALL: u8 = 3;

/// A failed subcommand: the message for stderr and the process exit status.
#[derive(Debug)]
pub struct Failure {
    msg: String,
    code: u8,
}

impl From<String> for Failure {
    fn from(msg: String) -> Self {
        Self { msg, code: 1 }
    }
}

#[cfg(unix)]
mod imp {
    use super::{Failure, InitArgs, RevokeArgs, StatusArgs};
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

    /// The record goes next to existing siblings, so its directory must already
    /// exist; creating it here would pick a mode for a directory the operator
    /// never named. Said up front because the underlying error is a bare
    /// "No such file or directory" with no path.
    fn require_state_dir(path: &std::path::Path) -> Result<(), String> {
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => return Ok(()),
        };
        if dir.is_dir() {
            return Ok(());
        }
        Err(format!(
            "the directory {} for --state {} does not exist; it must exist before `aasm lease init` (create it with \
             `mkdir -p {}` and keep it private to your user)",
            dir.display(),
            path.display(),
            dir.display()
        ))
    }

    pub fn init(a: &InitArgs) -> Result<String, Failure> {
        let digest = policy_digest(a)?;
        require_state_dir(&a.state)?;
        let s = state::init_run(&a.state, &a.subject, &digest, now_unix(), a.force).map_err(|e| e.to_string())?;
        // strip-for-publish:begin devtool
        // AAASM-6386: the record is fine, but a governed runtime may still deny
        // tools this policy leaves uncovered; say so now rather than at the first call.
        if let Some(policy) = &a.policy {
            for w in crate::commands::lease_readiness::warnings_for_file(policy, &a.subject) {
                eprintln!("warning: {w}");
            }
        }
        // strip-for-publish:end devtool
        let prefix = s.lease_id_prefix();
        Ok(format!(
            "initialized lease state at {} (generation {})\n\
             lease ids for this run have the form {}<domain>\n",
            a.state.display(),
            s.generation(),
            prefix
        ))
    }

    /// The most a `--wait-health` may wait. A larger request is clamped rather
    /// than overflowing the deadline arithmetic.
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(3600);

    /// `url` for display: no userinfo, query or fragment, any of which may carry
    /// a credential.
    fn redacted(url: &reqwest::Url) -> String {
        let mut u = url.clone();
        let _ = u.set_username("");
        let _ = u.set_password(None);
        u.set_query(None);
        u.set_fragment(None);
        u.to_string()
    }

    /// Poll `/health` until the runtime reports this run at `generation` or
    /// later.
    ///
    /// The runtime is matched by `run_id` as well as generation: a different
    /// run's runtime on that address (an older or newer run, or one started
    /// against another record) can show a high generation that says nothing
    /// about this revocation. `denied_all` for this run also acknowledges (every
    /// request is already refused) but exits with its own status.
    fn wait_for_runtime(
        base: &str,
        run_id: &str,
        generation: u64,
        timeout: std::time::Duration,
    ) -> Result<String, Failure> {
        let mut url = reqwest::Url::parse(base).map_err(|_| "--wait-health is not a valid URL".to_string())?;
        let path = format!("{}/health", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url.set_query(None);
        let shown = redacted(&url);
        // The health endpoint is the local runtime's. A proxy from the
        // environment, or a redirect, would send the question (and any URL
        // credentials) somewhere else and could answer it falsely.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.without_url().to_string())?;
        let timeout = timeout.min(MAX_WAIT);
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let last = match client
                .get(url.clone())
                .send()
                .and_then(|r| r.json::<serde_json::Value>())
            {
                Ok(v) => match v.get("lease_governance") {
                    None => {
                        return Err(format!(
                            "{shown} reports no lease_governance: that runtime is not in governed lease mode, \
                             so the revocation is recorded but nothing applied it"
                        )
                        .into())
                    }
                    Some(g) => {
                        let gen = g.get("generation").and_then(|x| x.as_u64()).unwrap_or(0);
                        let st = g.get("state").and_then(|x| x.as_str()).unwrap_or("");
                        if g.get("run_id").and_then(|x| x.as_str()) != Some(run_id) {
                            "runtime is bound to a different run".to_string()
                        } else if st == "denied_all" {
                            return Err(Failure {
                                msg: format!(
                                    "revocation recorded at generation {generation}; the runtime at {shown} is denying \
                                     all requests after a lease state anomaly, so the lease is refused but the \
                                     runtime is not governing by lease; restart it to govern again"
                                ),
                                code: super::EXIT_RUNTIME_DENYING_ALL,
                            });
                        } else if gen >= generation {
                            return Ok(format!("runtime applied generation {gen}"));
                        } else {
                            format!("runtime at generation {gen}")
                        }
                    }
                },
                Err(e) => e.without_url().to_string(),
            };
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "revocation recorded at generation {generation}, but the runtime at {shown} did not acknowledge \
                     it within {}s ({last}); treat the lease as still usable until it does",
                    timeout.as_secs()
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    pub fn revoke(a: &RevokeArgs) -> Result<String, Failure> {
        let s = state::revoke_issued_ids(&a.state, &a.lease_id).map_err(|e| e.to_string())?;
        let mut out = format!("generation {}\n", s.generation());
        if let Some(base) = &a.wait_health {
            let note = wait_for_runtime(
                base,
                s.run_id(),
                s.generation(),
                std::time::Duration::from_secs(a.wait_timeout_secs),
            )?;
            out.push_str(&note);
            out.push('\n');
        }
        Ok(out)
    }

    pub fn status(a: &StatusArgs) -> Result<String, Failure> {
        let bytes = state::load(&a.state).map_err(|e| e.to_string())?.to_bytes();
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(not(unix))]
mod imp {
    use super::{Failure, InitArgs, RevokeArgs, StatusArgs};

    fn unsupported() -> Result<String, Failure> {
        Err("`aasm lease` is only supported on Unix hosts".to_string().into())
    }
    pub fn init(_: &InitArgs) -> Result<String, Failure> {
        unsupported()
    }
    pub fn revoke(_: &RevokeArgs) -> Result<String, Failure> {
        unsupported()
    }
    pub fn status(_: &StatusArgs) -> Result<String, Failure> {
        unsupported()
    }
}
