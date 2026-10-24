//! Governed lease mode: startup binding and the revocation reload task
//! (AAASM-6259, ADR 0038).
//!
//! Inside the `devtool` strip region with the gate it builds. Its refusal
//! counterpart for builds without the gate is [`super::wiring::prepare`].
//!
//! # Fail closed, and stay closed
//!
//! The reload task re-reads the state record every [`RELOAD_INTERVAL`]. A
//! valid, monotonic update installs a new snapshot. *Anything else* — a read
//! error, a corrupt or vanished file, a changed anchor, a shrunk revocation set,
//! a generation that went backwards — installs a deny-all snapshot and ends the
//! task. It never heals: a record that was briefly wrong may have been wrong
//! long enough for someone to act on it, and only a restart (which re-validates
//! everything from scratch) may govern again.
//!
//! The policy file is read once, at startup. Editing it afterwards changes
//! nothing until restart; the digest binding makes a restart with an edited
//! policy refuse unless the operator re-initialises the record.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use super::decide::LeaseGovernance;
use super::gate::{PolicyLeaseGate, Snapshot};
use super::state::{self, LeaseState, LeaseStateError};
use super::wiring::{GovernedLease, LeaseStatus};
use crate::config::RuntimeConfig;
use crate::runtime::StartupRefusal;

/// How often the state record is re-read.
pub const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Lifetime applied to a grant that states no `ttl_seconds`, counted from the
/// record's `issued_at` (the `aasm lease init` time), not from runtime start.
/// Matches `aasm run`'s launch-time default.
pub const DEFAULT_LEASE_TTL_SECONDS: u64 = 3_600;

const DEFAULT_LEASE_ISSUER: &str = "aa-runtime:policy";

fn refuse(msg: impl Into<String>) -> StartupRefusal {
    StartupRefusal::new(format!("governed lease mode: {}", msg.into()))
}

/// Build the gate from `AA_LEASE_POLICY` + `AA_LEASE_STATE`, or refuse.
pub(super) fn prepare(config: &RuntimeConfig) -> Result<GovernedLease, StartupRefusal> {
    let policy_path = config
        .lease_policy_path
        .as_ref()
        .ok_or_else(|| refuse("AA_LEASE_POLICY is not set"))?;
    let state_path = config.lease_state_path.as_ref().ok_or_else(|| {
        refuse("AA_LEASE_STATE is not set; create the record with `aasm lease init` and point AA_LEASE_STATE at it")
    })?;

    // `load`, not `resolve`: the explicit path is the only candidate, so a
    // missing file can never fall back to a user- or machine-wide policy.
    let resolution = aa_policy::resolve::load(policy_path);
    if !matches!(resolution, aa_policy::resolve::PolicyResolution::Enforced { .. }) {
        return Err(refuse(format!(
            "AA_LEASE_POLICY must resolve to an enforced policy, but: {}",
            resolution.summary()
        )));
    }
    let digest = resolution
        .content_digest()
        .map(|d| d.strip_prefix("sha256:").unwrap_or(d).to_string())
        .ok_or_else(|| refuse("policy has no content digest"))?;

    // Never auto-created: a missing record would otherwise re-grant every
    // revoked lease. The operator runs `aasm lease init`.
    let state = state::load_expected(state_path, &config.agent_id, &digest).map_err(|e| match e {
        LeaseStateError::Mismatch(_) => refuse(format!(
            "{e}; this runtime's agent id is `{}` and the policy digest is {digest}; re-run \
             `aasm lease init` for this policy and agent",
            config.agent_id
        )),
        other => refuse(other.to_string()),
    })?;

    let governance = LeaseGovernance::from_state(
        &resolution,
        &config.agent_id,
        DEFAULT_LEASE_TTL_SECONDS,
        DEFAULT_LEASE_ISSUER,
        &state,
    )
    .map_err(|e| refuse(e.to_string()))?;

    let generation = state.generation();
    let gate = Arc::new(PolicyLeaseGate::new(Snapshot::governed(
        governance.clone(),
        state.clone(),
        generation,
    )));
    let status = Arc::new(LeaseStatus::new(generation));

    tracing::info!(
        generation,
        run_id = state.run_id(),
        policy_digest = %digest,
        "governed lease mode active"
    );

    let reload_gate = Arc::clone(&gate);
    let reload_status = Arc::clone(&status);
    let path = state_path.clone();
    Ok(GovernedLease {
        gate,
        status,
        reload: Box::new(move |tracker, token| {
            tracker.spawn(reload_loop(path, reload_gate, reload_status, governance, state, token));
        }),
    })
}

/// What one reload observation means.
#[derive(Debug)]
pub(crate) enum Reload {
    /// Nothing changed.
    Unchanged,
    /// A valid newer record: install this snapshot.
    Install(Box<LeaseState>),
    /// An anomaly: deny everything from now on, for this reason.
    Trip(String),
}

/// Judge a freshly read record against the one currently governing.
pub(crate) fn reload_step(current: &LeaseState, loaded: Result<LeaseState, LeaseStateError>) -> Reload {
    let new = match loaded {
        Ok(new) => new,
        Err(e) => return Reload::Trip(format!("lease state unreadable: {e}")),
    };
    if new == *current {
        return Reload::Unchanged;
    }
    match state::check_monotonic(current, &new) {
        Ok(()) => Reload::Install(Box::new(new)),
        Err(e) => Reload::Trip(e.to_string()),
    }
}

async fn read_state(path: &Path) -> Result<LeaseState, LeaseStateError> {
    let p = path.to_path_buf();
    // Blocking filesystem reads must not run on an async worker.
    match tokio::task::spawn_blocking(move || state::load(&p)).await {
        Ok(r) => r,
        Err(join) => Err(LeaseStateError::Io(std::io::Error::other(join.to_string()))),
    }
}

async fn reload_loop(
    path: PathBuf,
    gate: Arc<PolicyLeaseGate>,
    status: Arc<LeaseStatus>,
    governance: LeaseGovernance,
    mut current: LeaseState,
    token: CancellationToken,
) {
    let mut tick = tokio::time::interval(RELOAD_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = token.cancelled() => return,
            _ = tick.tick() => {}
        }
        let loaded = read_state(&path).await;
        match reload_step(&current, loaded) {
            Reload::Unchanged => {}
            Reload::Install(new) => {
                let generation = new.generation();
                let snapshot = Snapshot::governed(governance.clone(), (*new).clone(), generation);
                match gate.install(snapshot) {
                    Ok(()) => {
                        status.set_governed(generation);
                        tracing::info!(generation, revoked = new.revoked().len(), "lease revocations reloaded");
                        current = *new;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "lease gate cannot accept a reload; it keeps denying");
                        status.set_denied_all(generation);
                        return;
                    }
                }
            }
            Reload::Trip(reason) => {
                let generation = current.generation().saturating_add(1);
                tracing::error!(%reason, "lease state anomaly: denying every request until restart");
                if gate.install(Snapshot::deny_all(reason, generation)).is_err() {
                    tracing::error!("lease gate lock is poisoned; it keeps denying");
                }
                status.set_denied_all(generation);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef";

    fn base() -> LeaseState {
        LeaseState::new_run("agent-1", DIGEST, 1_700_000_000).expect("state")
    }

    fn revoked(of: &LeaseState, id: &str) -> LeaseState {
        let mut s = of.clone();
        assert!(s.revoke([id]).expect("revoke"));
        s
    }

    #[test]
    fn an_identical_record_changes_nothing() {
        let s = base();
        assert!(matches!(reload_step(&s, Ok(s.clone())), Reload::Unchanged));
    }

    #[test]
    fn a_monotonic_revocation_installs() {
        let s = base();
        let next = revoked(&s, "x");
        assert!(matches!(reload_step(&s, Ok(next)), Reload::Install(n) if n.generation() == 2));
    }

    #[test]
    fn every_anomaly_trips() {
        let s = base();
        let advanced = revoked(&s, "x");
        let cases: Vec<(&str, Result<LeaseState, LeaseStateError>, LeaseState)> = vec![
            ("missing", Err(LeaseStateError::Missing("p".into())), s.clone()),
            ("corrupt", Err(LeaseStateError::Corrupt("bad".into())), s.clone()),
            ("io", Err(LeaseStateError::Io(std::io::Error::other("boom"))), s.clone()),
            // Generation backwards and revocation shrink: restore of an older record.
            ("rollback", Ok(s.clone()), advanced.clone()),
            (
                "new run (anchor change)",
                Ok(LeaseState::new_run("agent-1", DIGEST, 1_700_000_000).unwrap()),
                s.clone(),
            ),
            (
                "subject change",
                Ok(LeaseState::new_run("agent-2", DIGEST, 1_700_000_000).unwrap()),
                s.clone(),
            ),
            (
                "digest change",
                Ok(LeaseState::new_run("agent-1", &"a".repeat(32), 1_700_000_000).unwrap()),
                s.clone(),
            ),
        ];
        for (name, loaded, current) in cases {
            assert!(
                matches!(reload_step(&current, loaded), Reload::Trip(_)),
                "{name} must trip"
            );
        }
    }
}
