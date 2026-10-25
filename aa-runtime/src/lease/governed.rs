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

/// Longest a single read of the state record may take before the gate fails
/// closed. A record on a hung filesystem would otherwise freeze revocation
/// while the gate kept answering from a stale snapshot.
pub const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

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
            "{e}; re-run `aasm lease init --force --subject {} --policy <policy file>` for this policy and agent (--force starts a new run and discards the revocation history)",
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
    let status = Arc::new(LeaseStatus::new(state.run_id(), generation));

    tracing::info!(
        generation,
        run_id = state.run_id(),
        policy_digest = %digest,
        "governed lease mode active"
    );

    let reload_gate = Arc::clone(&gate);
    let reload_status = Arc::clone(&status);
    let path = state_path.clone();
    let reader: Reader = Arc::new(move || state::load(&path));
    Ok(GovernedLease {
        gate,
        status,
        reload: Box::new(move |tracker, token| {
            let work = reload_loop(
                reader,
                READ_TIMEOUT,
                Arc::clone(&reload_gate),
                Arc::clone(&reload_status),
                governance,
                state,
                token.clone(),
            );
            tracker.spawn(supervise(reload_gate, reload_status, token, work));
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

type Reader = Arc<dyn Fn() -> Result<LeaseState, LeaseStateError> + Send + Sync>;

/// Why the reload loop ended normally.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LoopEnd {
    /// The runtime is shutting down.
    Cancelled,
    /// An anomaly was found and deny-all is installed; nothing more to do.
    Latched,
}

/// Read the record on a blocking thread, bounded by `timeout`. A read that does
/// not return in time is reported as an I/O error, which trips the gate.
async fn read_bounded(reader: Reader, timeout: std::time::Duration) -> Result<LeaseState, LeaseStateError> {
    // Blocking filesystem reads must not run on an async worker.
    match tokio::time::timeout(timeout, tokio::task::spawn_blocking(move || reader())).await {
        Ok(Ok(r)) => r,
        Ok(Err(join)) => Err(LeaseStateError::Io(std::io::Error::other(join.to_string()))),
        Err(_) => Err(LeaseStateError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("state read exceeded {}ms", timeout.as_millis()),
        ))),
    }
}

/// Install deny-all and publish it, from whatever generation the gate is at.
fn latch_denied(gate: &PolicyLeaseGate, status: &LeaseStatus, reason: String) {
    let generation = status.report().generation.saturating_add(1);
    tracing::error!(%reason, "lease state anomaly: denying every request until restart");
    if gate.install(Snapshot::deny_all(reason, generation)).is_err() {
        tracing::error!("lease gate lock is poisoned; it keeps denying");
    }
    status.set_denied_all(generation);
}

/// Run `work` as its own task and fail closed if it ends any way other than
/// the two normal ones. A reload task that panicked or was aborted would leave
/// the gate deciding from a revocation set nothing updates any more; a gate
/// that cannot learn of revocations must deny, not keep permitting.
pub(crate) async fn supervise<F>(
    gate: Arc<PolicyLeaseGate>,
    status: Arc<LeaseStatus>,
    token: CancellationToken,
    work: F,
) where
    F: std::future::Future<Output = LoopEnd> + Send + 'static,
{
    match tokio::spawn(work).await {
        Ok(LoopEnd::Latched) => {}
        Ok(LoopEnd::Cancelled) if token.is_cancelled() => {}
        Ok(LoopEnd::Cancelled) => latch_denied(&gate, &status, "reload task stopped without shutdown".to_string()),
        Err(e) => latch_denied(&gate, &status, format!("reload task died: {e}")),
    }
}

async fn reload_loop(
    reader: Reader,
    read_timeout: std::time::Duration,
    gate: Arc<PolicyLeaseGate>,
    status: Arc<LeaseStatus>,
    governance: LeaseGovernance,
    mut current: LeaseState,
    token: CancellationToken,
) -> LoopEnd {
    let mut tick = tokio::time::interval(RELOAD_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = token.cancelled() => return LoopEnd::Cancelled,
            _ = tick.tick() => {}
        }
        let loaded = read_bounded(Arc::clone(&reader), read_timeout).await;
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
                        return LoopEnd::Latched;
                    }
                }
            }
            Reload::Trip(reason) => {
                latch_denied(&gate, &status, reason);
                return LoopEnd::Latched;
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

    // ---- liveness and bounded reads -------------------------------------

    use crate::pipeline::{LeaseGate, LeaseVerdict};
    use aa_proto::assembly::common::v1::ActionType;
    use aa_proto::assembly::policy::v1::action_context::Action;
    use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};

    fn rig() -> (Arc<PolicyLeaseGate>, Arc<LeaseStatus>, LeaseGovernance, LeaseState) {
        let yaml = "tools:\n  calc: { allow: true, capabilities: [none] }\n";
        let resolution = aa_policy::resolve::classify(std::path::Path::new("p.yaml"), yaml);
        let digest = resolution
            .content_digest()
            .unwrap()
            .strip_prefix("sha256:")
            .unwrap()
            .to_string();
        let state = LeaseState::new_run("agent-1", &digest, 1_700_000_000).unwrap();
        let gov = LeaseGovernance::from_state(&resolution, "agent-1", 60, "t", &state).unwrap();
        let gate = Arc::new(PolicyLeaseGate::new(Snapshot::governed(gov.clone(), state.clone(), 1)));
        (gate, Arc::new(LeaseStatus::new(state.run_id(), 1)), gov, state)
    }

    fn calc() -> CheckActionRequest {
        CheckActionRequest {
            action_type: ActionType::ToolCall as i32,
            context: Some(ActionContext {
                action: Some(Action::ToolCall(ToolCallContext {
                    tool_name: "calc".into(),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        }
    }

    fn permits(gate: &PolicyLeaseGate) -> bool {
        gate.check("agent-1", &calc(), std::time::SystemTime::now()) == LeaseVerdict::Permit
    }

    #[tokio::test]
    async fn a_reload_task_that_panics_leaves_the_gate_denying_everything() {
        let (gate, status, _, _) = rig();
        assert!(permits(&gate), "positive control");
        supervise(gate.clone(), status.clone(), CancellationToken::new(), async {
            panic!("reload task bug");
            #[allow(unreachable_code)]
            LoopEnd::Latched
        })
        .await;
        assert!(!permits(&gate));
        assert_eq!(status.report().state, "denied_all");
    }

    #[tokio::test]
    async fn a_reload_task_that_ends_without_shutdown_also_fails_closed() {
        let (gate, status, _, _) = rig();
        supervise(gate.clone(), status.clone(), CancellationToken::new(), async {
            LoopEnd::Cancelled
        })
        .await;
        assert!(!permits(&gate));
        assert_eq!(status.report().state, "denied_all");
    }

    #[tokio::test]
    async fn a_clean_shutdown_does_not_trip_the_gate() {
        let (gate, status, _, _) = rig();
        let token = CancellationToken::new();
        token.cancel();
        supervise(gate.clone(), status.clone(), token, async { LoopEnd::Cancelled }).await;
        assert!(permits(&gate));
        assert_eq!(status.report().state, "governed");
    }

    #[tokio::test]
    async fn a_read_that_blocks_trips_the_gate_after_the_timeout() {
        let (gate, status, gov, state) = rig();
        let reader: Reader = Arc::new(|| {
            std::thread::sleep(std::time::Duration::from_secs(3));
            Err(LeaseStateError::Corrupt("unreachable".into()))
        });
        let end = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reload_loop(
                reader,
                std::time::Duration::from_millis(150),
                gate.clone(),
                status.clone(),
                gov,
                state,
                CancellationToken::new(),
            ),
        )
        .await
        .expect("a blocked read must not block the loop past its timeout");
        assert_eq!(end, LoopEnd::Latched);
        assert!(!permits(&gate));
        assert_eq!(status.report().state, "denied_all");
    }

    #[tokio::test]
    async fn read_bounded_reports_a_timeout_as_an_io_error() {
        let slow: Reader = Arc::new(|| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            Err(LeaseStateError::Missing("x".into()))
        });
        let r = read_bounded(slow, std::time::Duration::from_millis(50)).await;
        assert!(matches!(r, Err(LeaseStateError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut));
    }
}
