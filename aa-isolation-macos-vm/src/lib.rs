//! A macOS process-isolation backend for Agent Assembly (AAASM-5813).
//!
//! Implements [`aa_isolation::IsolationBackend`] by delegating confinement to
//! `aa-isolation-native` running inside a Virtualization.framework Linux
//! guest, driven over the real host↔guest launch protocol AAASM-5837 built
//! (`aa-isolation-vm-proto`, [`vmm`], [`paths`]) — the substrate AAASM-5812
//! proved (a Landlock-capable kernel, `guest-init`, vsock) now has something
//! real to carry.
//!
//! # What `Available` means here, and what it deliberately still does not
//!
//! [`MacosVmBackend::discover`] reports [`aa_isolation::BackendAvailability::Available`]
//! when three real, per-host facts hold — the helper binary, guest kernel and
//! guest rootfs artifacts exist (see [`vmm::VmConfig::from_env`]) and the
//! helper is codesigned with `com.apple.security.virtualization`. That is a
//! genuine, host-specific probe, not a compile-time assumption — see
//! [`MacosVmBackend::discover`]'s own documentation for exactly what it
//! checks and what it does not (per-guest capability negotiation, still
//! future work).
//!
//! **[`MacosVmBackend::capabilities`] reports zero [`aa_isolation::CapabilityReport`]
//! rows even when `Available`.** This is deliberate, not an oversight: this
//! crate has real hardware evidence from AAASM-5837's own verification pass
//! that Landlock genuinely enforces filesystem grants inside this guest, and
//! that the arm64 guest kernel cannot enforce a syscall filter (see
//! `aa-isolation-macos-vm-poc/README.md`) — but AAASM-5813's own AC3
//! requires that claim be "verified against AAASM-5812's own capability
//! findings, not asserted independently", through the same measured-probe
//! discipline `aa-isolation-native`'s own `capability::discover` holds
//! itself to (a controlled pair of confined commands, checked *on this
//! host*, not "it worked once in a different pass"). Building that probe for
//! a VM backend means booting a guest as part of `discover()`, which every
//! sibling backend's own probe is written to avoid needing (theirs cost one
//! `--version` call or one local confined command; this backend's would cost
//! a multi-second VM boot on every selection walk). That tradeoff is real
//! engineering work this pass does not do — see the AAASM-5813 Jira history
//! for the decision to defer it rather than either skip the probe discipline
//! or eat the boot cost silently.
//!
//! The practical consequence: `Available` with an empty capability report
//! means [`aa_isolation::plan::negotiate`] correctly *refuses* any launch
//! whose lowered policy requires prevention on a domain (filesystem,
//! syscall) — there is nothing here yet for it to trust — while correctly
//! *permitting* a launch with no capability-domain requirement to reach
//! [`IsolationBackend::prepare`](aa_isolation::IsolationBackend::prepare)
//! and run for real inside the guest. That is exactly AAASM-5813's AC1
//! ("launches a real confined process") without prematurely claiming AC3
//! ("capability report accurately reflects guest-actual enforcement").
//!
//! # The guest has no general toolchain (AAASM-5849)
//!
//! [`paths::to_guest_path`] refuses any program or grant path that is
//! neither under the launch's shared project directory nor one of this
//! guest image's fixed resident binaries — see that module's documentation.
//! A real `aasm run python …`/`git …` on macOS refuses today for exactly
//! that reason, honestly, rather than reaching a guest with nothing able to
//! exec it.

pub mod paths;
pub mod vmm;

use std::collections::BTreeMap;
use std::sync::Mutex;

use aa_isolation::{
    negotiate, BackendAvailability, BackendCapabilities, BackendIdentity, EnforcementEvidence, EnforcementPlan,
    ExecutionHandle, ExecutionSpec, ExitDisposition, IsolationBackend, Lowering, PlanRefusal, PlatformBoundary,
    PreparedExecution, Provenance, SpawnError, TerminationRequest,
};
use aa_isolation_vm_proto::{Disposition, Message, TerminationMode};

/// Stable machine identifier for this backend, named in `--isolation-backend`
/// and in every refusal that lists the candidates a build has.
pub const BACKEND_ID: &str = "aasm-macos-vm";

/// A running or prepared VM session, keyed by a token this backend hands out.
struct Session {
    vm: vmm::VmSession,
    share_dir: Option<std::path::PathBuf>,
    /// Set once [`Message::LaunchOutcome`] arrives, so a second
    /// [`IsolationBackend::wait_for_exit`] call returns the same answer
    /// without re-reading the (already fully-consumed) connection — required
    /// by that method's own contract.
    outcome: Option<Message>,
}

/// A macOS backend that delegates confinement to `aa-isolation-native` inside
/// a Virtualization.framework guest, over the AAASM-5837 launch protocol.
pub struct MacosVmBackend {
    config: Option<vmm::VmConfig>,
    unavailable_reason: Option<String>,
    child_environment: Option<BTreeMap<String, String>>,
    sessions: Mutex<BTreeMap<String, Session>>,
    next_token: std::sync::atomic::AtomicU64,
}

impl core::fmt::Debug for MacosVmBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MacosVmBackend")
            .field("available", &self.config.is_some())
            .finish()
    }
}

impl Default for MacosVmBackend {
    fn default() -> Self {
        Self::discover()
    }
}

impl MacosVmBackend {
    /// Discover this backend's availability.
    ///
    /// Checks, in order:
    /// 1. [`vmm::VmConfig::from_env`] — the helper binary, guest kernel and
    ///    guest rootfs artifacts exist at the paths their environment
    ///    variables name. Absent on essentially every host today: these are
    ///    large, gitignored build artifacts (see
    ///    `aa-isolation-macos-vm-poc/.gitignore`) produced by scripts this
    ///    pass's verification ran by hand, not by any release pipeline
    ///    (that gap is AAASM-5840).
    /// 2. The helper binary's codesignature carries
    ///    `com.apple.security.virtualization`, checked via `codesign -d
    ///    --entitlements :-` — a real per-host probe, not an assumption from
    ///    the artifact merely existing. Costs one subprocess call, not a VM
    ///    boot.
    ///
    /// Never fails, matching every other backend in this workspace: a host
    /// this cannot run on produces a backend whose availability is
    /// `Unavailable`, so `plan()` refuses before any launch starts.
    pub fn discover() -> Self {
        let Some(config) = vmm::VmConfig::from_env() else {
            return Self::unavailable(format!(
                "the macOS VM substrate is not configured on this host — set {}, {} and {} to the helper \
                 binary, guest kernel and guest rootfs image (see aa-isolation-macos-vm-poc/README.md); none of \
                 these are shipped by this build",
                vmm::VmConfig::ENV_HELPER,
                vmm::VmConfig::ENV_KERNEL,
                vmm::VmConfig::ENV_ROOTFS,
            ));
        };
        match entitlement_check(&config.helper_path) {
            Ok(()) => Self {
                config: Some(config),
                unavailable_reason: None,
                child_environment: None,
                sessions: Mutex::new(BTreeMap::new()),
                next_token: std::sync::atomic::AtomicU64::new(0),
            },
            Err(reason) => Self::unavailable(reason),
        }
    }

    fn unavailable(reason: String) -> Self {
        Self {
            config: None,
            unavailable_reason: Some(reason),
            child_environment: None,
            sessions: Mutex::new(BTreeMap::new()),
            next_token: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Set the exact environment the confined program is to receive.
    pub fn set_child_environment(&mut self, env: BTreeMap<String, String>) {
        self.child_environment = Some(env);
    }

    fn identity_value() -> BackendIdentity {
        BackendIdentity {
            id: BACKEND_ID.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            provenance: Provenance {
                source: "aa-isolation-macos-vm (AAASM-5813/AAASM-5837)".to_string(),
                license: "Apache-2.0".to_string(),
                modified: false,
            },
        }
    }

    fn capabilities_value(&self) -> BackendCapabilities {
        let availability = match &self.unavailable_reason {
            Some(reason) => BackendAvailability::Unavailable { reason: reason.clone() },
            None => BackendAvailability::Available,
        };
        // Zero CapabilityReport rows even when Available — see this crate's
        // module documentation for why that is the honest choice this pass,
        // not a placeholder.
        BackendCapabilities::new(availability, PlatformBoundary::GuestKernel, Vec::new())
            .expect("no two reports name the same domain: this backend reports none yet")
    }

    fn next_token(&self) -> String {
        let n = self.next_token.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{BACKEND_ID}-{n}")
    }
}

/// Verify the helper binary's codesignature carries the virtualization
/// entitlement, via `codesign -d --entitlements :-`.
///
/// # Why shelling out rather than parsing the Mach-O signature directly
///
/// `codesign` is the same tool this workspace's own `aa-isolation-macos-vm-poc`
/// README documents signing with, and Apple's code-signing format is not
/// something this crate should be in the business of re-implementing a
/// parser for — the entitlements blob is an internal, Apple-owned encoding
/// with no public Rust crate this workspace already depends on for it.
fn entitlement_check(helper_path: &std::path::Path) -> Result<(), String> {
    if !helper_path.is_file() {
        return Err(format!("the helper binary at {} does not exist", helper_path.display()));
    }
    let output = std::process::Command::new("codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(helper_path)
        .output()
        .map_err(|err| format!("could not run codesign to check the helper's entitlements: {err}"))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if combined.contains("com.apple.security.virtualization") {
        Ok(())
    } else {
        Err(format!(
            "the helper binary at {} is not signed with the com.apple.security.virtualization entitlement \
             (see AAASM-5840) — codesign output: {}",
            helper_path.display(),
            combined.trim()
        ))
    }
}

impl IsolationBackend for MacosVmBackend {
    fn identity(&self) -> BackendIdentity {
        Self::identity_value()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities_value()
    }

    fn plan(&self, spec: &ExecutionSpec) -> Result<EnforcementPlan, PlanRefusal> {
        negotiate(
            spec,
            &self.identity(),
            &self.capabilities(),
            &|_requirement, _outcome| Lowering::new(Vec::<String>::new()),
        )
    }

    fn prepare(&self, plan: EnforcementPlan) -> Result<PreparedExecution, SpawnError> {
        let Some(config) = &self.config else {
            return Err(SpawnError::Prepare {
                detail: self
                    .unavailable_reason
                    .clone()
                    .unwrap_or_else(|| "this backend is unavailable".to_string()),
            });
        };

        let spec = plan.spec();
        let share_dir = paths::share_dir_for(spec.working_dir());

        // Refuse up front, before booting anything, if the program itself
        // cannot be reached in the guest — see `paths` module docs.
        if let Err(err) = paths::to_guest_path(spec.program(), share_dir.as_deref()) {
            return Err(SpawnError::Prepare {
                detail: format!("cannot reach `{}` in the guest: {err}", spec.program()),
            });
        }

        let vm = vmm::boot(config, share_dir.as_deref()).map_err(|detail| SpawnError::Prepare { detail })?;
        let token = self.next_token();
        self.sessions.lock().expect("session lock poisoned").insert(
            token.clone(),
            Session {
                vm,
                share_dir,
                outcome: None,
            },
        );
        Ok(PreparedExecution::new(plan, token))
    }

    fn spawn(&self, prepared: PreparedExecution) -> Result<ExecutionHandle, SpawnError> {
        let expected = self.identity().id;
        if prepared.plan().backend().id != expected {
            return Err(SpawnError::BackendMismatch {
                expected,
                found: prepared.plan().backend().id.clone(),
            });
        }
        let token = prepared.token().to_string();
        let spec = prepared.plan().spec().clone();

        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        let Some(session) = sessions.get_mut(&token) else {
            return Err(SpawnError::Spawn {
                detail: format!("no prepared execution for token `{token}`"),
            });
        };

        // The program must be reachable in the guest, mapped from its host
        // form — already checked once in `prepare`; checked again here
        // because `spawn` is where the mapped value actually gets used, and
        // a caller could in principle call it with a different prepared
        // value than the one `prepare` validated.
        let mut fs_read = Vec::new();
        let mut fs_write = Vec::new();
        let program = match paths::to_guest_path(spec.program(), session.share_dir.as_deref()) {
            Ok(mapped) => mapped,
            Err(err) => {
                return Err(SpawnError::Spawn {
                    detail: format!("cannot reach `{}` in the guest: {err}", spec.program()),
                })
            }
        };
        // This pass grants exactly the working directory (the whole share)
        // for read and write when one is configured — a per-path grant
        // model mirroring the policy-derived grants a real `ExecutionSpec`
        // would carry is `aa_isolation_native::backend::permitted_scope`'s
        // job once this backend's own capability rows exist (see this
        // crate's module docs on why they don't yet); until then, the
        // *only* thing this launch can be trusted to grant is the boundary
        // that already exists structurally — the virtiofs share itself.
        if let Some(share) = &session.share_dir {
            fs_read.push(paths::GUEST_SHARE_MOUNTPOINT.to_string());
            fs_write.push(paths::GUEST_SHARE_MOUNTPOINT.to_string());
            let _ = share;
        }

        let request_id = token.clone();
        let request = Message::LaunchRequest {
            request_id: request_id.clone(),
            program,
            args: spec.args().to_vec(),
            env: self.child_environment.clone().unwrap_or_default(),
            working_dir: session
                .share_dir
                .as_ref()
                .map(|_| paths::GUEST_SHARE_MOUNTPOINT.to_string()),
            fs_read,
            fs_write,
            syscall_filter: None,
        };

        session.vm.send(&request).map_err(|err| SpawnError::Spawn {
            detail: format!("failed to send LaunchRequest: {err}"),
        })?;
        let reply = session.vm.recv().map_err(|err| SpawnError::Spawn {
            detail: format!("failed to read the guest's reply: {err}"),
        })?;
        match reply {
            Message::LaunchAccepted { .. } => {}
            Message::LaunchRefused { reason, .. } => {
                return Err(SpawnError::Spawn {
                    detail: format!("the guest refused this launch: {reason}"),
                })
            }
            other => {
                return Err(SpawnError::Spawn {
                    detail: format!("expected LaunchAccepted, got {other:?}"),
                })
            }
        }

        Ok(ExecutionHandle::new(self.identity(), token, prepared.plan().posture()))
    }

    fn wait_for_exit(&self, handle: &ExecutionHandle) -> Result<ExitDisposition, SpawnError> {
        if handle.backend().id != self.identity().id {
            return Err(SpawnError::Supervision {
                detail: format!(
                    "handle names backend `{}`, not `{}`",
                    handle.backend().id,
                    self.identity().id
                ),
            });
        }
        let token = handle.token().to_string();
        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        let Some(session) = sessions.get_mut(&token) else {
            return Err(SpawnError::Supervision {
                detail: format!("no execution for token `{token}`"),
            });
        };

        if session.outcome.is_none() {
            let message = session.vm.recv().map_err(|err| SpawnError::Supervision {
                detail: format!("the guest ended before reporting a disposition; it was destroyed: {err}"),
            })?;
            session.outcome = Some(message);
        }

        match session.outcome.as_ref().expect("just set or already present") {
            Message::LaunchOutcome { disposition, .. } => Ok(match disposition {
                Disposition::Exited { code } => ExitDisposition::Code(*code),
                Disposition::NoCode { detail } => ExitDisposition::NoCode { detail: detail.clone() },
            }),
            other => Err(SpawnError::Supervision {
                detail: format!("expected LaunchOutcome, got {other:?}"),
            }),
        }
    }

    fn terminate(&self, handle: &ExecutionHandle, request: TerminationRequest) -> Result<(), SpawnError> {
        let token = handle.token().to_string();
        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        let Some(session) = sessions.get_mut(&token) else {
            return Err(SpawnError::Supervision {
                detail: format!("no execution for token `{token}`"),
            });
        };
        let mode = match request {
            TerminationRequest::Graceful => TerminationMode::Graceful,
            TerminationRequest::Immediate => TerminationMode::Immediate,
            // `TerminationRequest` is `#[non_exhaustive]`: a future variant
            // this backend does not yet understand is refused rather than
            // guessed at — silently mapping an unrecognized request to
            // either existing mode could deliver a weaker (or stronger)
            // termination than the caller actually asked for.
            other => {
                return Err(SpawnError::Supervision {
                    detail: format!("this backend does not understand termination request {other:?}"),
                })
            }
        };
        session
            .vm
            .send(&Message::TerminateRequest {
                request_id: token,
                mode,
            })
            .map_err(|err| SpawnError::Supervision {
                detail: format!("failed to send TerminateRequest: {err}"),
            })
    }

    fn evidence(&self, handle: &ExecutionHandle) -> EnforcementEvidence {
        // No prevention claims recorded — see this crate's module
        // documentation on why capability rows (and therefore evidence
        // records that would depend on them) are deliberately deferred this
        // pass. `implicit_grants` from the guest's own LaunchOutcome is
        // available (`aa_isolation_vm_proto::implicit_grant`) but has
        // nowhere honest to go yet without an existing ClaimTerm this
        // backend is entitled to use — recorded once capability rows exist.
        EnforcementEvidence::new(self.identity(), handle.posture())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_always_yields_a_backend() {
        let backend = MacosVmBackend::discover();
        assert_eq!(backend.identity().id, BACKEND_ID);
    }

    #[test]
    fn without_env_configuration_this_backend_is_unavailable() {
        for var in [
            vmm::VmConfig::ENV_HELPER,
            vmm::VmConfig::ENV_KERNEL,
            vmm::VmConfig::ENV_ROOTFS,
        ] {
            // Best-effort: only meaningful when the test process's own
            // environment does not already carry these — true in CI and on
            // a developer machine that has not exported them for a manual
            // hardware-verification run.
            if std::env::var(var).is_ok() {
                return;
            }
        }
        let backend = MacosVmBackend::discover();
        assert!(matches!(
            backend.capabilities().availability(),
            BackendAvailability::Unavailable { .. }
        ));
    }

    #[test]
    fn an_unavailable_backend_refuses_every_plan() {
        let backend = MacosVmBackend::unavailable("test".to_string());
        let spec = ExecutionSpec::new("probe", aa_isolation::IdentityRef::root("probe"));
        assert!(backend.plan(&spec).is_err());
    }
}
