//! Turning an [`ExecutionSpec`] into the backend's command line.
//!
//! # The one rule this module exists to hold
//!
//! **Argv is passed as argv.** Nothing here builds a shell command, formats a
//! program name into a string that is later split, or interpolates a
//! caller-supplied value into anything that a shell will read. Every element of
//! [`Argv`] becomes exactly one element of `execve`'s argument vector, so a
//! program named `; rm -rf /` is a program with a strange name and not a second
//! command. That property is pinned by
//! [`tests::caller_argv_survives_verbatim_through_the_command_line`], and it is
//! the reason this module is pure data with no `Command` in it: a function that
//! cannot spawn cannot spawn a shell.
//!
//! # Lowering is a total function with an explicit failure arm
//!
//! Some requirements cannot be expressed to this backend at all — a permitted
//! *set* of syscalls, when the mechanism takes a denied *list*; a CPU-time
//! ceiling, when the mechanism has none. Those return [`LoweringGap`] rather
//! than silently emitting nothing, because a requirement that produced no flag
//! and no complaint is a requirement that reads as satisfied.
//! [`crate::capability`] turns each gap into a narrowed capability report, and
//! `aa_isolation::negotiate` turns that into a refusal. The gap never becomes a
//! flag that "approximately" means the requirement.

use aa_isolation::{
    permitted_selector, CapabilityDomain, ControlRequirement, ExecutionSpec, RequirementScope, ResourceLimits,
};

/// The subcommand that runs a confined program.
pub const SUBCOMMAND_RUN: &str = "run";
/// Separates the backend's own flags from the program to confine.
pub const ARG_SEPARATOR: &str = "--";
/// Grants read access to a path.
pub const FLAG_FS_READ: &str = "--fs-read";
/// Grants write access to a path.
pub const FLAG_FS_WRITE: &str = "--fs-write";
/// Permits egress to one destination specification.
pub const FLAG_NET_ALLOW: &str = "--net-allow";
/// Caps resident memory, in bytes.
pub const FLAG_MAX_MEMORY: &str = "--max-memory";
/// Caps the number of processes in the confined tree.
pub const FLAG_MAX_PROCESSES: &str = "--max-processes";
/// Starts the confined program with an empty environment.
pub const FLAG_CLEAN_ENV: &str = "--clean-env";
/// Passes one `NAME=VALUE` pair into the otherwise empty environment.
pub const FLAG_ENV: &str = "--env";
/// Sets the confined program's working directory.
pub const FLAG_CWD: &str = "--cwd";

/// Join a flag to its value as a single argument.
///
/// # Why every value-taking flag goes through this
///
/// Some of these values come from policy: a permitted path, a permitted egress
/// destination. Emitted as two arguments, a value beginning with `-` sits in the
/// argument vector where the next *flag* is expected, and whether it is read as
/// a value or as a flag is then a property of the mechanism's argument parser
/// rather than of this backend. A policy selector of `--no-supervisor` is not a
/// hypothetical: it is the shape an attacker would choose.
///
/// `--flag=value` is one argument and cannot be re-read as two, whatever the
/// value starts with. The mechanism will reject a nonsensical value — a path
/// that does not exist, a destination that does not parse — and rejection is
/// the fail-closed direction.
///
/// Pinned by [`tests::a_selector_that_looks_like_a_flag_cannot_become_one`].
fn flag_with_value(flag: &str, value: &str) -> String {
    format!("{flag}={value}")
}
/// Waives one named protection on a host too old to provide it.
///
/// Emitted **only** when a caller authorised it by name through
/// [`crate::SandlockBackend::discover_authorising_degraded`]. The mechanism
/// applies this waiver silently — it prints nothing, and there is no flag that
/// makes it print anything — which is precisely why the authorisation has to be
/// explicit here and is recorded into evidence there.
pub const FLAG_ALLOW_DEGRADED: &str = "--allow-degraded";

/// Flags that weaken the boundary, which this backend must never emit on its
/// own initiative.
///
/// Each one either turns a protection off, replaces the supervised launch with
/// an unsupervised one, or routes the program through a shell. None is
/// reachable from an [`ExecutionSpec`]: policy has no field that could ask for
/// them, and lowering has no branch that could produce them. The list exists so
/// that stays true by test rather than by inspection — see
/// [`tests::no_spec_can_produce_a_flag_that_weakens_the_boundary`].
///
/// [`FLAG_ALLOW_DEGRADED`] is absent from this list because a caller can
/// authorise it deliberately; the test asserts it is absent unless they did.
pub const BOUNDARY_WEAKENING_FLAGS: &[&str] = &[
    "--disable",
    "--no-supervisor",
    "--exec-shell",
    "-e",
    "--extra-allow-syscall",
    "--net-deny",
    "--net-deny-bind",
    "--http-allow",
    "--profile",
    "-p",
    "--profile-file",
    "--user",
    "--dry-run",
];

/// A requirement this backend cannot express, and why.
///
/// Carried out of lowering rather than thrown away, so the reason reaches the
/// operator through a capability report and a refusal instead of vanishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweringGap {
    /// The domain that could not be lowered.
    pub domain: CapabilityDomain,
    /// What the mechanism can express instead, phrased for someone deciding
    /// whether to change the policy or change the backend.
    pub reason: String,
}

/// A fully built command line: the executable's arguments, in order.
///
/// Holds no program path — [`crate::backend`] supplies that from measured host
/// facts, so a spec can never name the binary that confines it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Argv {
    args: Vec<String>,
    /// The index at which [`ARG_SEPARATOR`] sits, so tests can assert that
    /// everything after it came from the caller and everything before it did
    /// not.
    separator_at: usize,
}

impl Argv {
    /// Every argument, in order.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// The confinement flags, before the separator.
    pub fn confinement_flags(&self) -> &[String] {
        &self.args[..self.separator_at]
    }

    /// The program and its arguments, after the separator.
    pub fn target(&self) -> &[String] {
        &self.args[self.separator_at + 1..]
    }
}

/// Everything one requirement contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainLowering {
    /// The flags this requirement produced.
    pub flags: Vec<String>,
    /// A description of what was done, in the backend's own words, for
    /// [`aa_isolation::Lowering`].
    pub steps: Vec<String>,
}

/// Lower one requirement, or report why it cannot be.
///
/// # Errors
///
/// [`LoweringGap`] when the mechanism cannot express the requirement. This is
/// not "the requirement failed" — nothing has been attempted yet. It is the
/// input to the capability narrowing in [`crate::capability::narrow_for`],
/// which is what turns it into a refusal.
pub fn lower_requirement(requirement: &ControlRequirement) -> Result<DomainLowering, LoweringGap> {
    match requirement.domain() {
        CapabilityDomain::FilesystemRead => Ok(filesystem(requirement, FLAG_FS_READ, "readable")),
        CapabilityDomain::FilesystemWrite => Ok(filesystem(requirement, FLAG_FS_WRITE, "writable")),
        CapabilityDomain::NetworkEgress => Ok(network_egress(requirement)),
        CapabilityDomain::ProcessCreation => process_creation(requirement),
        CapabilityDomain::Resource => resource(requirement),
        CapabilityDomain::Ipc => Ok(DomainLowering {
            // Abstract-`AF_UNIX` scoping is applied by the mechanism itself
            // whenever it confines a process; there is no flag to emit and no
            // way to ask for it selectively. Recorded as a step so evidence
            // does not read as though nothing covered the domain.
            flags: Vec::new(),
            steps: vec![
                "ipc: abstract AF_UNIX socket scoping is applied unconditionally by the confinement, \
                 with no per-launch flag; no argument emitted"
                    .to_string(),
            ],
        }),
        CapabilityDomain::Credential => Ok(DomainLowering {
            // The credential posture travels on the spec, not on a requirement's
            // scope, so it is lowered once by `credential_flags` rather than
            // here. Emitting nothing twice would double the `--clean-env`.
            flags: Vec::new(),
            steps: vec![
                "credential: lowered from the spec's credential posture rather than from this \
                 requirement's scope"
                    .to_string(),
            ],
        }),
        CapabilityDomain::NameResolution => Err(LoweringGap {
            domain: CapabilityDomain::NameResolution,
            reason: "the mechanism redirects hostname resolution to a synthetic hosts file pinned at \
                     start; redirection is not a decision about a resolution, and no flag makes it one"
                .to_string(),
        }),
        CapabilityDomain::Syscall => Err(LoweringGap {
            domain: CapabilityDomain::Syscall,
            reason: "the mechanism takes a denied list of syscall names; the contract's syscall scope is \
                     a permitted set, whose complement is unbounded and therefore cannot be emitted as \
                     a denied list without under-stating the requirement"
                .to_string(),
        }),
        // `CapabilityDomain` is `#[non_exhaustive]`: a domain added by a later
        // ticket must refuse here, not fall through to "nothing to do".
        other => Err(LoweringGap {
            domain: other,
            reason: "this backend has no lowering for the domain; it was added to the contract after \
                     the backend was written"
                .to_string(),
        }),
    }
}

/// Filesystem domains: a permitted set of paths, or nothing at all.
///
/// The mechanism is default-deny, so an empty grant is a meaningful, expressible
/// policy — "no path is readable" — rather than a failure to lower. That is why
/// [`RequirementScope::Whole`] emits no flag and says so explicitly: the flag
/// list is the grant, and an absent grant denies everything.
fn filesystem(requirement: &ControlRequirement, flag: &str, verb: &str) -> DomainLowering {
    let domain = requirement.domain();
    match requirement.scope() {
        RequirementScope::Selectors(selectors) => {
            let paths: Vec<&str> = selectors.iter().filter_map(|s| permitted_selector(s)).collect();
            let unreadable: Vec<&String> = selectors.iter().filter(|s| permitted_selector(s).is_none()).collect();
            let flags: Vec<String> = paths.iter().map(|path| flag_with_value(flag, path)).collect();
            let mut steps = vec![format!(
                "{domain}: default-deny; {} path(s) made {verb} via `{flag}`",
                paths.len()
            )];
            if !unreadable.is_empty() {
                // A selector with no `permit-only:` prefix is not a path this
                // backend may grant — the contract gives selectors no polarity
                // field, and reading a bare string as a grant would invert the
                // requirement's meaning on exactly the inputs where it matters.
                steps.push(format!(
                    "{domain}: {} selector(s) carried no permitted-set prefix and were NOT granted; \
                     they remain denied by the default-deny posture",
                    unreadable.len()
                ));
            }
            DomainLowering { flags, steps }
        }
        RequirementScope::Whole => DomainLowering {
            flags: Vec::new(),
            steps: vec![format!(
                "{domain}: whole-domain requirement; no path is made {verb}, so the mechanism's \
                 default-deny posture covers the domain entirely"
            )],
        },
        RequirementScope::Limits(_) => DomainLowering {
            flags: Vec::new(),
            steps: vec![format!(
                "{domain}: numeric ceilings do not apply to a filesystem domain; no grant emitted, so \
                 the default-deny posture stands"
            )],
        },
    }
}

/// Egress: a permitted set of destinations, or a total denial.
fn network_egress(requirement: &ControlRequirement) -> DomainLowering {
    match requirement.scope() {
        RequirementScope::Selectors(selectors) => {
            let hosts: Vec<&str> = selectors.iter().filter_map(|s| permitted_selector(s)).collect();
            let flags: Vec<String> = hosts.iter().map(|host| flag_with_value(FLAG_NET_ALLOW, host)).collect();
            DomainLowering {
                flags,
                steps: vec![format!(
                    "network_egress: default-deny; {} destination(s) permitted via `{FLAG_NET_ALLOW}`. \
                     Hostname destinations are resolved once at start and pinned, so the permitted set \
                     is the address set observed then, not whatever the name resolves to later",
                    hosts.len()
                )],
            }
        }
        _ => DomainLowering {
            flags: Vec::new(),
            steps: vec![
                "network_egress: whole-domain requirement; no destination is permitted, so every \
                 outbound connection is denied by the default-deny posture"
                    .to_string(),
            ],
        },
    }
}

/// Process creation: expressible only as a ceiling on the number of processes.
fn process_creation(requirement: &ControlRequirement) -> Result<DomainLowering, LoweringGap> {
    match requirement.scope() {
        RequirementScope::Whole => Ok(DomainLowering {
            // One process is the launched program itself, so a ceiling of one
            // denies every `fork`/`clone` it attempts.
            flags: vec![flag_with_value(FLAG_MAX_PROCESSES, "1")],
            steps: vec![
                "process_creation: ceiling of 1 process, so the launched program itself is the whole \
                 tree and any clone/fork is denied before the new task exists"
                    .to_string(),
            ],
        }),
        RequirementScope::Limits(limits) => match limits.max_pids {
            Some(max) => Ok(DomainLowering {
                flags: vec![flag_with_value(FLAG_MAX_PROCESSES, &max.to_string())],
                steps: vec![format!(
                    "process_creation: ceiling of {max} process(es) in the confined tree"
                )],
            }),
            None => Err(LoweringGap {
                domain: CapabilityDomain::ProcessCreation,
                reason: "the requirement stated numeric ceilings but none of them was a process count, \
                         which is the only process-creation control this mechanism has"
                    .to_string(),
            }),
        },
        RequirementScope::Selectors(_) => Err(LoweringGap {
            domain: CapabilityDomain::ProcessCreation,
            reason: "the mechanism controls process creation as a count ceiling only; it cannot permit \
                     a named set of programs to be executed and deny the rest"
                .to_string(),
        }),
    }
}

/// Resource ceilings, of which only some are expressible and only some are
/// decided before the effect.
///
/// The wall-clock ceiling is deliberately *not* lowered here. It is enforced by
/// terminating a process that has already run, which is
/// [`ClaimTerm::Detected`](aa_core::attestation::ClaimTerm::Detected) territory
/// and not prevention. Emitting it alongside the memory ceiling would let one
/// `Resource` requirement report a pre-effect outcome on the strength of a
/// control that acts afterwards. [`crate::capability::narrow_for`] refuses such
/// a requirement instead.
fn resource(requirement: &ControlRequirement) -> Result<DomainLowering, LoweringGap> {
    let RequirementScope::Limits(limits) = requirement.scope() else {
        return Err(LoweringGap {
            domain: CapabilityDomain::Resource,
            reason: "a resource requirement must carry numeric ceilings; a whole-domain or selector \
                     scope names no quantity this mechanism could cap"
                .to_string(),
        });
    };
    if let Some(unexpressible) = unexpressible_limit(limits) {
        return Err(LoweringGap {
            domain: CapabilityDomain::Resource,
            reason: format!("the mechanism has no ceiling for {unexpressible}"),
        });
    }
    let mut flags = Vec::new();
    let mut steps = Vec::new();
    if let Some(bytes) = limits.max_memory_bytes {
        flags.push(flag_with_value(FLAG_MAX_MEMORY, &bytes.to_string()));
        steps.push(format!(
            "resource: memory ceiling of {bytes} byte(s), decided by the supervisor while the \
             allocating call is held, so the allocation does not complete"
        ));
    }
    if let Some(pids) = limits.max_pids {
        flags.push(flag_with_value(FLAG_MAX_PROCESSES, &pids.to_string()));
        steps.push(format!("resource: ceiling of {pids} process(es) in the confined tree"));
    }
    if flags.is_empty() {
        return Err(LoweringGap {
            domain: CapabilityDomain::Resource,
            reason: "the requirement stated no ceiling this mechanism can enforce before the effect".to_string(),
        });
    }
    Ok(DomainLowering { flags, steps })
}

/// The first ceiling in `limits` that this mechanism cannot enforce before the
/// effect, if any.
///
/// Named separately so [`crate::capability`] can ask the same question without
/// duplicating the list, and so adding a field to
/// [`ResourceLimits`](aa_isolation::ResourceLimits) surfaces here rather than
/// being silently ignored.
pub fn unexpressible_limit(limits: &ResourceLimits) -> Option<&'static str> {
    if limits.max_cpu_seconds.is_some() {
        return Some("accumulated CPU time");
    }
    if limits.max_file_size_bytes.is_some() {
        return Some("the size of a single created file");
    }
    if limits.max_open_files.is_some() {
        return Some("the number of simultaneously open descriptors");
    }
    if limits.max_wall_clock_seconds.is_some() {
        return Some(
            "wall-clock lifetime as a pre-effect control — the mechanism terminates a process that has \
             already run, which is detection and not prevention",
        );
    }
    None
}

/// The flags that realise the spec's credential posture.
///
/// Returned separately from the per-requirement lowering because the posture
/// lives on the spec rather than on any one requirement, and because it must be
/// emitted exactly once however many requirements a spec carries.
///
/// # Why the unremoved-ambient names are passed through too
///
/// [`CredentialPosture::ambient_unremoved`](aa_isolation::CredentialPosture)
/// means *this name reaches the child even though policy asked that it not*. On
/// a launch that replaces the environment, that is only true if this lowering
/// actually puts the name back — otherwise the posture would say the child holds
/// something the command line withheld, which is the same class of lie as
/// reporting a kept variable as removed, with the sign flipped. So a name in
/// that list is emitted exactly like a delegated one, and the *difference*
/// between the two travels where it belongs: in evidence, where a delegation
/// reads as a decision and an unremoved name reads as a debt.
pub fn credential_flags(spec: &ExecutionSpec) -> Vec<String> {
    let credentials = spec.credentials();
    if credentials.removed.is_empty() && credentials.delegated.is_empty() {
        return Vec::new();
    }
    // Start empty and add back only what was named. Removing the named
    // variables from an inherited environment would leave everything nobody
    // thought to name, which is the opposite of least authority.
    let mut flags = vec![FLAG_CLEAN_ENV.to_string()];
    for name in credentials.delegated.iter().chain(credentials.ambient_unremoved.iter()) {
        if let Some(value) = std::env::var_os(name).and_then(|v| v.into_string().ok()) {
            flags.push(flag_with_value(FLAG_ENV, &format!("{name}={value}")));
        }
    }
    flags
}

/// Names that policy asked to keep out of the child and that this lowering
/// cannot remove.
///
/// Two sources, and both are real:
///
/// * the spec's own `ambient_unremoved` list — a compatibility exception the
///   caller recorded, which this backend honours by passing the name through;
/// * every name in `removed`, but **only** when `environment_replaced` is false.
///   With no environment replacement the child inherits the launching
///   environment whole, so a name policy asked to remove is still there, and
///   reporting it as removed would be exactly the failure this Epic exists to
///   prevent.
///
/// The second source is why this function exists rather than the caller reading
/// `spec.credentials().ambient_unremoved` directly: whether a `removed` name was
/// actually removed is a property of the *lowering*, not of the posture.
///
/// `environment_replaced` is a parameter rather than `!credential_flags(spec)
/// .is_empty()` computed here because the posture is no longer the only thing
/// that can replace the environment: AAASM-5711 lets a caller hand the backend
/// the exact environment the confined program is to receive, which replaces it
/// whatever the posture says. Recomputing from the posture would then report
/// every `removed` name as residue on precisely the launches that did remove
/// them.
pub fn unremoved_ambient(spec: &ExecutionSpec, environment_replaced: bool) -> Vec<String> {
    let credentials = spec.credentials();
    let mut residue = credentials.ambient_unremoved.clone();
    if !environment_replaced {
        residue.extend(credentials.removed.iter().cloned());
    }
    residue.sort();
    residue.dedup();
    residue
}

/// Well-known instance-metadata addresses this spec's egress grants name.
///
/// The metadata service mints cloud credentials for anything that can reach it,
/// so a permitted destination that names one is ambient credential authority
/// arriving through the network domain — which is why
/// [`AmbientAuthorityKind::CloudMetadataEndpoint`] carries both domains.
///
/// # What this can and cannot see
///
/// It compares a permitted destination against
/// [`CLOUD_METADATA_ENDPOINTS`](aa_isolation::CLOUD_METADATA_ENDPOINTS)
/// literally, allowing for a trailing port or path. It therefore catches the
/// case an operator would write by hand and **does not** catch a CIDR block
/// containing the link-local range, a hostname that resolves into it, or a proxy
/// that forwards to it. That gap is stated in the evidence sentence this feeds
/// rather than papered over: a launch permitting broad egress reaches the
/// metadata service whatever this returns.
///
/// The mechanism is default-deny for egress, so a spec that permits no
/// destination reaches no metadata service, and this returns empty for the right
/// reason.
///
/// [`AmbientAuthorityKind::CloudMetadataEndpoint`]: aa_isolation::AmbientAuthorityKind::CloudMetadataEndpoint
pub fn reachable_metadata_endpoints(spec: &ExecutionSpec) -> Vec<&'static str> {
    let permitted: Vec<&str> = spec
        .requirements()
        .iter()
        .filter(|r| r.domain() == CapabilityDomain::NetworkEgress)
        .filter_map(|r| match r.scope() {
            RequirementScope::Selectors(selectors) => Some(selectors),
            _ => None,
        })
        .flatten()
        .filter_map(|s| permitted_selector(s))
        .collect();
    aa_isolation::CLOUD_METADATA_ENDPOINTS
        .iter()
        .copied()
        .filter(|endpoint| {
            permitted.iter().any(|destination| {
                *destination == *endpoint
                    // A destination is conventionally `host:port` or a URL
                    // authority; both keep the address as a prefix ending at a
                    // separator, so anchoring on one avoids matching an
                    // unrelated address that merely starts with these digits.
                    || destination
                        .strip_prefix(endpoint)
                        .is_some_and(|rest| rest.starts_with(':') || rest.starts_with('/'))
            })
        })
        .collect()
}

/// The flags that install an exact, caller-computed environment.
///
/// Every launch that uses this starts from [`FLAG_CLEAN_ENV`] and adds back only
/// what the caller listed, so the confined program receives that map and nothing
/// else. That is strictly narrower than the alternative of letting the
/// confinement executable pass its own environment through, and it is the only
/// way `aasm run` can put the governance identity, the proxy address and the
/// adapter's CA path inside the boundary: without an explicit environment those
/// variables live in the *supervisor's* process, which a `--clean-env` launch
/// deliberately does not inherit.
///
/// The caller owns the precedence question. This function applies no layering
/// of its own — the map that arrives is the environment that runs, so nothing
/// here can silently override a value the caller resolved.
pub fn explicit_environment_flags(env: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    let mut flags = vec![FLAG_CLEAN_ENV.to_string()];
    for (name, value) in env {
        flags.push(flag_with_value(FLAG_ENV, &format!("{name}={value}")));
    }
    flags
}

/// Build the whole command line for a spec and its already-lowered flags.
///
/// `confinement` is the concatenation of every requirement's flags plus the
/// credential flags; this function adds the working directory, the separator
/// and the caller's program and arguments, in that order.
pub fn build_argv(spec: &ExecutionSpec, confinement: Vec<String>) -> Argv {
    let mut args = vec![SUBCOMMAND_RUN.to_string()];
    args.extend(confinement);
    if let Some(dir) = spec.working_dir() {
        args.push(flag_with_value(FLAG_CWD, &dir.to_string_lossy()));
    }
    let separator_at = args.len();
    args.push(ARG_SEPARATOR.to_string());
    // From here down, every element is caller-supplied and is pushed whole. No
    // element is split, quoted, escaped or joined — the vector is the argument
    // vector.
    args.push(spec.program().to_string());
    args.extend(spec.args().iter().cloned());
    Argv { args, separator_at }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_isolation::{permit_only_selector, IdentityRef, RequirementIntent};

    fn spec(program: &str, args: &[&str]) -> ExecutionSpec {
        ExecutionSpec::new(program, IdentityRef::root("agent-under-test")).with_args(args.iter().copied())
    }

    /// The property the whole module exists for. Every one of these strings is
    /// a shell metacharacter sequence that would change the meaning of a
    /// concatenated command line; each must arrive as exactly one argument,
    /// byte for byte.
    #[test]
    fn caller_argv_survives_verbatim_through_the_command_line() {
        let hostile = [
            "; rm -rf /",
            "$(id)",
            "`id`",
            "a b\tc",
            "--net-allow",
            "*",
            "\n--fs-write\n/",
            "'",
            "\"",
        ];
        let argv = build_argv(&spec("/bin/echo", &hostile), Vec::new());
        assert_eq!(argv.target()[0], "/bin/echo");
        assert_eq!(argv.target()[1..], hostile.map(String::from));
    }

    /// A program name that looks like one of the backend's own flags must not
    /// be readable as one — the separator is what guarantees that, so its
    /// position is asserted rather than assumed.
    #[test]
    fn the_separator_divides_backend_flags_from_caller_input() {
        let argv = build_argv(
            &spec("--clean-env", &["-r", "/"]),
            vec![flag_with_value(FLAG_FS_READ, "/usr")],
        );
        assert_eq!(argv.confinement_flags(), ["run", "--fs-read=/usr"]);
        assert_eq!(argv.args()[argv.confinement_flags().len()], ARG_SEPARATOR);
        assert_eq!(argv.target(), ["--clean-env", "-r", "/"]);
    }

    #[test]
    fn a_whole_domain_filesystem_requirement_grants_nothing() {
        let lowered = lower_requirement(&ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
            .expect("a whole-domain filesystem requirement is expressible");
        assert!(lowered.flags.is_empty(), "{:?}", lowered.flags);
        assert!(lowered.steps[0].contains("default-deny"));
    }

    #[test]
    fn permitted_paths_become_grants_and_bare_selectors_do_not() {
        let requirement = ControlRequirement::prevent(CapabilityDomain::FilesystemRead).with_scope(
            RequirementScope::Selectors(vec![permit_only_selector("/usr"), "/etc/shadow".to_string()]),
        );
        let lowered = lower_requirement(&requirement).expect("expressible");
        assert_eq!(lowered.flags, ["--fs-read=/usr"]);
        assert!(
            lowered
                .steps
                .iter()
                .any(|s| s.contains("carried no permitted-set prefix")),
            "the un-prefixed selector must be reported, not silently dropped: {:?}",
            lowered.steps
        );
    }

    /// A syscall allow-list cannot be inverted into a finite deny-list, so it
    /// must produce a gap. If this ever starts returning `Ok`, a requirement
    /// that asked to permit exactly `read` would be satisfied by a mechanism
    /// that denies nothing.
    #[test]
    fn a_permitted_syscall_set_is_a_gap_not_an_empty_lowering() {
        let requirement = ControlRequirement::prevent(CapabilityDomain::Syscall)
            .with_scope(RequirementScope::Selectors(vec![permit_only_selector("read")]));
        let gap = lower_requirement(&requirement).expect_err("a permitted syscall set is not expressible");
        assert_eq!(gap.domain, CapabilityDomain::Syscall);
    }

    #[test]
    fn name_resolution_is_a_gap() {
        let gap = lower_requirement(&ControlRequirement::prevent(CapabilityDomain::NameResolution))
            .expect_err("name resolution is not expressible");
        assert_eq!(gap.domain, CapabilityDomain::NameResolution);
    }

    /// A wall-clock ceiling is a termination after the fact. Lowering it beside
    /// a memory ceiling would let the pair report as pre-effect, so the whole
    /// requirement is a gap instead.
    #[test]
    fn a_wall_clock_ceiling_is_a_gap_even_beside_an_expressible_one() {
        let requirement = ControlRequirement::prevent(CapabilityDomain::Resource).with_scope(RequirementScope::Limits(
            ResourceLimits {
                max_memory_bytes: Some(1024),
                max_wall_clock_seconds: Some(30),
                ..ResourceLimits::default()
            },
        ));
        let gap = lower_requirement(&requirement).expect_err("a wall-clock ceiling is not pre-effect");
        assert!(gap.reason.contains("detection and not prevention"), "{}", gap.reason);
    }

    #[test]
    fn a_memory_ceiling_lowers_to_a_flag() {
        let requirement = ControlRequirement::prevent(CapabilityDomain::Resource).with_scope(RequirementScope::Limits(
            ResourceLimits {
                max_memory_bytes: Some(268_435_456),
                ..ResourceLimits::default()
            },
        ));
        let lowered = lower_requirement(&requirement).expect("expressible");
        assert_eq!(lowered.flags, ["--max-memory=268435456"]);
    }

    #[test]
    fn a_whole_domain_process_requirement_caps_the_tree_at_one() {
        let lowered =
            lower_requirement(&ControlRequirement::prevent(CapabilityDomain::ProcessCreation)).expect("expressible");
        assert_eq!(lowered.flags, ["--max-processes=1"]);
    }

    /// AAASM-5816: the whole-domain requirement `aa_isolation::lower_policy`
    /// produces for `capabilities: deny: [terminal_exec]` must deny descendant
    /// process creation without denying the launched program's own execve. A
    /// ceiling of one process leaves exactly one slot — the launched program
    /// itself — so it is the target's own launch that fills it, and any
    /// `fork`/`clone` it attempts afterward finds no room left. This backend
    /// half of the bug was already correct (the defect was entirely in the
    /// policy lowering that fed it); this test pins the step text as the
    /// backend's own record of that split so a future change to the wording
    /// cannot silently drop the "own launch is not denied" half of the claim.
    #[test]
    fn a_whole_domain_process_requirement_permits_the_launch_and_denies_descendants() {
        let lowered =
            lower_requirement(&ControlRequirement::prevent(CapabilityDomain::ProcessCreation)).expect("expressible");
        assert!(
            lowered.steps[0].contains("the launched program itself is the whole tree"),
            "the step text must say the launched program's own execve is unaffected: {:?}",
            lowered.steps
        );
        assert!(
            lowered.steps[0].contains("any clone/fork is denied"),
            "the step text must say descendant creation is denied: {:?}",
            lowered.steps
        );
    }

    /// Least authority means starting from nothing and adding back, never
    /// starting from the ambient environment and subtracting.
    #[test]
    fn a_credential_posture_starts_from_an_empty_environment() {
        let spec = spec("/bin/true", &[]).with_credentials(aa_isolation::CredentialPosture {
            removed: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
            delegated: Vec::new(),
            ambient_unremoved: Vec::new(),
        });
        assert_eq!(credential_flags(&spec), [FLAG_CLEAN_ENV]);
        assert!(unremoved_ambient(&spec, !credential_flags(&spec).is_empty()).is_empty());
    }

    /// A posture that names nothing leaves the environment inherited, and that
    /// has to be reported as residue rather than passed over.
    #[test]
    fn an_empty_posture_reports_no_flags_and_no_false_removal() {
        let spec = spec("/bin/true", &[]);
        assert!(credential_flags(&spec).is_empty());
        assert!(unremoved_ambient(&spec, !credential_flags(&spec).is_empty()).is_empty());
    }

    /// **The property this Epic exists for, at the lowering layer.** A name the
    /// posture says could not be removed must come out of `unremoved_ambient`,
    /// and must not be silently absent because the environment was replaced.
    ///
    /// The negative control is the same variable moved from
    /// `ambient_unremoved` to `removed`: it then reports as removed and out of
    /// the residue, so the assertion below is about which list the name is in
    /// and not about the function returning everything it is given.
    #[test]
    fn a_compatibility_exception_is_reported_as_residue_and_reaches_the_child() {
        // `PATH` rather than a fabricated name: it is set on every host this
        // runs on, and mutating the process environment from a test is a data
        // race against every other test in the binary. It is also the realistic
        // exception — a child that cannot resolve a program name is a child that
        // does not run.
        assert!(std::env::var_os("PATH").is_some(), "this host sets no PATH");
        let kept = spec("/bin/true", &[]).with_credentials(aa_isolation::CredentialPosture {
            removed: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
            delegated: Vec::new(),
            ambient_unremoved: vec!["PATH".to_string()],
        });
        assert_eq!(unremoved_ambient(&kept, !credential_flags(&kept).is_empty()), ["PATH"]);
        assert!(
            credential_flags(&kept).iter().any(|f| f.starts_with("--env=PATH=")),
            "the name reported as still reaching the child was withheld from it: {:?}",
            credential_flags(&kept)
        );

        // Negative control: the same variable moved into `removed`. It leaves
        // the residue *and* leaves the command line, so the assertion above is
        // about which list the name is in.
        let removed = spec("/bin/true", &[]).with_credentials(aa_isolation::CredentialPosture {
            removed: vec!["AWS_SECRET_ACCESS_KEY".to_string(), "PATH".to_string()],
            delegated: Vec::new(),
            ambient_unremoved: Vec::new(),
        });
        assert!(unremoved_ambient(&removed, !credential_flags(&removed).is_empty()).is_empty());
        assert!(
            !credential_flags(&removed).iter().any(|f| f.contains("PATH=")),
            "a removed name reached the child: {:?}",
            credential_flags(&removed)
        );
    }

    /// With no environment replacement, every name policy asked to remove is
    /// still there — and must be reported as such rather than as removed.
    #[test]
    fn without_a_replacement_a_removed_name_is_reported_as_residue() {
        // `removed` alone triggers the clean-environment flag, so the only way
        // to reach this state is a posture that names nothing but the residue
        // itself — which is what a caller records when it could not act at all.
        let spec = spec("/bin/true", &[]).with_credentials(aa_isolation::CredentialPosture {
            removed: Vec::new(),
            delegated: Vec::new(),
            ambient_unremoved: vec!["SSH_AUTH_SOCK".to_string()],
        });
        assert!(credential_flags(&spec).is_empty());
        assert_eq!(
            unremoved_ambient(&spec, !credential_flags(&spec).is_empty()),
            ["SSH_AUTH_SOCK"]
        );
    }

    /// A permitted destination naming the metadata service is credential
    /// authority arriving over the network, and must be visible as such.
    #[test]
    fn a_permitted_metadata_destination_is_reported_as_reachable() {
        let reachable = spec("/bin/true", &[]).with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(RequirementScope::Selectors(vec![
                permit_only_selector("169.254.169.254:80"),
            ])),
        );
        assert_eq!(reachable_metadata_endpoints(&reachable), ["169.254.169.254"]);

        // Control one: the same requirement with an ordinary destination.
        let ordinary = spec("/bin/true", &[]).with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress)
                .with_scope(RequirementScope::Selectors(vec![permit_only_selector("10.0.0.1:443")])),
        );
        assert!(reachable_metadata_endpoints(&ordinary).is_empty());

        // Control two: an address that merely starts with the same digits must
        // not match, or the check reports reachability that is not there.
        let lookalike = spec("/bin/true", &[]).with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(RequirementScope::Selectors(vec![
                permit_only_selector("169.254.169.2540"),
            ])),
        );
        assert!(
            reachable_metadata_endpoints(&lookalike).is_empty(),
            "a longer address matched the metadata endpoint as a prefix"
        );
    }

    /// Default-deny means a spec that permits nothing reaches no metadata
    /// service, and the check must say so for that reason rather than by
    /// accident.
    #[test]
    fn a_spec_with_no_egress_grant_reaches_no_metadata_endpoint() {
        assert!(reachable_metadata_endpoints(&spec("/bin/true", &[])).is_empty());
        let whole =
            spec("/bin/true", &[]).with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress));
        assert!(reachable_metadata_endpoints(&whole).is_empty());
    }

    /// The boundary can only be weakened by a flag, and no spec can reach one.
    ///
    /// Swept across every domain and every scope shape rather than asserted on
    /// one example: the risk is a future lowering branch, and a test that only
    /// checks today's branches would not see it.
    #[test]
    fn no_spec_can_produce_a_flag_that_weakens_the_boundary() {
        let scopes = [
            RequirementScope::Whole,
            RequirementScope::Selectors(vec![
                permit_only_selector("--no-supervisor"),
                permit_only_selector("/tmp"),
                "--disable".to_string(),
            ]),
            RequirementScope::Limits(ResourceLimits {
                max_memory_bytes: Some(1),
                max_pids: Some(2),
                ..ResourceLimits::default()
            }),
        ];
        let mut emitted: Vec<String> = Vec::new();
        for domain in CapabilityDomain::ALL {
            for scope in &scopes {
                let requirement = ControlRequirement::prevent(*domain).with_scope(scope.clone());
                if let Ok(lowered) = lower_requirement(&requirement) {
                    emitted.extend(lowered.flags);
                }
            }
        }
        let spec =
            spec("--no-supervisor", &["--disable", "-e", "id"]).with_credentials(aa_isolation::CredentialPosture {
                removed: vec!["X".to_string()],
                delegated: vec!["Y".to_string()],
                ambient_unremoved: Vec::new(),
            });
        emitted.extend(credential_flags(&spec));
        let argv = build_argv(&spec, emitted);
        for flag in BOUNDARY_WEAKENING_FLAGS
            .iter()
            .chain(std::iter::once(&FLAG_ALLOW_DEGRADED))
        {
            assert!(
                !argv
                    .confinement_flags()
                    .iter()
                    .any(|a| a == flag || a.starts_with(&format!("{flag}="))),
                "lowering emitted the boundary-weakening flag `{flag}`: {:?}",
                argv.confinement_flags()
            );
        }
        // The control: those very strings ARE present, on the caller's side of
        // the separator, so the assertions above are not passing because the
        // strings are simply absent from the command line.
        assert!(argv.target().contains(&"--no-supervisor".to_string()));
        assert!(argv.target().contains(&"--disable".to_string()));
    }

    /// A permitted-set selector is policy data. Emitted as its own argument it
    /// would sit exactly where the mechanism's parser looks for the next flag.
    #[test]
    fn a_selector_that_looks_like_a_flag_cannot_become_one() {
        let requirement = ControlRequirement::prevent(CapabilityDomain::FilesystemRead).with_scope(
            RequirementScope::Selectors(vec![permit_only_selector("--no-supervisor")]),
        );
        let lowered = lower_requirement(&requirement).expect("expressible");
        assert_eq!(lowered.flags, ["--fs-read=--no-supervisor"]);
        assert_eq!(
            lowered.flags.len(),
            1,
            "the value must share an argument with its flag, or it can be read as one: {:?}",
            lowered.flags
        );
    }

    #[test]
    fn the_intent_of_a_requirement_does_not_change_the_flags_emitted() {
        // Lowering answers "what would this mechanism do", not "may it".
        // Whether an observe-only requirement is *acceptable* is `negotiate`'s
        // decision, and duplicating it here is how the two would diverge.
        let prevent = lower_requirement(&ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)).unwrap();
        let observe = lower_requirement(&ControlRequirement::observe(CapabilityDomain::FilesystemWrite)).unwrap();
        assert_eq!(prevent.flags, observe.flags);
        assert_eq!(
            ControlRequirement::observe(CapabilityDomain::FilesystemWrite).intent(),
            RequirementIntent::Observe
        );
    }
}
