//! Turning a permitted path scope into the kernel rules that realise it.
//!
//! Split in two on purpose. [`plan`] is pure, total and platform-free — it
//! answers *which rights each path gets* and is unit-testable on any host.
//! [`install`] is the only function that calls the kernel, and it does nothing
//! but execute a plan. A boundary that was computed in the same place it was
//! applied could only be tested on a Linux runner, which is where the arithmetic
//! errors would be least visible.
//!
//! # Nested grants: a deeper path is never weaker than one above it
//!
//! Policy states read and write scope separately, so a document that permits
//! reading `/workspace` and writing `/workspace/build` is ordinary. The kernel
//! primitive attaches rights to a file hierarchy, and this crate deliberately
//! does **not** depend on how it combines a rule with a rule above it: [`plan`]
//! gives every granted path the union of its own rights and the rights of every
//! granted path that contains it, so the installed rule for `/workspace/build`
//! carries read *and* write whichever way the kernel would have resolved the
//! pair.
//!
//! This can only ever add a right an ancestor already granted, so it grants
//! nothing the operator did not write — and it removes the case where naming a
//! subtree for one verb silently withdraws the other verb the operator granted
//! above it. [`tests::a_deeper_grant_keeps_the_rights_granted_above_it`] is the
//! property; [`tests::propagation_never_grants_a_right_no_ancestor_granted`] is
//! the control in the other direction.
//!
//! # Containment is component-aware
//!
//! `/workspace` does not contain `/workspace-of-someone-else`. A byte-prefix
//! test would say it does, which is the classic prefix-matching widening that a
//! path allow-list exists to prevent, and it is checked here rather than assumed
//! from the policy layer because these two run in different processes.

use std::collections::BTreeMap;

use crate::launch::{Grants, PathVerbs};

/// One installed rule: a path and the rights its subtree carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRule {
    /// The path the rule is tied to.
    pub path: String,
    /// The rights the subtree beneath it carries.
    pub verbs: PathVerbs,
}

/// The complete set of rules one launch installs, in a deterministic order.
///
/// An empty plan is a *policy* — deny everything — and never an absent one. The
/// distinction is the reason this is a plain `Vec` rather than an `Option`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulePlan {
    /// Every rule, ordered by path.
    pub rules: Vec<PlannedRule>,
}

impl RulePlan {
    /// Whether the plan permits nothing at all.
    pub fn denies_everything(&self) -> bool {
        self.rules.is_empty()
    }

    /// One sentence per rule, for the opaque
    /// [`Lowering`](aa_isolation::Lowering) an evidence record carries.
    pub fn describe(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|rule| {
                format!(
                    "{}: {}",
                    rule.path,
                    match (rule.verbs.read, rule.verbs.write) {
                        (true, true) => "read and write the subtree beneath it",
                        (true, false) => "read the subtree beneath it",
                        (false, true) => "write the subtree beneath it",
                        // Unreachable through `plan`, which only emits a path
                        // some verb named. Stated rather than `unreachable!` so
                        // a future caller that constructs a `RulePlan` by hand
                        // gets a legible sentence instead of a panic.
                        (false, false) => "no right (an empty rule grants nothing)",
                    }
                )
            })
            .collect()
    }
}

/// Whether `ancestor` contains `path` — equal, or a proper directory prefix.
///
/// Component-aware: see the module documentation for why a byte prefix is
/// wrong. Both arguments are expected absolute; a non-absolute one simply fails
/// to contain anything, which is the fail-closed direction.
fn contains(ancestor: &str, path: &str) -> bool {
    if ancestor == "/" {
        return true;
    }
    if path == ancestor {
        return true;
    }
    path.len() > ancestor.len() && path.starts_with(ancestor) && path.as_bytes()[ancestor.len()] == b'/'
}

/// Compute the rules a grant set installs.
///
/// Pure and total: no filesystem is touched, so the same grants produce the same
/// plan on every host and in every test.
pub fn plan(grants: &Grants) -> RulePlan {
    let by_path: BTreeMap<&str, PathVerbs> = grants.by_path();
    let rules = by_path
        .iter()
        .map(|(path, verbs)| {
            let mut effective = *verbs;
            for (other, other_verbs) in &by_path {
                if contains(other, path) {
                    effective.read |= other_verbs.read;
                    effective.write |= other_verbs.write;
                }
            }
            PlannedRule {
                path: (*path).to_string(),
                verbs: effective,
            }
        })
        .collect();
    RulePlan { rules }
}

/// The Landlock ABI version this backend's filesystem claim requires, and why
/// this number rather than a lower one.
///
/// **Measured, not assumed** — see `crate::host::AbiFloor` for how a host is
/// checked against it, and `tests/linux_confinement_native.rs`'s truncation
/// scenario for the adversarial control that would fail if the number were
/// lowered.
///
/// * ABI v1 (Linux 5.13) carries the open/read/create/remove rights, and would
///   be enough for a claim about *opening* files.
/// * ABI v2 (Linux 5.19) adds `REFER`, which is what makes a cross-directory
///   rename or hard link expressible at all. Without it the kernel denies every
///   such operation outright, so v2 is not required for the claim to be true —
///   it is required for it to be usable.
/// * **ABI v3 (Linux 6.2) adds `TRUNCATE`, and this backend's write claim is
///   false below it.** `truncate(2)` takes a path and needs no writable
///   descriptor, so on a v1/v2 kernel a program confined by this backend can
///   still destroy the contents of any file outside its write grant. A right the
///   kernel does not handle is a right the kernel allows; there is no
///   configuration of a v2 host that closes this.
///
/// Higher versions add capability this backend does not claim (`IOCTL_DEV` at
/// v5, abstract-socket and signal scoping at v6, audit control at v7), so they
/// are not part of the floor — they appear as stated limitations on the
/// capability report instead.
#[cfg(target_os = "linux")]
pub const REQUIRED_ABI: landlock::ABI = landlock::ABI::V3;

/// The [`REQUIRED_ABI`] as a plain number, for messages and for hosts where the
/// binding crate is not compiled in.
pub const REQUIRED_ABI_VERSION: u32 = 3;

/// The kernel release that first carried [`REQUIRED_ABI_VERSION`], for an
/// operator who has a `uname -r` and not an ABI number.
pub const REQUIRED_KERNEL_RELEASE: &str = "6.2";

/// What installing a plan produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The effective Landlock ABI the kernel and the binding agreed on.
    pub effective_abi: u32,
    /// Whether every requested restriction was enforced, verbatim from the
    /// kernel binding.
    ///
    /// Anything other than "fully enforced" is a refusal at the call site, not a
    /// value a caller has to remember to check — it is carried for the record.
    pub fully_enforced: bool,
}

/// Install a plan on the calling thread group, or fail without installing a
/// partial one.
///
/// # Why this refuses instead of degrading
///
/// The binding's default compatibility level silently drops any right the
/// running kernel does not support, which on a kernel below [`REQUIRED_ABI`]
/// would install a ruleset that *looks* like the requested one and does not stop
/// `truncate(2)`. This asks for a hard requirement instead, so an old kernel
/// produces an error here rather than a boundary nobody could tell apart from
/// the real one. `crate::host` refuses earlier still, before any process starts;
/// this is the same rule restated at the syscall, because the two run in
/// different processes and this one cannot assume the other ran.
///
/// A path in the plan that cannot be opened is also an error rather than a
/// dropped rule. Dropping it would be *stricter* — so it is not a security
/// failure — but it would produce a launch whose installed boundary differs from
/// the planned one with nothing recording that it did.
///
/// # Errors
///
/// A sentence naming what failed, suitable for
/// [`crate::launch::FAILURE_MARKER`] output. Nothing is executed after an error.
#[cfg(target_os = "linux")]
pub fn install(plan: &RulePlan) -> Result<Installed, String> {
    use landlock::{
        Access, AccessFs, BitFlags, CompatLevel, Compatible, LandlockStatus, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };

    let handled = AccessFs::from_all(REQUIRED_ABI);
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(|e| {
            format!(
                "the kernel cannot handle the access rights this backend's filesystem claim requires \
                 (Landlock ABI v{REQUIRED_ABI_VERSION}, Linux {REQUIRED_KERNEL_RELEASE} or newer): {e}"
            )
        })?
        .create()
        .map_err(|e| format!("the Landlock ruleset could not be created: {e}"))?;

    for rule in &plan.rules {
        let mut access: BitFlags<AccessFs> = BitFlags::EMPTY;
        if rule.verbs.read {
            access |= AccessFs::from_read(REQUIRED_ABI);
        }
        if rule.verbs.write {
            access |= AccessFs::from_write(REQUIRED_ABI);
        }
        // Opened with `O_PATH | O_CLOEXEC` by the binding, so the descriptor
        // cannot be read through and cannot survive the `execve` below into the
        // confined program.
        let fd = PathFd::new(&rule.path).map_err(|e| {
            format!(
                "the permitted path `{}` could not be opened, so the rule the supervisor planned was not \
                 installed; refusing rather than confining with a boundary that differs from the plan: {e}",
                rule.path
            )
        })?;
        let is_directory = std::fs::metadata(&rule.path)
            .map(|meta| meta.is_dir())
            .map_err(|e| format!("the permitted path `{}` could not be inspected: {e}", rule.path))?;
        let access = file_safe(access, is_directory);
        if access.is_empty() {
            return Err(format!(
                "the rule for `{}` would carry no right at all once the directory-only rights were \
                 removed, and an empty rule grants nothing; refusing rather than installing it",
                rule.path
            ));
        }
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| format!("the rule for `{}` was rejected by the kernel: {e}", rule.path))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| format!("the ruleset could not be applied to this process: {e}"))?;

    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(format!(
            "the kernel enforced only part of the requested boundary ({:?}); refusing rather than \
             executing the program behind a boundary weaker than the one that was planned",
            status.ruleset
        ));
    }
    if !status.no_new_privs {
        return Err(
            "`no_new_privs` was not set, so a set-user-ID program could regain privilege from inside the \
             boundary; refusing rather than executing the program"
                .to_string(),
        );
    }
    let effective_abi = match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => effective_abi as u32,
        // Unreachable while `restrict_self` returned `FullyEnforced` above,
        // which a kernel without Landlock cannot produce. Stated rather than
        // assumed so a future binding change surfaces here as a refusal.
        other => {
            return Err(format!(
                "the kernel reported the boundary as enforced while reporting Landlock as `{other:?}`; \
                 refusing rather than trusting a contradiction"
            ))
        }
    };
    Ok(Installed {
        effective_abi,
        fully_enforced: true,
    })
}

/// The rights a rule may carry, given whether its path is a directory.
///
/// # Why this is not "belt and braces"
///
/// The kernel **rejects** — it does not ignore — a rule that ties a
/// directory-only right to a regular file: `landlock_add_rule` returns `EINVAL`,
/// and because [`install`] refuses rather than degrades, one such rule turns
/// every launch on that host into a refusal. `AccessFs::from_read` carries
/// `ReadDir` alongside `ReadFile`, so *any* permitted path that names a file
/// rather than a directory hits it. Policy has been able to name one since the
/// path scope existed; AAASM-5804's `/proc` scope made it certain, because
/// `/proc/bootconfig` and its neighbours are files.
///
/// Removing the directory-only bits is not a widening: they are meaningless on a
/// file, and the file rights that remain are the ones the requirement asked for.
#[cfg(target_os = "linux")]
fn file_safe(
    access: landlock::BitFlags<landlock::AccessFs>,
    is_directory: bool,
) -> landlock::BitFlags<landlock::AccessFs> {
    use landlock::AccessFs;
    if is_directory {
        access
    } else {
        access & AccessFs::from_file(REQUIRED_ABI)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arithmetic behind the fix, checkable without a kernel: a directory
    /// keeps every right, a file keeps the file rights and loses `ReadDir`, and
    /// neither gains anything.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_rule_on_a_file_loses_the_directory_only_rights_and_gains_nothing() {
        use landlock::{Access, AccessFs};

        for requested in [
            AccessFs::from_read(REQUIRED_ABI),
            AccessFs::from_write(REQUIRED_ABI),
            AccessFs::from_all(REQUIRED_ABI),
        ] {
            let on_directory = file_safe(requested, true);
            assert_eq!(on_directory, requested, "a directory rule was narrowed");

            let on_file = file_safe(requested, false);
            assert!(on_file.contains(requested & AccessFs::from_file(REQUIRED_ABI)));
            assert!(
                requested.contains(on_file),
                "a file rule gained a right the requirement did not ask for"
            );
            assert!(
                !on_file.contains(AccessFs::ReadDir),
                "a rule tied to a regular file kept a directory-only right, which the kernel rejects"
            );
            assert!(!on_file.is_empty(), "a file rule lost every right");
        }

        // The control: `ReadDir` really is among the rights a read requirement
        // asks for, so the assertion above is removing something rather than
        // observing an absence that was always there.
        assert!(AccessFs::from_read(REQUIRED_ABI).contains(AccessFs::ReadDir));
    }

    fn grants(read: &[&str], write: &[&str]) -> Grants {
        Grants {
            read: read.iter().map(|s| (*s).to_string()).collect(),
            write: write.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn verbs_for<'a>(plan: &'a RulePlan, path: &str) -> &'a PathVerbs {
        &plan
            .rules
            .iter()
            .find(|r| r.path == path)
            .unwrap_or_else(|| panic!("no rule for {path}: {plan:?}"))
            .verbs
    }

    /// **The property this module exists for.** Naming a subtree for one verb
    /// must not withdraw the other verb an ancestor granted.
    #[test]
    fn a_deeper_grant_keeps_the_rights_granted_above_it() {
        let plan = plan(&grants(&["/workspace"], &["/workspace/build"]));
        assert_eq!(
            verbs_for(&plan, "/workspace/build"),
            &PathVerbs {
                read: true,
                write: true
            }
        );
        // The control, in the same plan: the ancestor did NOT acquire the
        // descendant's write right, so propagation runs one way only.
        assert_eq!(
            verbs_for(&plan, "/workspace"),
            &PathVerbs {
                read: true,
                write: false
            }
        );
    }

    /// The other direction, and the reason propagation is safe: a path can only
    /// gain a right some containing grant already carried.
    #[test]
    fn propagation_never_grants_a_right_no_ancestor_granted() {
        let plan = plan(&grants(&["/etc"], &["/workspace"]));
        assert_eq!(
            verbs_for(&plan, "/etc"),
            &PathVerbs {
                read: true,
                write: false
            },
            "a disjoint write grant reached an unrelated read grant"
        );
        assert_eq!(
            verbs_for(&plan, "/workspace"),
            &PathVerbs {
                read: false,
                write: true
            },
            "a disjoint read grant reached an unrelated write grant"
        );
    }

    /// A byte-prefix test would make `/workspace` contain
    /// `/workspace-of-someone-else`, which is the widening a path allow-list
    /// exists to prevent.
    #[test]
    fn containment_is_component_aware_not_byte_prefix() {
        assert!(contains("/workspace", "/workspace/build"));
        assert!(contains("/workspace", "/workspace"));
        assert!(contains("/", "/anything"));
        assert!(!contains("/workspace", "/workspace-of-someone-else"));
        assert!(!contains("/workspace/build", "/workspace"));

        let plan = plan(&grants(&["/workspace"], &["/workspace-of-someone-else"]));
        assert_eq!(
            verbs_for(&plan, "/workspace-of-someone-else"),
            &PathVerbs {
                read: false,
                write: true
            },
            "a lookalike sibling inherited the read grant as if it were beneath it"
        );
    }

    /// Root is an ancestor of everything, so a grant on `/` reaches every other
    /// rule. Asserted because it is the one path where the component rule has a
    /// special case.
    #[test]
    fn a_root_grant_reaches_every_other_rule() {
        let plan = plan(&grants(&["/"], &["/workspace"]));
        assert_eq!(
            verbs_for(&plan, "/workspace"),
            &PathVerbs {
                read: true,
                write: true
            }
        );
    }

    /// An empty grant set is deny-everything, and the plan must say so rather
    /// than looking like an absent plan.
    #[test]
    fn an_empty_grant_set_plans_no_rules_and_denies_everything() {
        let plan = plan(&Grants::default());
        assert!(plan.denies_everything());
        assert!(plan.describe().is_empty());
    }

    /// The plan is the input to an evidence record, so it has to be
    /// deterministic across runs and it has to name every path.
    #[test]
    fn the_plan_is_ordered_and_describes_every_rule() {
        let plan = plan(&grants(&["/usr", "/etc"], &["/workspace"]));
        let paths: Vec<&str> = plan.rules.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/etc", "/usr", "/workspace"]);
        assert_eq!(plan.describe().len(), 3);
        assert!(plan.describe()[2].contains("write"));
    }
}
