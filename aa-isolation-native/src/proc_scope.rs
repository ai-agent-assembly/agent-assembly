//! Keeping other processes' per-PID `/proc` entries outside a granted `/proc`
//! (AAASM-5804).
//!
//! # The gap this closes, and why a filesystem rule is what closes it
//!
//! AAASM-5709 gave the confined program an environment built from nothing, with
//! only the names the launch delegated added back. AAASM-5785 and AAASM-5786
//! then measured what that is worth while `/proc` is readable: nothing stops the
//! confined program opening some *other* process's `/proc/<pid>/environ` and
//! reading the credentials that were withheld from its own environment. An
//! environment plan is a statement about one process's `environ` array; it is
//! not a statement about who may read it.
//!
//! `/proc` is not an unusual grant — it is on the read list of nearly every
//! launch this backend makes, because the dynamic loader, the shell and most
//! interpreters want it. So the grant that makes the credential control moot is
//! the ordinary one, which is exactly why ADR 0035's AAASM-5801 amendment
//! (*`/proc` scoping: how AAASM-5709's environment grant becomes an enforced
//! boundary*) makes this the filesystem primitive's job rather than a separate
//! mechanism.
//!
//! # What the scope does
//!
//! A launch that grants `/proc` gets, instead of one rule on `/proc`, one rule
//! per **non-PID** top-level entry — `/proc/sys`, `/proc/meminfo`,
//! `/proc/cpuinfo`, and so on — plus `/proc/self`. Every `/proc/<pid>` directory
//! belonging to some other process is then simply not named by any rule, and the
//! kernel primitive is default-deny within the rights it handles.
//!
//! This can only ever remove access: every emitted path is beneath the `/proc`
//! the launch already granted. Nothing here grants a path policy did not reach,
//! which is the invariant [`crate::lower`] is built around and this module is
//! deliberately downstream of.
//!
//! # Why `/proc/self` is emitted as the literal string
//!
//! `/proc/self` resolves per-process, at open time. The supervisor builds the
//! grant set but the **launcher** opens the paths and installs the rules, and
//! the launcher is the confined program — it `execve`s it, keeping its process
//! id. So the string `/proc/self` handed across the command line resolves, in
//! the only process that resolves it, to the confined program's own per-PID
//! directory.
//!
//! Resolving it in the supervisor would tie the rule to the *supervisor's*
//! directory: the confined program would lose its own process state and gain a
//! window into the trusted supervisor's — the exact inversion this module
//! exists to prevent. [`tests::the_own_process_entry_is_never_resolved_here`]
//! pins it.
//!
//! # Two things this scope cannot do, both recorded rather than glossed
//!
//! * **A `/` grant defeats it.** A kernel rule adds a permission; it cannot
//!   subtract one. A launch that grants `/` has already granted every
//!   `/proc/<pid>` beneath it, and no rule under `/proc` withdraws that. Such a
//!   launch is left alone and reported as unscoped, because narrowing something
//!   while the wider grant stands would produce evidence that reads stricter
//!   than the boundary is.
//! * **A descendant cannot read its own per-PID entry either.** The rule is tied
//!   to the launched process's directory, which is the only per-PID directory
//!   that exists when the boundary is installed. A child the confined program
//!   forks afterwards has a different process id, and `/proc/self` from inside
//!   *that* process resolves somewhere no rule names. This is strictly stricter
//!   than an unscoped `/proc` — it withholds, it never grants — but it is a real
//!   behavioural limit and it is carried on the capability report rather than
//!   discovered by an operator whose tool broke.

use crate::launch::Grants;

/// The top-level path whose per-PID children this module keeps out.
pub const PROC: &str = "/proc";

/// The one per-PID entry a scoped `/proc` keeps: the confined program's own.
///
/// A literal, never a resolved path — see the module documentation.
pub const OWN_PROC: &str = "/proc/self";

/// The path that makes the scope unexpressible when it is granted.
const ROOT: &str = "/";

/// What `/proc` looked like when the grant set was built.
///
/// A value rather than a filesystem read inside [`scope`], so the decision is
/// pure and testable on a host that has no `/proc` at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcListing {
    /// The top-level entries of `/proc`, as read from the host. May contain
    /// per-PID names; [`scope`] is what filters them, so the filter is unit
    /// tested rather than trusted to the reader.
    Enumerated(Vec<String>),
    /// `/proc` could not be listed, and why.
    Unavailable(String),
}

/// A grant set with the `/proc` scope applied, or explicitly not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedGrants {
    /// The grants the launch will actually install.
    pub grants: Grants,
    /// Whether other processes' per-PID entries are outside the installed scope.
    ///
    /// True only when the scope was applied *or* when no `/proc` grant existed
    /// to scope — both of which leave a sibling's `environ` unreachable. False
    /// whenever a `/proc` (or `/`) grant stands unscoped, which is the state
    /// AAASM-5785 measured.
    pub per_pid_entries_withheld: bool,
    /// One sentence per decision taken, for evidence.
    pub steps: Vec<String>,
}

/// Apply the `/proc` scope to a grant set.
///
/// Pure and total: the same grants and the same listing produce the same result
/// on every host, including hosts with no `/proc`.
pub fn scope(grants: &Grants, listing: &ProcListing) -> ScopedGrants {
    let root_granted = grants.read.contains(ROOT) || grants.write.contains(ROOT);
    let proc_read = grants.read.contains(PROC);
    let proc_write = grants.write.contains(PROC);

    if root_granted {
        return ScopedGrants {
            grants: grants.clone(),
            per_pid_entries_withheld: false,
            steps: vec![format!(
                "/proc scope NOT applied: this launch grants `{ROOT}`, and a kernel rule adds a permission \
                 rather than subtracting one, so no rule beneath `{PROC}` can withdraw what the `{ROOT}` \
                 rule already granted. Every other process's `{PROC}/<pid>/environ` is readable from inside \
                 this boundary, so the delegated child environment is not a credential boundary on this \
                 launch (AAASM-5785)"
            )],
        };
    }
    if !proc_read && !proc_write {
        return ScopedGrants {
            grants: grants.clone(),
            per_pid_entries_withheld: true,
            steps: vec![format!(
                "/proc scope not needed: this launch names no `{PROC}` grant, so the default-deny posture \
                 already keeps every per-PID entry — including other processes' `environ` — outside it"
            )],
        };
    }

    let entries = match listing {
        ProcListing::Unavailable(reason) => {
            return ScopedGrants {
                grants: grants.clone(),
                per_pid_entries_withheld: false,
                steps: vec![format!(
                    "/proc scope NOT applied: `{PROC}` could not be listed ({reason}), so the entries to \
                     grant in its place are unknown. The launch-wide `{PROC}` grant stands rather than \
                     being replaced by a guess, and every other process's `{PROC}/<pid>/environ` stays \
                     readable from inside this boundary (AAASM-5785)"
                )],
            }
        }
        ProcListing::Enumerated(entries) => entries,
    };

    let kept: Vec<&str> = entries
        .iter()
        .map(String::as_str)
        .filter(|name| is_non_pid_entry(name))
        .collect();
    if kept.is_empty() {
        return ScopedGrants {
            grants: grants.clone(),
            per_pid_entries_withheld: false,
            steps: vec![format!(
                "/proc scope NOT applied: the listing of `{PROC}` held no non-PID entry, which no live \
                 Linux host produces. The launch-wide `{PROC}` grant stands rather than being replaced by \
                 an empty one, and every other process's `{PROC}/<pid>/environ` stays readable from inside \
                 this boundary (AAASM-5785)"
            )],
        };
    }

    let mut scoped = grants.clone();
    let mut steps = Vec::new();
    for (verb, granted, set) in [
        ("read", proc_read, &mut scoped.read),
        ("write", proc_write, &mut scoped.write),
    ] {
        if !granted {
            continue;
        }
        set.remove(PROC);
        for name in &kept {
            set.insert(format!("{PROC}/{name}"));
        }
        // Belt and braces: `self` is a top-level entry of every live `/proc`, so
        // the loop above already emitted it. Inserting it explicitly means a
        // host whose listing somehow omitted it still leaves the confined
        // program its own process state, rather than losing it silently.
        set.insert(OWN_PROC.to_string());
        steps.push(format!(
            "/proc {verb} scope applied: the launch-wide `{PROC}` grant was replaced by {} non-PID \
             entrie(s) beneath it plus `{OWN_PROC}`, which the launcher — the confined process itself — \
             resolves to its own per-PID directory. No other process's `{PROC}/<pid>` is named by any \
             rule, so its `environ` is outside this launch's {verb} scope (AAASM-5785/5786)",
            kept.len()
        ));
    }

    ScopedGrants {
        grants: scoped,
        per_pid_entries_withheld: true,
        steps,
    }
}

/// Whether a top-level `/proc` name is something other than a process directory.
///
/// Per-PID directories are decimal names, and the kernel produces no other
/// all-decimal entry at this level. Anything containing a path separator, and
/// the two directory entries themselves, are refused as well: they are not
/// entries this module may turn into a grant, and a `..` reaching a grant is the
/// classic widening a path allow-list exists to prevent.
fn is_non_pid_entry(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.bytes().all(|b| b.is_ascii_digit())
}

/// Read the top-level entries of `/proc` on this host.
///
/// # Why an entry that does not resolve is dropped here
///
/// [`crate::rules::install`] refuses the whole launch when a planned path cannot
/// be opened, deliberately: a dropped rule would install a boundary that differs
/// from the plan with nothing recording that it did. That rule is right and it
/// makes this listing load-bearing — one dangling symlink among `/proc`'s
/// top-level entries would turn every launch on the host into a refusal. So an
/// entry that does not resolve *now*, in the supervisor, never becomes a planned
/// path at all. Dropping it can only narrow the boundary, and it is dropped
/// before the plan exists rather than after it was made.
///
/// # Errors
///
/// Never — a failure becomes [`ProcListing::Unavailable`] carrying the reason,
/// because a scope that could not be computed has to reach evidence as a stated
/// non-application rather than as an error a caller might drop.
#[cfg(target_os = "linux")]
pub fn read_listing() -> ProcListing {
    let entries = match std::fs::read_dir(PROC) {
        Ok(entries) => entries,
        Err(e) => return ProcListing::Unavailable(format!("{PROC} could not be opened: {e}")),
    };
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => return ProcListing::Unavailable(format!("{PROC} could not be read through: {e}")),
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_non_pid_entry(&name) {
            continue;
        }
        if std::fs::metadata(entry.path()).is_ok() {
            names.insert(name);
        }
    }
    ProcListing::Enumerated(names.into_iter().collect())
}

/// The non-Linux arm. This backend confines nothing here, and a listing invented
/// on a host with no `/proc` would be a fact about nothing.
#[cfg(not(target_os = "linux"))]
pub fn read_listing() -> ProcListing {
    ProcListing::Unavailable(format!(
        "this host is {}, which has no {PROC} to list; this backend confines Linux processes",
        std::env::consts::OS
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants(read: &[&str], write: &[&str]) -> Grants {
        Grants {
            read: read.iter().map(|s| (*s).to_string()).collect(),
            write: write.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// A listing shaped like a live host's: non-PID entries mixed with process
    /// directories.
    fn listing() -> ProcListing {
        ProcListing::Enumerated(
            ["1", "17", "4021", "cpuinfo", "meminfo", "self", "sys", "thread-self"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        )
    }

    /// **The property this module exists for.** A granted `/proc` stops naming
    /// any other process's directory, and the confined program keeps its own.
    #[test]
    fn a_granted_proc_becomes_its_non_pid_entries_plus_the_process_its_own() {
        let scoped = scope(&grants(&["/usr", PROC], &[]), &listing());
        let read: Vec<&str> = scoped.grants.read.iter().map(String::as_str).collect();
        assert_eq!(
            read,
            [
                "/proc/cpuinfo",
                "/proc/meminfo",
                "/proc/self",
                "/proc/sys",
                "/proc/thread-self",
                "/usr"
            ]
        );
        assert!(scoped.per_pid_entries_withheld);
        // The control, in the same result: an unrelated grant is untouched, so
        // the assertion above is about `/proc` and not about a rewritten set.
        assert!(scoped.grants.read.contains("/usr"));
        assert!(scoped.grants.write.is_empty());
    }

    /// Every per-PID name in the listing must be gone, and no rule may name one.
    #[test]
    fn no_other_processs_directory_survives_the_scope() {
        let scoped = scope(&grants(&[PROC], &[]), &listing());
        for pid in ["1", "17", "4021"] {
            assert!(
                !scoped.grants.read.contains(&format!("{PROC}/{pid}")),
                "a per-PID directory was granted: {pid}"
            );
        }
        assert!(
            !scoped.grants.read.contains(PROC),
            "the launch-wide /proc grant survived, so every per-PID entry is still beneath a rule"
        );
    }

    /// The literal string is what crosses the command line: resolving it here
    /// would tie the rule to the supervisor's own directory.
    #[test]
    fn the_own_process_entry_is_never_resolved_here() {
        let scoped = scope(&grants(&[PROC], &[]), &listing());
        assert!(scoped.grants.read.contains(OWN_PROC));
        let this_process = format!("{PROC}/{}", std::process::id());
        assert!(
            !scoped.grants.read.contains(&this_process),
            "the scope resolved `{OWN_PROC}` in the supervisor, which would confine the child to the \
             supervisor's process directory"
        );
    }

    /// Scoping under a `/` grant would report a narrowing the kernel did not
    /// perform, because a rule cannot subtract from a wider one.
    #[test]
    fn a_root_grant_is_left_alone_and_reported_as_unscoped() {
        let scoped = scope(&grants(&["/", PROC], &[]), &listing());
        assert_eq!(scoped.grants, grants(&["/", PROC], &[]));
        assert!(!scoped.per_pid_entries_withheld);
        assert!(scoped.steps[0].contains("NOT applied"), "{:?}", scoped.steps);
    }

    /// A listing that could not be taken must leave the grant alone *and* say
    /// the boundary is the unscoped one — never quietly emit `/proc/self` and
    /// read as if the gap were closed.
    #[test]
    fn an_unavailable_listing_leaves_the_grant_and_reports_it() {
        let before = grants(&[PROC], &[]);
        let scoped = scope(&before, &ProcListing::Unavailable("no permission".to_string()));
        assert_eq!(scoped.grants, before);
        assert!(!scoped.per_pid_entries_withheld);
        assert!(scoped.steps[0].contains("no permission"), "{:?}", scoped.steps);

        // The same for a listing with nothing usable in it.
        let empty = scope(&before, &ProcListing::Enumerated(vec!["1".to_string()]));
        assert_eq!(empty.grants, before);
        assert!(!empty.per_pid_entries_withheld);
    }

    /// A launch that never granted `/proc` is already strict, and must not be
    /// reported as the AAASM-5785 state.
    #[test]
    fn a_launch_with_no_proc_grant_is_untouched_and_already_withholds() {
        let before = grants(&["/usr"], &["/workspace"]);
        let scoped = scope(&before, &listing());
        assert_eq!(scoped.grants, before);
        assert!(scoped.per_pid_entries_withheld);
        assert!(scoped.steps[0].contains("not needed"), "{:?}", scoped.steps);
    }

    /// The verb a launch granted is the verb that is scoped, and the other verb
    /// gains nothing. The pair is the control.
    #[test]
    fn the_scope_grants_no_verb_the_launch_did_not() {
        let read_only = scope(&grants(&[PROC], &[]), &listing());
        assert!(read_only.grants.write.is_empty(), "a read grant became a write grant");

        let write_only = scope(&grants(&[], &[PROC]), &listing());
        assert!(write_only.grants.read.is_empty(), "a write grant became a read grant");
        assert!(write_only.grants.write.contains(OWN_PROC));
        assert!(!write_only.grants.write.contains(PROC));
    }

    /// **The invariant that makes this safe to run on every launch.** Every path
    /// the scope emits is beneath something the launch already granted, so no
    /// scoping can widen a boundary.
    #[test]
    fn the_scope_never_emits_a_path_outside_what_was_granted() {
        for before in [
            grants(&[PROC], &[]),
            grants(&[PROC, "/usr"], &[PROC]),
            grants(&["/usr"], &["/workspace"]),
            grants(&["/", PROC], &[]),
        ] {
            let after = scope(&before, &listing());
            for (was, now) in [(&before.read, &after.grants.read), (&before.write, &after.grants.write)] {
                for path in now {
                    assert!(
                        was.iter().any(|granted| path == granted
                            || (path.starts_with(granted) && path.as_bytes().get(granted.len()) == Some(&b'/'))),
                        "the scope emitted `{path}`, which no grant in {was:?} contains"
                    );
                }
            }
        }
    }

    /// A per-PID directory policy named *explicitly* is the operator's decision
    /// and is not this module's to withdraw — it only replaces the launch-wide
    /// grant.
    #[test]
    fn an_explicitly_named_process_directory_is_not_withdrawn() {
        let scoped = scope(&grants(&[PROC, "/proc/17"], &[]), &listing());
        assert!(scoped.grants.read.contains("/proc/17"));
    }

    #[test]
    fn a_name_that_is_not_a_usable_entry_never_becomes_a_grant() {
        for hostile in ["", ".", "..", "../etc", "sys/kernel", "1", "0", "999999"] {
            assert!(!is_non_pid_entry(hostile), "{hostile} was accepted as a /proc entry");
        }
        for real in ["self", "thread-self", "sys", "cpuinfo", "version_signature", "1abc"] {
            assert!(is_non_pid_entry(real), "{real} was refused as a /proc entry");
        }
    }

    /// A Linux host lists its real `/proc`, and `self` is in it — which is why
    /// the explicit insertion of [`OWN_PROC`] is belt and braces rather than the
    /// only thing keeping the confined program's own state reachable.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_linux_host_lists_its_own_proc_including_self() {
        let ProcListing::Enumerated(entries) = read_listing() else {
            panic!("a Linux host could not list {PROC}");
        };
        assert!(entries.iter().any(|e| e == "self"), "{entries:?}");
        // This process's own directory is in `/proc` by definition, and it must
        // not be in the listing — so the assertion above is not passing over a
        // listing that simply kept everything.
        assert!(
            !entries.contains(&std::process::id().to_string()),
            "a per-PID directory reached the listing: {entries:?}"
        );
        assert!(
            entries.iter().all(|e| !e.bytes().all(|b| b.is_ascii_digit())),
            "{entries:?}"
        );
    }

    /// Anywhere else the listing is explicitly unavailable, never an empty list
    /// that would read as "nothing there" and produce an empty scope.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_non_linux_host_reports_the_listing_as_unavailable() {
        let ProcListing::Unavailable(reason) = read_listing() else {
            panic!("a host with no {PROC} enumerated one");
        };
        assert!(reason.contains(std::env::consts::OS), "{reason}");
    }
}
