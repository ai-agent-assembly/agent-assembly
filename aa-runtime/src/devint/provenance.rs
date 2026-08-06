//! Which build answered — runtime provenance for the DI-API (AAASM-5628).
//!
//! # The failure this module exists to make impossible
//!
//! `aasm` reported whatever runtime happened to be listening, and nothing on
//! any surface said *which build* produced the answer. Twice that produced a
//! confident wrong answer:
//!
//! 1. A runtime built from a **different checkout** answered and reported
//!    `DI-API v2` where the checkout under test declares `v3`. Every
//!    measurement in that campaign was silently against the wrong build.
//! 2. A runtime whose **worktree had been deleted** kept serving and reported
//!    `claude-code … not_installed` while Claude Code was healthy and on
//!    `PATH`. `aasm integrations plan` exited 3 with "Claude Code is not
//!    installed on this host" — a sentence indistinguishable from a real
//!    product regression.
//!
//! Later, two runtimes from the **same** build were serving simultaneously.
//! Both were correct, and it was still an attribution failure: a client that
//! cannot say *which* process answered cannot attribute its result to one.
//!
//! **Port reachability is never sufficient.** In every case the socket was
//! reachable and the runtime was healthy. It was simply not the build under
//! test — or not the only one.
//!
//! # Three questions, three answers, kept separate
//!
//! | Question | Answered by | Failing verdict |
//! | --- | --- | --- |
//! | Is this the build I expect? | [`verify`] | [`ProvenanceVerdict::Mismatch`] |
//! | Can this runtime still be identified at all? | [`verify`] | [`ProvenanceVerdict::ExecutableMissing`] |
//! | Is it the *only* one answering? | [`multiplicity`] | [`RuntimeMultiplicity::Ambiguous`] |
//!
//! They are deliberately not one check. A build-identity comparison says
//! nothing about duplicates — two runtimes from the same commit match each
//! other perfectly — so a client that only compared identities would resolve
//! silently to one of them, which is the third failure above.
//!
//! # Why the constants are compiled in
//!
//! [`BUILD_SHA`] and [`BUILD_SOURCE_PATH`] come from `aa-runtime/build.rs`.
//! `aa-cli` depends on `aa-runtime`, so client and server read the *same*
//! compiled constants: equal values mean "compiled together", which is exactly
//! the claim a client needs to make. Asking the running process to shell out to
//! `git` instead would report the SHA of whatever directory it was started
//! from, which is a different question with a plausible-looking answer.

use std::path::{Path, PathBuf};

use aa_core::integration::{core_version, now_unix_secs};
use aa_proto::assembly::devint::v1 as wire;

/// The commit `aa-runtime` was compiled from, or [`UNKNOWN_SHA`].
pub const BUILD_SHA: &str = env!("AA_BUILD_SHA");

/// The checkout `aa-runtime` was compiled from; empty when the build
/// suppressed it.
pub const BUILD_SOURCE_PATH: &str = env!("AA_BUILD_SOURCE_PATH");

/// What `build.rs` writes when there was no checkout to read a commit from.
///
/// An honest sentinel rather than a guess: a fabricated SHA would compare equal
/// to nothing and unequal to everything, both silently.
pub const UNKNOWN_SHA: &str = "unknown";

/// How many characters of a SHA a human-facing surface prints.
pub const SHORT_SHA_LEN: usize = 12;

/// The `(deleted)` marker Linux appends to `/proc/<pid>/exe` for an unlinked
/// binary. macOS reports the original path with no marker, which is why
/// presence is checked with [`Path::exists`] rather than by reading this.
const DELETED_SUFFIX: &str = " (deleted)";

/// Abbreviate a SHA for a one-line banner, leaving [`UNKNOWN_SHA`] alone.
pub fn short_sha(sha: &str) -> String {
    if sha == UNKNOWN_SHA || sha.len() <= SHORT_SHA_LEN {
        return sha.to_string();
    }
    sha[..SHORT_SHA_LEN].to_string()
}

/// The identity a build claims: what it is, and what it was compiled from.
///
/// Two fields rather than one because they fail differently. A version
/// difference means someone mixed releases; a SHA difference at the same
/// version means two checkouts — the case a version string cannot see, and the
/// one that cost a whole QA campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentity {
    /// The core version this build reports.
    pub core_version: String,
    /// The commit it was compiled from, or [`UNKNOWN_SHA`].
    pub build_sha: String,
}

impl BuildIdentity {
    /// The identity of the build this code was compiled into.
    pub fn of_this_build() -> Self {
        Self {
            core_version: core_version().to_string(),
            build_sha: BUILD_SHA.to_string(),
        }
    }

    /// Whether two identities were compiled together.
    ///
    /// A SHA of [`UNKNOWN_SHA`] on *both* sides still matches: two binaries
    /// from the same published tarball genuinely are the same build, and
    /// refusing them would break every installed-from-crates.io pairing to
    /// catch nothing. One known and one unknown does *not* match — that is
    /// precisely a release binary talking to a local build.
    pub fn matches(&self, other: &Self) -> bool {
        self.core_version == other.core_version && self.build_sha == other.build_sha
    }

    /// One line naming both fields, for a diagnostic.
    pub fn describe(&self) -> String {
        format!("{} ({})", self.core_version, short_sha(&self.build_sha))
    }
}

/// This runtime's own provenance, captured once when it starts serving.
///
/// `pid`, `executable_path` and `started_at_unix_secs` are captured at start
/// and never recomputed: they are facts about *this* process, and re-reading
/// them per connection would only invite them to disagree with each other.
/// Executable presence is the exception — see [`Self::executable_present`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProvenance {
    /// What this build is.
    pub identity: BuildIdentity,
    /// The serving process.
    pub pid: u32,
    /// Absolute path of the running executable, as the OS reported it at start.
    pub executable_path: PathBuf,
    /// The checkout this binary was compiled from; empty when suppressed.
    pub source_path: String,
    /// When this runtime started serving.
    pub started_at_unix_secs: u64,
}

impl RuntimeProvenance {
    /// Snapshot the running process.
    ///
    /// A binary whose path cannot be resolved at all yields an empty path,
    /// which [`Self::executable_present`] then reports as absent — "I could not
    /// tell you what I am" and "what I am is gone" are the same answer to a
    /// client deciding whether to trust the reply.
    pub fn detect() -> Self {
        let executable_path = std::env::current_exe().map(strip_deleted_marker).unwrap_or_default();
        Self {
            identity: BuildIdentity::of_this_build(),
            pid: std::process::id(),
            executable_path,
            source_path: BUILD_SOURCE_PATH.to_string(),
            started_at_unix_secs: now_unix_secs(),
        }
    }

    /// Whether the executable still exists, **evaluated now**.
    ///
    /// Deliberately not a stored field. The failure being caught is a worktree
    /// deleted *while the runtime keeps serving*, so a value captured at start
    /// would report exactly the wrong thing at exactly the moment it matters.
    pub fn executable_present(&self) -> bool {
        !self.executable_path.as_os_str().is_empty() && self.executable_path.exists()
    }

    /// Render for the `HelloAck`, re-checking executable presence.
    pub fn to_wire(&self) -> wire::RuntimeProvenance {
        wire::RuntimeProvenance {
            core_version: self.identity.core_version.clone(),
            build_sha: self.identity.build_sha.clone(),
            pid: self.pid,
            executable_path: self.executable_path.display().to_string(),
            executable_present: self.executable_present(),
            source_path: self.source_path.clone(),
            started_at_unix_secs: self.started_at_unix_secs,
        }
    }
}

impl Default for RuntimeProvenance {
    fn default() -> Self {
        Self::detect()
    }
}

/// Provenance as a *client* received it.
///
/// A separate type from [`RuntimeProvenance`] on purpose: `executable_present`
/// is an assertion the peer made about itself at the instant it answered, not
/// something the reader may recompute later and treat as the same fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerProvenance {
    /// What the peer says it is.
    pub identity: BuildIdentity,
    /// The process that answered.
    pub pid: u32,
    /// Where the peer says its executable is.
    pub executable_path: String,
    /// Whether the peer found that path when it answered.
    pub executable_present: bool,
    /// The checkout the peer was built from; empty when suppressed.
    pub source_path: String,
    /// When the peer started serving.
    pub started_at_unix_secs: u64,
}

impl PeerProvenance {
    /// Decode what arrived on the wire.
    pub fn from_wire(view: &wire::RuntimeProvenance) -> Self {
        Self {
            identity: BuildIdentity {
                core_version: view.core_version.clone(),
                build_sha: view.build_sha.clone(),
            },
            pid: view.pid,
            executable_path: view.executable_path.clone(),
            executable_present: view.executable_present,
            source_path: view.source_path.clone(),
            started_at_unix_secs: view.started_at_unix_secs,
        }
    }
}

/// What a client concluded about the runtime that answered it.
///
/// Every failing variant carries its own sentence. That is the point: the
/// failure this replaces was a *generic-looking product answer*
/// (`not_installed`) standing in for "you are talking to the wrong build", and
/// a shared "provenance check failed" message would repeat the mistake one
/// level up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceVerdict {
    /// The peer is the expected build and can still be identified.
    Verified {
        /// The process that answered.
        pid: u32,
        /// What answered.
        identity: BuildIdentity,
    },
    /// The peer never sent provenance, because it predates DI-API
    /// [`DI_API_PROVENANCE_SINCE`](super::negotiate::DI_API_PROVENANCE_SINCE).
    /// Not treated as "no identity": an old runtime is one that *cannot* say,
    /// which is still a runtime whose answers are unattributable.
    NotReported {
        /// The version the connection negotiated.
        negotiated_version: u32,
    },
    /// The peer is serving from an executable that no longer exists.
    ExecutableMissing {
        /// The process that answered.
        pid: u32,
        /// The path it named.
        executable_path: String,
    },
    /// The peer is a different build from the one this client belongs to.
    Mismatch {
        /// The process that answered.
        pid: u32,
        /// What this client expected.
        expected: BuildIdentity,
        /// What answered instead.
        reported: BuildIdentity,
        /// The checkout the peer was built from, when it named one.
        source_path: String,
    },
}

impl ProvenanceVerdict {
    /// Whether a result obtained over this connection may be attributed to the
    /// intended build.
    ///
    /// Only [`Self::Verified`] is true. There is no "probably" tier: the whole
    /// defect is that an unverified answer looked like a verified one.
    pub const fn is_trustworthy(&self) -> bool {
        matches!(self, ProvenanceVerdict::Verified { .. })
    }

    /// A stable snake_case name, for JSON output and for a script to branch on.
    pub const fn as_str(&self) -> &'static str {
        match self {
            ProvenanceVerdict::Verified { .. } => "verified",
            ProvenanceVerdict::NotReported { .. } => "not_reported",
            ProvenanceVerdict::ExecutableMissing { .. } => "executable_missing",
            ProvenanceVerdict::Mismatch { .. } => "mismatch",
        }
    }

    /// The pid that answered, when the peer named one.
    pub const fn pid(&self) -> Option<u32> {
        match self {
            ProvenanceVerdict::Verified { pid, .. }
            | ProvenanceVerdict::ExecutableMissing { pid, .. }
            | ProvenanceVerdict::Mismatch { pid, .. } => Some(*pid),
            ProvenanceVerdict::NotReported { .. } => None,
        }
    }

    /// What happened, naming the specific facts that disagreed.
    pub fn detail(&self) -> String {
        match self {
            ProvenanceVerdict::Verified { pid, identity } => {
                format!(
                    "the Agent Assembly runtime answering is {} (pid {pid})",
                    identity.describe()
                )
            }
            ProvenanceVerdict::NotReported { negotiated_version } => format!(
                "the Agent Assembly runtime answering speaks DI-API v{negotiated_version} and cannot state which \
                 build it is, so this result cannot be attributed to a build"
            ),
            ProvenanceVerdict::ExecutableMissing { pid, executable_path } => format!(
                "the Agent Assembly runtime answering (pid {pid}) is serving from {executable_path}, which no longer \
                 exists — it cannot be identified, and its answers about this host cannot be trusted"
            ),
            ProvenanceVerdict::Mismatch {
                pid,
                expected,
                reported,
                source_path,
            } => {
                let built_from = if source_path.is_empty() {
                    String::new()
                } else {
                    format!(", built from {source_path}")
                };
                format!(
                    "the Agent Assembly runtime answering (pid {pid}) is {}{built_from}, not the {} this aasm was \
                     built with — every answer it gives describes that build, not this one",
                    reported.describe(),
                    expected.describe()
                )
            }
        }
    }

    /// What to do about it. Never "try again": every failing verdict here is
    /// about a *wrong* process, and retrying reaches the same one.
    pub fn remediation(&self) -> String {
        match self {
            ProvenanceVerdict::Verified { .. } => String::new(),
            ProvenanceVerdict::NotReported { .. } => {
                "stop that runtime and start the one built alongside this aasm — they ship as one unit".to_string()
            }
            ProvenanceVerdict::ExecutableMissing { pid, .. } => {
                format!("stop it (`kill {pid}`) and re-run; aasm will start a runtime from this build")
            }
            ProvenanceVerdict::Mismatch { pid, .. } => format!(
                "stop it (`kill {pid}`) and re-run, or run the aasm built alongside it — do not record a result from \
                 this connection"
            ),
        }
    }
}

/// Decide whether the runtime that answered is the intended build.
///
/// `reported` is `None` when the `HelloAck` carried no provenance message at
/// all, which is how a pre-v4 peer answers.
///
/// The order is: *can I identify it → is it the right one*. A runtime whose
/// executable is gone is reported as unidentifiable even when its SHA matches,
/// because nothing it claims can be re-derived or re-inspected afterwards, and
/// that fact is worth naming on its own.
pub fn verify(
    reported: Option<&PeerProvenance>,
    expected: &BuildIdentity,
    negotiated_version: u32,
) -> ProvenanceVerdict {
    let Some(peer) = reported else {
        return ProvenanceVerdict::NotReported { negotiated_version };
    };

    if !peer.executable_present {
        return ProvenanceVerdict::ExecutableMissing {
            pid: peer.pid,
            executable_path: if peer.executable_path.is_empty() {
                "(an unresolvable path)".to_string()
            } else {
                peer.executable_path.clone()
            },
        };
    }

    if !peer.identity.matches(expected) {
        return ProvenanceVerdict::Mismatch {
            pid: peer.pid,
            expected: expected.clone(),
            reported: peer.identity.clone(),
            source_path: peer.source_path.clone(),
        };
    }

    ProvenanceVerdict::Verified {
        pid: peer.pid,
        identity: peer.identity.clone(),
    }
}

/// How many runtimes are reachable, and which one answered.
///
/// Kept apart from [`ProvenanceVerdict`] because it is a different question
/// with a different answer. Two runtimes compiled from the same commit have
/// *identical* identities, so no amount of identity comparison can notice that
/// there are two of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeMultiplicity {
    /// Exactly one runtime is listening: the one that answered.
    Single {
        /// Where it is listening.
        answered: PathBuf,
    },
    /// More than one runtime is listening.
    ///
    /// Reported, never silently resolved — including when every one of them is
    /// the same build. A result that cannot be attributed to a process is not
    /// attributable at all, and the pid is required provenance.
    Ambiguous {
        /// The socket this client is actually talking to.
        answered: PathBuf,
        /// Every reachable socket, including `answered`.
        all: Vec<PathBuf>,
    },
}

impl RuntimeMultiplicity {
    /// Whether exactly one runtime is reachable.
    pub const fn is_unambiguous(&self) -> bool {
        matches!(self, RuntimeMultiplicity::Single { .. })
    }

    /// How many runtimes are reachable.
    pub fn reachable_count(&self) -> usize {
        match self {
            RuntimeMultiplicity::Single { .. } => 1,
            RuntimeMultiplicity::Ambiguous { all, .. } => all.len(),
        }
    }

    /// What happened, naming every reachable runtime and the one that answered.
    pub fn detail(&self) -> String {
        match self {
            RuntimeMultiplicity::Single { answered } => {
                format!("one Agent Assembly runtime is reachable, at {}", answered.display())
            }
            RuntimeMultiplicity::Ambiguous { answered, all } => {
                let others: Vec<String> = all
                    .iter()
                    .filter(|p| *p != answered)
                    .map(|p| p.display().to_string())
                    .collect();
                format!(
                    "{} Agent Assembly runtimes are reachable; this command reached {} and the others ({}) were not \
                     consulted — a result from one of several runtimes cannot be attributed to a build",
                    all.len(),
                    answered.display(),
                    others.join(", ")
                )
            }
        }
    }

    /// What to do about it.
    pub fn remediation(&self) -> String {
        match self {
            RuntimeMultiplicity::Single { .. } => String::new(),
            RuntimeMultiplicity::Ambiguous { .. } => {
                "stop every Agent Assembly runtime but the one under test, then re-run — \
                 `aasm integrations status --output json` names the pid that answered"
                    .to_string()
            }
        }
    }
}

/// Classify how many runtimes answered.
///
/// `reachable` is what [`super::socket::reachable_runtimes`] found; `answered`
/// is the socket this client connected to. `answered` is folded in even when
/// the scan missed it (an `AA_DEVINT_SOCKET` override outside the scanned
/// directory), so the count is never lower than what is demonstrably true.
pub fn multiplicity(answered: &Path, reachable: &[PathBuf]) -> RuntimeMultiplicity {
    let mut all: Vec<PathBuf> = reachable.to_vec();
    if !all.iter().any(|p| p == answered) {
        all.push(answered.to_path_buf());
    }
    all.sort();
    all.dedup();

    if all.len() <= 1 {
        RuntimeMultiplicity::Single {
            answered: answered.to_path_buf(),
        }
    } else {
        RuntimeMultiplicity::Ambiguous {
            answered: answered.to_path_buf(),
            all,
        }
    }
}

/// Drop Linux's `" (deleted)"` marker from an unlinked `/proc/self/exe` target.
///
/// Without this the path would never compare equal to anything on disk *and*
/// would read as a filename in a message. macOS resolves the original path with
/// no marker, so presence is decided by [`Path::exists`] on both platforms and
/// this only tidies the string.
fn strip_deleted_marker(path: PathBuf) -> PathBuf {
    let rendered = path.to_string_lossy();
    match rendered.strip_suffix(DELETED_SUFFIX) {
        Some(trimmed) => PathBuf::from(trimmed),
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(version: &str, sha: &str) -> BuildIdentity {
        BuildIdentity {
            core_version: version.to_string(),
            build_sha: sha.to_string(),
        }
    }

    fn peer(identity: BuildIdentity, present: bool) -> PeerProvenance {
        PeerProvenance {
            identity,
            pid: 4242,
            executable_path: "/build-a/target/debug/aa-runtime".to_string(),
            executable_present: present,
            source_path: "/build-a".to_string(),
            started_at_unix_secs: 1_700_000_000,
        }
    }

    #[test]
    fn this_build_states_a_version_and_a_sha() {
        let me = BuildIdentity::of_this_build();
        assert!(!me.core_version.is_empty());
        assert!(!me.build_sha.is_empty(), "build.rs must always emit something");
        assert!(me.matches(&BuildIdentity::of_this_build()));
    }

    #[test]
    fn the_same_version_from_two_checkouts_does_not_match() {
        // The whole defect in one assertion: version equality is not build
        // equality, and the version is all the old handshake carried.
        let a = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let b = identity("0.0.1-rc.6", "bbbbbbbbbbbb");
        assert_eq!(a.core_version, b.core_version);
        assert!(!a.matches(&b));
    }

    #[test]
    fn two_builds_with_no_checkout_still_match_each_other() {
        // Two binaries from the same published tarball genuinely are one build.
        let a = identity("0.0.1-rc.6", UNKNOWN_SHA);
        assert!(a.matches(&identity("0.0.1-rc.6", UNKNOWN_SHA)));
        // …but a release binary talking to a local build is a mismatch.
        assert!(!a.matches(&identity("0.0.1-rc.6", "cccccccccccc")));
    }

    #[test]
    fn a_matching_build_with_a_live_executable_is_verified() {
        let expected = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let verdict = verify(Some(&peer(expected.clone(), true)), &expected, 4);
        assert!(verdict.is_trustworthy());
        assert_eq!(verdict.as_str(), "verified");
        assert_eq!(verdict.pid(), Some(4242));
        assert!(verdict.remediation().is_empty());
    }

    #[test]
    fn a_different_build_is_a_mismatch_naming_both_sides() {
        let expected = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let verdict = verify(Some(&peer(identity("0.0.1-rc.6", "bbbbbbbbbbbb"), true)), &expected, 4);
        assert!(!verdict.is_trustworthy());
        assert_eq!(verdict.as_str(), "mismatch");
        let detail = verdict.detail();
        assert!(detail.contains("aaaaaaaaaaaa"), "{detail}");
        assert!(detail.contains("bbbbbbbbbbbb"), "{detail}");
        assert!(
            detail.contains("/build-a"),
            "the peer's checkout is worth naming: {detail}"
        );
        assert!(verdict.remediation().contains("4242"), "{}", verdict.remediation());
    }

    #[test]
    fn a_deleted_executable_is_unidentifiable_even_when_the_build_matches() {
        // The second reproduction: same build, worktree gone, still serving.
        let expected = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let verdict = verify(Some(&peer(expected.clone(), false)), &expected, 4);
        assert!(!verdict.is_trustworthy());
        assert_eq!(verdict.as_str(), "executable_missing");
        assert!(verdict.detail().contains("no longer exists"), "{}", verdict.detail());
    }

    #[test]
    fn a_peer_that_sent_no_provenance_is_not_read_as_having_none() {
        let verdict = verify(None, &identity("0.0.1-rc.6", "aaaaaaaaaaaa"), 3);
        assert!(!verdict.is_trustworthy());
        assert_eq!(verdict.as_str(), "not_reported");
        assert!(verdict.detail().contains("v3"), "{}", verdict.detail());
        assert_eq!(verdict.pid(), None);
    }

    /// Every failing verdict must say something a reader can act on, and no two
    /// may say the same thing — a shared message would rebuild the generic
    /// failure this ticket exists to remove.
    #[test]
    fn every_failing_verdict_has_its_own_actionable_sentence() {
        let expected = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let verdicts = [
            verify(None, &expected, 3),
            verify(Some(&peer(expected.clone(), false)), &expected, 4),
            verify(Some(&peer(identity("0.0.1-rc.6", "bbbbbbbbbbbb"), true)), &expected, 4),
        ];
        let mut seen: Vec<String> = Vec::new();
        for verdict in &verdicts {
            assert!(!verdict.is_trustworthy());
            assert!(!verdict.detail().is_empty());
            assert!(!verdict.remediation().is_empty(), "{}", verdict.as_str());
            assert!(
                !seen.contains(&verdict.detail()),
                "duplicate detail: {}",
                verdict.detail()
            );
            seen.push(verdict.detail());
        }
        // …and none of them reads like a product answer about the tool.
        for verdict in &verdicts {
            assert!(
                !verdict.detail().contains("not installed"),
                "a provenance failure must never look like a tool-detection answer"
            );
        }
    }

    #[test]
    fn one_reachable_runtime_is_unambiguous() {
        let path = PathBuf::from("/run/devint.sock");
        let verdict = multiplicity(&path, std::slice::from_ref(&path));
        assert!(verdict.is_unambiguous());
        assert_eq!(verdict.reachable_count(), 1);
        assert!(verdict.remediation().is_empty());
    }

    #[test]
    fn two_reachable_runtimes_are_ambiguous_even_when_identical() {
        // No identity is consulted here at all — that is the point. Two
        // runtimes from one commit are indistinguishable by build, and still
        // must not be silently resolved to one.
        let answered = PathBuf::from("/run/devint.sock");
        let other = PathBuf::from("/run/devint-2.sock");
        let verdict = multiplicity(&answered, &[answered.clone(), other.clone()]);
        assert!(!verdict.is_unambiguous());
        assert_eq!(verdict.reachable_count(), 2);
        let detail = verdict.detail();
        assert!(detail.contains("2 Agent Assembly runtimes"), "{detail}");
        assert!(
            detail.contains("devint-2.sock"),
            "the other runtime must be named: {detail}"
        );
        assert!(!verdict.remediation().is_empty());
    }

    #[test]
    fn the_answered_socket_counts_even_when_the_scan_missed_it() {
        // An `AA_DEVINT_SOCKET` override can sit outside the scanned directory.
        // Undercounting there would report "one runtime" while two answer.
        let answered = PathBuf::from("/elsewhere/devint.sock");
        let scanned = PathBuf::from("/run/devint.sock");
        let verdict = multiplicity(&answered, &[scanned]);
        assert_eq!(verdict.reachable_count(), 2);
        assert!(!verdict.is_unambiguous());
    }

    #[test]
    fn this_process_reports_a_live_executable_and_its_own_pid() {
        let provenance = RuntimeProvenance::detect();
        assert_eq!(provenance.pid, std::process::id());
        assert!(provenance.executable_present(), "the test binary exists");
        assert!(provenance.started_at_unix_secs > 0);

        let view = provenance.to_wire();
        assert_eq!(view.pid, std::process::id());
        assert!(view.executable_present);
        assert_eq!(view.build_sha, BUILD_SHA);
        assert!(!view.executable_path.is_empty());
    }

    #[test]
    fn a_vanished_executable_is_reported_absent_at_answer_time_not_start_time() {
        // Captured while the file existed, deleted afterwards — the exact
        // sequence a deleted worktree produces.
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = dir.path().join("aa-runtime");
        std::fs::write(&exe, b"#!/bin/true\n").expect("write");

        let mut provenance = RuntimeProvenance::detect();
        provenance.executable_path = exe.clone();
        assert!(provenance.executable_present());
        assert!(provenance.to_wire().executable_present);

        std::fs::remove_file(&exe).expect("remove");
        assert!(!provenance.executable_present());
        assert!(
            !provenance.to_wire().executable_present,
            "presence must be re-read when the frame is written"
        );
    }

    #[test]
    fn an_unresolvable_executable_path_is_absent_rather_than_present() {
        let provenance = RuntimeProvenance {
            executable_path: PathBuf::new(),
            ..RuntimeProvenance::detect()
        };
        assert!(!provenance.executable_present());
        let verdict = verify(
            Some(&PeerProvenance::from_wire(&provenance.to_wire())),
            &BuildIdentity::of_this_build(),
            4,
        );
        assert_eq!(verdict.as_str(), "executable_missing");
        assert!(verdict.detail().contains("unresolvable"), "{}", verdict.detail());
    }

    #[test]
    fn the_linux_deleted_marker_is_not_carried_into_the_path() {
        let marked = PathBuf::from("/gone/target/debug/aa-runtime (deleted)");
        assert_eq!(
            strip_deleted_marker(marked),
            PathBuf::from("/gone/target/debug/aa-runtime")
        );
        let plain = PathBuf::from("/here/aa-runtime");
        assert_eq!(strip_deleted_marker(plain.clone()), plain);
    }

    #[test]
    fn a_short_sha_stays_readable_and_leaves_the_unknown_sentinel_alone() {
        assert_eq!(short_sha("0123456789abcdef0123"), "0123456789ab");
        assert_eq!(short_sha(UNKNOWN_SHA), UNKNOWN_SHA);
        assert_eq!(short_sha("abc"), "abc");
    }

    #[test]
    fn a_wire_round_trip_preserves_every_provenance_field() {
        let provenance = RuntimeProvenance::detect();
        let decoded = PeerProvenance::from_wire(&provenance.to_wire());
        assert_eq!(decoded.identity, provenance.identity);
        assert_eq!(decoded.pid, provenance.pid);
        assert_eq!(
            decoded.executable_path,
            provenance.executable_path.display().to_string()
        );
        assert_eq!(decoded.source_path, provenance.source_path);
        assert_eq!(decoded.started_at_unix_secs, provenance.started_at_unix_secs);
    }
}
