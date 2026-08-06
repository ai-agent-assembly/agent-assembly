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
//! # Absence is not agreement — the comparison is three-state
//!
//! Two builds that both answer "I don't know what I am" have established
//! nothing about each other. An earlier revision of this module treated
//! `unknown == unknown` as a match, on the reasoning that two binaries from one
//! published tarball genuinely are one build. That reasoning is invalid: it
//! concludes *identity* from *shared ignorance*, and it holds equally for two
//! binaries from two unrelated tarballs. That accepted risk is **rejected**;
//! see ADR 0030 §5.4a.
//!
//! So [`BuildIdentity::compare`] returns three states, not a bool:
//!
//! | Case | Result |
//! | --- | --- |
//! | two equal authoritative identities | [`IdentityComparison::Match`] |
//! | two different authoritative identities | [`IdentityComparison::Mismatch`] |
//! | either identity is not authoritative | [`IdentityComparison::Unverifiable`] |
//!
//! **`pid`, executable name, executable path, DI-API version and package
//! version are not proof of identical build content**, individually or
//! together, and none of them may raise a comparison to `Match`. `core_version`
//! is carried and compared because it can *falsify* — two different versions
//! cannot be one build — but a version string cannot verify: two checkouts sat
//! at the same version in the failure this module exists to prevent.
//!
//! # Why the constants are compiled in
//!
//! [`BUILD_SHA`], [`BUILD_SOURCE_PATH`] and [`BUILD_IDENTITY_SOURCE`] come from
//! `aa-runtime/build.rs`. `aa-cli` depends on `aa-runtime`, so client and server
//! read the *same* compiled constants: equal values mean "compiled together",
//! which is exactly the claim a client needs to make. Asking the running process
//! to shell out to `git` instead would report the SHA of whatever directory it
//! was started from, which is a different question with a plausible-looking
//! answer.
//!
//! # Packaged installations
//!
//! An official release artifact is built by `release.yml` from an
//! `actions/checkout` working tree, in a single `cargo build --release -p
//! aa-cli -p aa-runtime …`, so both binaries carry the *same* `checkout`
//! identity and pair as `Match` with no release-process change. A
//! `cargo package` tarball carries `.cargo_vcs_info.json`, which `build.rs`
//! reads as the `packaged` source — a real artifact-level identity shared by
//! every crate published from one commit, rather than a version-string proxy.

use std::path::{Path, PathBuf};

use aa_core::integration::{core_version, now_unix_secs};
use aa_proto::assembly::devint::v1 as wire;

/// The commit `aa-runtime` was compiled from, or [`UNKNOWN_SHA`].
pub const BUILD_SHA: &str = env!("AA_BUILD_SHA");

/// The checkout `aa-runtime` was compiled from; empty when the build
/// suppressed it.
pub const BUILD_SOURCE_PATH: &str = env!("AA_BUILD_SOURCE_PATH");

/// How [`BUILD_SHA`] was obtained — see [`IdentitySource`].
pub const BUILD_IDENTITY_SOURCE: &str = env!("AA_BUILD_IDENTITY_SOURCE");

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

/// How a [`BuildIdentity`]'s `build_sha` was obtained.
///
/// Recorded rather than inferred from the shape of the SHA string, because the
/// question a three-state comparison asks is not "does this look like a commit"
/// but "did anything authoritative produce it". Only the first three variants
/// can raise a comparison to [`IdentityComparison::Match`].
///
/// This is an honesty signal for first-party builds, **not** an authentication
/// control: a hostile peer can claim any source it likes, exactly as it can
/// claim any `build_sha`. It buys truthfulness about our own builds, and
/// nothing downstream treats it as more than that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// `AA_BUILD_SHA` was set in the build environment.
    Injected,
    /// `git rev-parse HEAD` answered in the workspace root.
    Checkout,
    /// `.cargo_vcs_info.json` in a `cargo package` tarball named the commit.
    Packaged,
    /// Nothing could be resolved; the SHA is [`UNKNOWN_SHA`].
    ///
    /// Also what a peer built before the source field existed decodes to, since
    /// it sends an empty string. Both are the same fact: this identity proves
    /// nothing.
    Absent,
}

impl IdentitySource {
    /// Decode the wire token, treating anything unrecognised as [`Self::Absent`].
    ///
    /// Unrecognised resolves to `Absent` rather than to a permissive default: an
    /// identity whose provenance this build cannot interpret has not been shown
    /// to be authoritative, and an unknown must never be resolved in the
    /// direction that produces a match.
    pub fn from_wire(token: &str) -> Self {
        match token {
            "injected" => Self::Injected,
            "checkout" => Self::Checkout,
            "packaged" => Self::Packaged,
            _ => Self::Absent,
        }
    }

    /// The stable token used on the wire and in JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Injected => "injected",
            Self::Checkout => "checkout",
            Self::Packaged => "packaged",
            Self::Absent => "absent",
        }
    }

    /// Whether an identity from this source may prove a match.
    pub const fn is_authoritative(self) -> bool {
        !matches!(self, Self::Absent)
    }
}

/// The identity a build claims: what it is, what it was compiled from, and how
/// it came to know that.
///
/// Three fields rather than one because they carry different force. A version
/// difference means someone mixed releases — it can *falsify*. A SHA difference
/// at the same version means two checkouts, the case a version string cannot
/// see and the one that cost a whole QA campaign. And `sha_source` is what
/// decides whether the SHA can prove anything at all: a SHA nothing
/// authoritative produced is a placeholder, not an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentity {
    /// The core version this build reports.
    pub core_version: String,
    /// The commit it was compiled from, or [`UNKNOWN_SHA`].
    pub build_sha: String,
    /// Where `build_sha` came from.
    pub sha_source: IdentitySource,
}

impl BuildIdentity {
    /// The identity of the build this code was compiled into.
    pub fn of_this_build() -> Self {
        Self {
            core_version: core_version().to_string(),
            build_sha: BUILD_SHA.to_string(),
            sha_source: IdentitySource::from_wire(BUILD_IDENTITY_SOURCE),
        }
    }

    /// Whether this identity can prove a match, rather than merely fail to
    /// contradict one.
    ///
    /// A SHA is authoritative only when an authoritative mechanism produced it
    /// *and* it is not the [`UNKNOWN_SHA`] sentinel. Both are checked: a build
    /// that named a source but no SHA, or a SHA with no source, has not
    /// established an identity, and reading either as one is how absence turns
    /// back into agreement.
    pub fn is_authoritative(&self) -> bool {
        self.sha_source.is_authoritative() && !self.build_sha.is_empty() && self.build_sha != UNKNOWN_SHA
    }

    /// Compare two identities, in three states.
    ///
    /// The order encodes what each field can do:
    ///
    /// 1. **`core_version` can falsify.** Two known, different versions cannot
    ///    be one build, whatever the SHAs say — including when the SHAs agree,
    ///    which is a contradiction and must not read as a match.
    /// 2. **A non-authoritative SHA on either side ends it.** Neither peer has
    ///    established what it is, so the relationship is *unverifiable*. Never
    ///    a match: `unknown` vs `unknown` proves only shared ignorance.
    /// 3. **Two authoritative SHAs decide.** Equal is the only `Match` this
    ///    function can return, and it names `build_sha` as what proved it.
    ///
    /// Nothing else is consulted. `pid`, executable name, executable path,
    /// DI-API version and package version are not proof of identical build
    /// content — individually or in combination — so none of them appears here.
    pub fn compare(&self, other: &Self) -> IdentityComparison {
        let mut fields = vec![compare_field(
            "core_version",
            &self.core_version,
            &other.core_version,
            true,
        )];
        let sha_authoritative = self.is_authoritative() && other.is_authoritative();
        fields.push(compare_field(
            "build_sha",
            &self.build_sha,
            &other.build_sha,
            sha_authoritative,
        ));
        fields.push(compare_field(
            "build_id_source",
            self.sha_source.as_str(),
            other.sha_source.as_str(),
            self.sha_source.is_authoritative() && other.sha_source.is_authoritative(),
        ));

        // 1. A version disagreement falsifies outright.
        if !self.core_version.is_empty() && !other.core_version.is_empty() && self.core_version != other.core_version {
            return IdentityComparison::Mismatch { fields };
        }

        // 2. Without two authoritative SHAs there is nothing left that can prove
        //    or disprove sameness.
        if !sha_authoritative {
            return IdentityComparison::Unverifiable { fields };
        }

        // 3. Two authoritative SHAs settle it either way.
        if self.build_sha == other.build_sha {
            IdentityComparison::Match {
                proved_by: "build_sha",
                fields,
            }
        } else {
            IdentityComparison::Mismatch { fields }
        }
    }

    /// One line naming the version, the commit and where the commit came from.
    pub fn describe(&self) -> String {
        format!(
            "{} ({} via {})",
            self.core_version,
            short_sha(&self.build_sha),
            self.sha_source.as_str()
        )
    }
}

/// What one provenance field did in a comparison.
///
/// Kept per-field so a diagnostic can name *which* fact was absent, matched or
/// disagreed, instead of collapsing to "provenance check failed" — the generic
/// message this whole module exists to avoid one level up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldStatus {
    /// Both sides stated it, authoritatively, and they agree.
    Matched,
    /// Both sides stated it and they disagree.
    Mismatched,
    /// One or both sides could not state it authoritatively.
    Absent,
}

impl FieldStatus {
    /// The stable token used in JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Mismatched => "mismatched",
            Self::Absent => "absent",
        }
    }
}

/// One field's contribution to a comparison, with both sides' values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldReport {
    /// The provenance field, named as it appears on the wire.
    pub field: &'static str,
    /// What it did.
    pub status: FieldStatus,
    /// What this client expected.
    pub expected: String,
    /// What the peer reported.
    pub reported: String,
}

/// Compare one field, given whether both sides stated it authoritatively.
fn compare_field(field: &'static str, expected: &str, reported: &str, authoritative: bool) -> FieldReport {
    let status = if !authoritative || expected.is_empty() || reported.is_empty() {
        FieldStatus::Absent
    } else if expected == reported {
        FieldStatus::Matched
    } else {
        FieldStatus::Mismatched
    };
    FieldReport {
        field,
        status,
        expected: expected.to_string(),
        reported: reported.to_string(),
    }
}

/// The three states two build identities can stand in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityComparison {
    /// Two authoritative identities agree.
    Match {
        /// The field that proved it. Never `core_version`, which can falsify
        /// but not verify.
        proved_by: &'static str,
        /// What every field did.
        fields: Vec<FieldReport>,
    },
    /// Two identities positively disagree.
    Mismatch {
        /// What every field did.
        fields: Vec<FieldReport>,
    },
    /// Nothing authoritative was available on one or both sides.
    ///
    /// **Never a match.** Absence of provenance on both peers proves only that
    /// both are unknown, not that they are the same build.
    Unverifiable {
        /// What every field did.
        fields: Vec<FieldReport>,
    },
}

impl IdentityComparison {
    /// Every field's contribution, whatever the outcome.
    pub fn fields(&self) -> &[FieldReport] {
        match self {
            Self::Match { fields, .. } | Self::Mismatch { fields } | Self::Unverifiable { fields } => fields,
        }
    }

    /// The fields with a given status, named — for a diagnostic sentence.
    pub fn named(&self, status: FieldStatus) -> Vec<&'static str> {
        self.fields()
            .iter()
            .filter(|f| f.status == status)
            .map(|f| f.field)
            .collect()
    }

    /// One clause naming which fields were absent, matched and mismatched.
    pub fn describe_fields(&self) -> String {
        let mut parts = Vec::new();
        for status in [FieldStatus::Mismatched, FieldStatus::Matched, FieldStatus::Absent] {
            let named = self.named(status);
            if !named.is_empty() {
                parts.push(format!("{} {}", status.as_str(), named.join(", ")));
            }
        }
        parts.join("; ")
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
            build_id_source: self.identity.sha_source.as_str().to_string(),
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
                sha_source: IdentitySource::from_wire(&view.build_id_source),
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
        /// The authoritative field that proved it.
        proved_by: &'static str,
    },
    /// The peer could be neither confirmed nor refuted as this build.
    ///
    /// The state that did not exist before AAASM-5628's rework, and whose
    /// absence was the defect: `unknown` on both sides was read as agreement.
    /// It is not. This verdict is **never** rendered as verified or matching, on
    /// any surface or in JSON.
    Unverifiable {
        /// The process that answered.
        pid: u32,
        /// What this client is.
        expected: BuildIdentity,
        /// What answered.
        reported: BuildIdentity,
        /// Which fields were absent, matched or mismatched.
        comparison: IdentityComparison,
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
        /// Which fields were absent, matched or mismatched.
        comparison: IdentityComparison,
    },
}

/// The three states a client can be in about the runtime that answered.
///
/// The operational vocabulary: what a *caller* branches on, as distinct from
/// [`ProvenanceVerdict`], which says which specific fact produced it. Two
/// different verdicts can share a standing and still deserve different
/// sentences, which is why both exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceStanding {
    /// The peer was positively established as this build.
    Verified,
    /// The peer was neither established nor refuted. Read-only surfaces may
    /// proceed while reporting it; privileged writes, mutating operations,
    /// enforcement claims and manual enforcement evidence must refuse.
    Unverifiable,
    /// The peer was positively established as *not* usable as this build — a
    /// different build, or one that can no longer be identified at all. Every
    /// surface refuses.
    Refuted,
}

impl ProvenanceStanding {
    /// The stable token used in JSON and in messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverifiable => "unverifiable",
            Self::Refuted => "refuted",
        }
    }
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

    /// Which of the three operational states this verdict is.
    ///
    /// `NotReported` and `Unverifiable` are both *absences* — a peer too old to
    /// say, and a peer with nothing authoritative to say. `ExecutableMissing`
    /// and `Mismatch` are both *positive findings* about the peer, so they are
    /// refuted rather than merely unverified, and every surface refuses them.
    pub const fn standing(&self) -> ProvenanceStanding {
        match self {
            ProvenanceVerdict::Verified { .. } => ProvenanceStanding::Verified,
            ProvenanceVerdict::NotReported { .. } | ProvenanceVerdict::Unverifiable { .. } => {
                ProvenanceStanding::Unverifiable
            }
            ProvenanceVerdict::ExecutableMissing { .. } | ProvenanceVerdict::Mismatch { .. } => {
                ProvenanceStanding::Refuted
            }
        }
    }

    /// A stable snake_case name, for JSON output and for a script to branch on.
    pub const fn as_str(&self) -> &'static str {
        match self {
            ProvenanceVerdict::Verified { .. } => "verified",
            ProvenanceVerdict::Unverifiable { .. } => "unverifiable",
            ProvenanceVerdict::NotReported { .. } => "not_reported",
            ProvenanceVerdict::ExecutableMissing { .. } => "executable_missing",
            ProvenanceVerdict::Mismatch { .. } => "mismatch",
        }
    }

    /// The pid that answered, when the peer named one.
    pub const fn pid(&self) -> Option<u32> {
        match self {
            ProvenanceVerdict::Verified { pid, .. }
            | ProvenanceVerdict::Unverifiable { pid, .. }
            | ProvenanceVerdict::ExecutableMissing { pid, .. }
            | ProvenanceVerdict::Mismatch { pid, .. } => Some(*pid),
            ProvenanceVerdict::NotReported { .. } => None,
        }
    }

    /// Which fields were absent, matched or mismatched, when a comparison ran.
    ///
    /// `None` for the verdicts reached before any comparison was possible: a
    /// peer that sent no provenance, and one whose executable is gone.
    pub const fn comparison(&self) -> Option<&IdentityComparison> {
        match self {
            ProvenanceVerdict::Unverifiable { comparison, .. } | ProvenanceVerdict::Mismatch { comparison, .. } => {
                Some(comparison)
            }
            ProvenanceVerdict::Verified { .. }
            | ProvenanceVerdict::NotReported { .. }
            | ProvenanceVerdict::ExecutableMissing { .. } => None,
        }
    }

    /// What happened, naming the specific facts that disagreed.
    pub fn detail(&self) -> String {
        match self {
            ProvenanceVerdict::Verified {
                pid,
                identity,
                proved_by,
            } => {
                format!(
                    "the Agent Assembly runtime answering is {} (pid {pid}), proved by {proved_by}",
                    identity.describe()
                )
            }
            ProvenanceVerdict::Unverifiable {
                pid,
                expected,
                reported,
                comparison,
            } => format!(
                "the Agent Assembly runtime answering (pid {pid}) reports {} and this aasm is {}, and neither states a \
                 build identity anything authoritative produced — provenance fields: {}. Two builds that cannot say \
                 what they are have not been shown to be the same build, so this result is unverifiable rather than \
                 verified",
                reported.describe(),
                expected.describe(),
                comparison.describe_fields()
            ),
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
                comparison,
            } => {
                let built_from = if source_path.is_empty() {
                    String::new()
                } else {
                    format!(", built from {source_path}")
                };
                format!(
                    "the Agent Assembly runtime answering (pid {pid}) is {}{built_from}, not the {} this aasm was \
                     built with — every answer it gives describes that build, not this one; provenance fields: {}",
                    reported.describe(),
                    expected.describe(),
                    comparison.describe_fields()
                )
            }
        }
    }

    /// What to do about it. Never "try again": every failing verdict here is
    /// about a *wrong* process, and retrying reaches the same one.
    pub fn remediation(&self) -> String {
        match self {
            ProvenanceVerdict::Verified { .. } => String::new(),
            ProvenanceVerdict::Unverifiable { pid, .. } => format!(
                "read-only commands still work and will report this as unverifiable; to make it verifiable, stop it \
                 (`kill {pid}`) and re-run so aasm starts the runtime shipped beside it, or install both from the \
                 same official release artifact — a build that carries no commit identity cannot be paired with one \
                 that does"
            ),
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
/// The order is: *can I identify it → what does the comparison say*. A runtime
/// whose executable is gone is reported as unidentifiable even when its SHA
/// matches, because nothing it claims can be re-derived or re-inspected
/// afterwards, and that fact is worth naming on its own.
///
/// The comparison is [`BuildIdentity::compare`], which is three-state. Its
/// `Unverifiable` arm is a first-class outcome here, not a fall-through into
/// `Verified`: absence of provenance on both peers proves only that both are
/// unknown.
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

    match expected.compare(&peer.identity) {
        IdentityComparison::Match { proved_by, .. } => ProvenanceVerdict::Verified {
            pid: peer.pid,
            identity: peer.identity.clone(),
            proved_by,
        },
        comparison @ IdentityComparison::Mismatch { .. } => ProvenanceVerdict::Mismatch {
            pid: peer.pid,
            expected: expected.clone(),
            reported: peer.identity.clone(),
            source_path: peer.source_path.clone(),
            comparison,
        },
        comparison @ IdentityComparison::Unverifiable { .. } => ProvenanceVerdict::Unverifiable {
            pid: peer.pid,
            expected: expected.clone(),
            reported: peer.identity.clone(),
            comparison,
        },
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

    /// An identity from an authoritative source — a real checkout.
    fn identity(version: &str, sha: &str) -> BuildIdentity {
        BuildIdentity {
            core_version: version.to_string(),
            build_sha: sha.to_string(),
            sha_source: IdentitySource::Checkout,
        }
    }

    /// An identity from a build that could not resolve a commit at all.
    fn unknown_identity(version: &str) -> BuildIdentity {
        BuildIdentity {
            core_version: version.to_string(),
            build_sha: UNKNOWN_SHA.to_string(),
            sha_source: IdentitySource::Absent,
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
    fn this_build_states_a_version_a_sha_and_where_the_sha_came_from() {
        let me = BuildIdentity::of_this_build();
        assert!(!me.core_version.is_empty());
        assert!(!me.build_sha.is_empty(), "build.rs must always emit something");
        // Whatever the source is, `of_this_build` must agree with itself. A
        // build with no identity is `Unverifiable` even against a copy of
        // itself — that is the point of the three-state rule.
        let expected = if me.is_authoritative() {
            IdentityComparison::Match {
                proved_by: "build_sha",
                fields: Vec::new(),
            }
        } else {
            IdentityComparison::Unverifiable { fields: Vec::new() }
        };
        assert_eq!(
            std::mem::discriminant(&me.compare(&BuildIdentity::of_this_build())),
            std::mem::discriminant(&expected)
        );
    }

    /// TEST 1 of the owner's list — the same known SHA is a Match.
    #[test]
    fn the_same_known_sha_is_a_match_proved_by_the_sha() {
        let a = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let comparison = a.compare(&identity("0.0.1-rc.6", "aaaaaaaaaaaa"));
        let IdentityComparison::Match { proved_by, .. } = &comparison else {
            panic!("expected a match, got {comparison:?}");
        };
        assert_eq!(
            *proved_by, "build_sha",
            "a version string must never be what proved a match"
        );
        assert_eq!(
            comparison.named(FieldStatus::Matched),
            vec!["core_version", "build_sha", "build_id_source"]
        );
        assert!(comparison.named(FieldStatus::Absent).is_empty());
    }

    /// TEST 2 — two different known SHAs are a Mismatch.
    ///
    /// Also the original defect in one assertion: version equality is not build
    /// equality, and the version is all the old handshake carried.
    #[test]
    fn two_different_known_shas_are_a_mismatch_at_the_same_version() {
        let a = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let b = identity("0.0.1-rc.6", "bbbbbbbbbbbb");
        assert_eq!(a.core_version, b.core_version);
        let comparison = a.compare(&b);
        assert!(
            matches!(comparison, IdentityComparison::Mismatch { .. }),
            "got {comparison:?}"
        );
        assert_eq!(comparison.named(FieldStatus::Mismatched), vec!["build_sha"]);
    }

    /// TEST 3 — the rejected behaviour. `unknown` vs `unknown` is
    /// **Unverifiable**, never a Match.
    ///
    /// The previous revision returned `true` here, on the reasoning that two
    /// binaries from one published tarball are one build. The reasoning
    /// concludes identity from shared ignorance and holds equally for two
    /// unrelated tarballs, so it is rejected (ADR 0030 §5.4a).
    #[test]
    fn two_builds_with_no_identity_are_unverifiable_never_a_match() {
        let a = unknown_identity("0.0.1-rc.6");
        let comparison = a.compare(&unknown_identity("0.0.1-rc.6"));
        assert!(
            matches!(comparison, IdentityComparison::Unverifiable { .. }),
            "absence on both sides is not agreement, got {comparison:?}"
        );
        assert!(comparison.named(FieldStatus::Absent).contains(&"build_sha"));
        // `core_version` may legitimately be reported as matched — it did — and
        // the diagnostic is supposed to say so. What must never happen is that
        // matching it *upgrades* the outcome: no authoritative field matched, so
        // the verdict stays unverifiable.
        assert_eq!(comparison.named(FieldStatus::Matched), vec!["core_version"]);
        assert!(
            !matches!(comparison, IdentityComparison::Match { .. }),
            "a matching version must never carry the comparison to a match"
        );
    }

    /// TEST 4 — a known identity against an unknown one is Unverifiable.
    ///
    /// Not a mismatch: the peer has not been shown to be a *different* build,
    /// only to be unable to say. The two states get different sentences and
    /// different exit codes, so conflating them would misdirect the reader.
    #[test]
    fn a_known_identity_against_an_unknown_one_is_unverifiable_in_both_directions() {
        let known = identity("0.0.1-rc.6", "cccccccccccc");
        let unknown = unknown_identity("0.0.1-rc.6");
        for (left, right) in [(&known, &unknown), (&unknown, &known)] {
            let comparison = left.compare(right);
            assert!(
                matches!(comparison, IdentityComparison::Unverifiable { .. }),
                "got {comparison:?}"
            );
        }
    }

    /// TEST 5 — two official packaged artifacts from one commit are a Match.
    ///
    /// `packaged` is `.cargo_vcs_info.json`, which names the commit the crate
    /// was published from. It is a real shared artifact identity, so it proves a
    /// match exactly as a checkout does.
    #[test]
    fn matching_packaged_build_ids_are_a_match() {
        let a = BuildIdentity {
            core_version: "0.0.1-rc.7".to_string(),
            build_sha: "1234567890abcdef1234567890abcdef12345678".to_string(),
            sha_source: IdentitySource::Packaged,
        };
        let comparison = a.compare(&a.clone());
        assert!(matches!(comparison, IdentityComparison::Match { .. }), "{comparison:?}");
    }

    /// TEST 6 — two packaged artifacts from different commits are a Mismatch.
    #[test]
    fn mismatched_packaged_build_ids_are_a_mismatch() {
        let a = BuildIdentity {
            core_version: "0.0.1-rc.7".to_string(),
            build_sha: "1234567890abcdef1234567890abcdef12345678".to_string(),
            sha_source: IdentitySource::Packaged,
        };
        let b = BuildIdentity {
            build_sha: "fedcba0987654321fedcba0987654321fedcba09".to_string(),
            ..a.clone()
        };
        assert!(
            matches!(a.compare(&b), IdentityComparison::Mismatch { .. }),
            "{:?}",
            a.compare(&b)
        );
    }

    /// TEST 7 — a release binary against an unrelated local build is not a
    /// Match, whichever way the identities fall.
    #[test]
    fn a_release_binary_against_an_unrelated_local_build_is_never_a_match() {
        let release_with_id = BuildIdentity {
            core_version: "0.0.1-rc.7".to_string(),
            build_sha: "1111111111111111111111111111111111111111".to_string(),
            sha_source: IdentitySource::Injected,
        };
        let release_without_id = unknown_identity("0.0.1-rc.7");
        let local = identity("0.0.1-rc.7", "2222222222222222222222222222222222222222");

        for release in [&release_with_id, &release_without_id] {
            let comparison = release.compare(&local);
            assert!(
                !matches!(comparison, IdentityComparison::Match { .. }),
                "a release artifact and an unrelated local build are not one build: {comparison:?}"
            );
        }
        // …and the two failures are told apart, because their remedies differ.
        assert!(matches!(
            release_with_id.compare(&local),
            IdentityComparison::Mismatch { .. }
        ));
        assert!(matches!(
            release_without_id.compare(&local),
            IdentityComparison::Unverifiable { .. }
        ));
    }

    /// A known SHA with no authoritative source behind it cannot prove a match.
    ///
    /// The escape hatch the three-state rule would otherwise leave open: fill in
    /// a plausible SHA from a non-authoritative mechanism and the comparison
    /// would upgrade itself back to `Match`.
    #[test]
    fn a_sha_with_no_authoritative_source_cannot_prove_a_match() {
        let forged = BuildIdentity {
            core_version: "0.0.1-rc.6".to_string(),
            build_sha: "aaaaaaaaaaaa".to_string(),
            sha_source: IdentitySource::Absent,
        };
        assert!(!forged.is_authoritative());
        assert!(matches!(
            forged.compare(&forged.clone()),
            IdentityComparison::Unverifiable { .. }
        ));
    }

    /// A version disagreement falsifies even when the SHAs agree — that pairing
    /// is a contradiction, and reading it as a match would trust a peer whose
    /// own two fields disagree with each other.
    #[test]
    fn a_version_disagreement_falsifies_even_with_equal_shas() {
        let a = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let b = identity("0.0.1-rc.7", "aaaaaaaaaaaa");
        let comparison = a.compare(&b);
        assert!(
            matches!(comparison, IdentityComparison::Mismatch { .. }),
            "{comparison:?}"
        );
        assert_eq!(comparison.named(FieldStatus::Mismatched), vec!["core_version"]);
    }

    #[test]
    fn a_matching_build_with_a_live_executable_is_verified() {
        let expected = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let verdict = verify(Some(&peer(expected.clone(), true)), &expected, 4);
        assert!(verdict.is_trustworthy());
        assert_eq!(verdict.as_str(), "verified");
        assert_eq!(verdict.standing(), ProvenanceStanding::Verified);
        assert_eq!(verdict.pid(), Some(4242));
        assert!(verdict.remediation().is_empty());
    }

    /// The verdict a runtime with no build identity produces, end to end.
    #[test]
    fn a_peer_with_no_build_identity_is_unverifiable_and_names_the_absent_fields() {
        let expected = unknown_identity("0.0.1-rc.6");
        let verdict = verify(Some(&peer(unknown_identity("0.0.1-rc.6"), true)), &expected, 4);
        assert!(!verdict.is_trustworthy());
        assert_eq!(verdict.as_str(), "unverifiable");
        assert_eq!(verdict.standing(), ProvenanceStanding::Unverifiable);
        assert_eq!(verdict.pid(), Some(4242));
        let detail = verdict.detail();
        assert!(detail.contains("unverifiable"), "{detail}");
        assert!(!detail.contains("not installed"), "{detail}");
        // The diagnostic must name which fields were absent.
        assert!(detail.contains("absent"), "{detail}");
        assert!(detail.contains("build_sha"), "{detail}");
        assert!(!verdict.remediation().is_empty());
        let comparison = verdict.comparison().expect("a comparison ran");
        assert!(comparison.named(FieldStatus::Absent).contains(&"build_sha"));
    }

    #[test]
    fn a_different_build_is_a_mismatch_naming_both_sides() {
        let expected = identity("0.0.1-rc.6", "aaaaaaaaaaaa");
        let verdict = verify(Some(&peer(identity("0.0.1-rc.6", "bbbbbbbbbbbb"), true)), &expected, 4);
        assert!(!verdict.is_trustworthy());
        assert_eq!(verdict.as_str(), "mismatch");
        assert_eq!(verdict.standing(), ProvenanceStanding::Refuted);
        let detail = verdict.detail();
        assert!(detail.contains("aaaaaaaaaaaa"), "{detail}");
        assert!(detail.contains("bbbbbbbbbbbb"), "{detail}");
        assert!(
            detail.contains("/build-a"),
            "the peer's checkout is worth naming: {detail}"
        );
        assert!(
            detail.contains("mismatched build_sha"),
            "the disagreeing field must be named: {detail}"
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
            verify(Some(&peer(unknown_identity("0.0.1-rc.6"), true)), &expected, 4),
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

    /// The contract the owner decision states in one line: no surface, and no
    /// JSON, may render an unverifiable result as verified or matching.
    ///
    /// Asserted on the *vocabulary* rather than on one renderer, because every
    /// surface derives its wording from these two tokens.
    #[test]
    fn an_unverifiable_verdict_never_reads_as_verified_or_matching() {
        let expected = unknown_identity("0.0.1-rc.6");
        let verdict = verify(Some(&peer(unknown_identity("0.0.1-rc.6"), true)), &expected, 4);
        assert_ne!(verdict.as_str(), "verified");
        assert_ne!(verdict.standing().as_str(), "verified");
        assert!(!verdict.is_trustworthy());
        for rendered in [verdict.as_str().to_string(), verdict.standing().as_str().to_string()] {
            assert!(!rendered.contains("verified"), "{rendered}");
            assert!(!rendered.contains("match"), "{rendered}");
        }
        // The one place "verified" may appear is inside the explanation of why
        // it is *not* verified, and even there it must be negated.
        assert!(
            verdict.detail().contains("unverifiable rather than verified"),
            "{}",
            verdict.detail()
        );
        // A matching version is reported as matching — that is the diagnostic
        // doing its job — but no *authoritative* field matched, which is why
        // the verdict is what it is.
        let comparison = verdict.comparison().expect("comparison");
        assert!(!comparison.named(FieldStatus::Matched).contains(&"build_sha"));
        assert!(comparison.named(FieldStatus::Absent).contains(&"build_sha"));
    }

    /// A peer that predates the source field sends an empty string, which must
    /// read as absent rather than as a source this build happens not to know.
    #[test]
    fn an_unrecognised_or_empty_identity_source_reads_as_absent() {
        for token in ["", "something-new", "checkout-ish", "ABSENT"] {
            assert_eq!(
                IdentitySource::from_wire(token),
                IdentitySource::Absent,
                "{token:?} must not be read as authoritative"
            );
        }
        for token in ["injected", "checkout", "packaged"] {
            assert!(IdentitySource::from_wire(token).is_authoritative(), "{token}");
            assert_eq!(IdentitySource::from_wire(token).as_str(), token);
        }
    }

    #[test]
    fn a_wire_round_trip_preserves_every_provenance_field() {
        let provenance = RuntimeProvenance::detect();
        let wire = provenance.to_wire();
        assert_eq!(
            wire.build_id_source,
            provenance.identity.sha_source.as_str(),
            "the source must ride on the wire, or the peer cannot tell an authoritative SHA from a placeholder"
        );
        let decoded = PeerProvenance::from_wire(&wire);
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
