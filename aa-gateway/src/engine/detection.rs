//! The canonical detection port for the gateway's Stage 6 scan (ADR 0032 §10,
//! decision D-1; AAASM-5354).
//!
//! # What this formalises
//!
//! A detection seam already existed in [`super::PolicyEngine`], hardcoded and
//! unnamed: Stage 6 ran the built-in Aho-Corasick scan, then appended matches
//! from the policy's `data.sensitive_patterns` regexes onto the same
//! `Vec<CredentialFinding>`. Two sources, one merged list, no abstraction — and
//! no way for a third source to join without a third open-coded loop.
//!
//! This module names that seam. Each source is a [`DetectionPass`]; [`run`]
//! executes passes in order and merges their output. The merged
//! `Vec<CredentialFinding>` the enforcement stages consume is byte-identical to
//! what the open-coded loops produced, in the same order, with the same spans:
//! the passes are the same two computations, moved rather than rewritten.
//!
//! # Why an out-of-process provider cannot be plugged in here
//!
//! ADR 0032 D-1 permits this port to wrap an **in-process, deterministic**
//! scanner on a synchronous path, and forbids routing it to anything out of
//! process — no Presidio, no Gitleaks, no provider container, no transport.
//! Validation requirement 10 requires that boundary to be enforced by the
//! compiler rather than by convention, because `PolicyEngine::evaluate` is a
//! synchronous **pre-action** enforcement path: a blocking network call placed
//! behind this trait would stall every governed action in the process, and a
//! failing one would decide policy by timeout.
//!
//! [`DetectionPass`] is therefore **sealed**. Its supertrait
//! `sealed::InProcess` lives in a private module of this file, so a type
//! outside this module cannot implement it and therefore cannot implement
//! `DetectionPass` — the compiler rejects it with `E0277`, which the
//! `compile_fail` doctest on [`DetectionPass`] pins. Adding an out-of-process
//! provider is not a matter of writing an adapter somewhere else in the tree;
//! it requires an `impl sealed::InProcess` **in this file**, directly beneath
//! this paragraph, which is exactly the diff a reviewer needs to see.
//!
//! Two weaker properties reinforce it but are not what discharges requirement
//! 10, and are recorded as secondary so they are not mistaken for the boundary:
//! [`DetectionPass::detect`] is a plain `fn` returning a value rather than an
//! `async fn` returning a future, and it borrows the caller's `&str` for the
//! duration of the call. Both make a remote implementation awkward. Neither
//! makes one impossible — `block_on` exists — which is why the seal, and not
//! the signature, is the mechanism.
//!
//! # What a pass may not do
//!
//! A pass returns findings. It cannot return, influence or short-circuit a
//! policy decision: no type reachable from [`DetectionPass::detect`]'s
//! signature can express one, and [`run`] has no access to the policy document.
//! Agent Assembly owns the decision (ADR 0002; ADR 0032 §4), and
//! [`ConfidenceBand`](aa_security::canonical::ConfidenceBand) in particular is
//! evidence carried alongside a finding, never an authorisation input — it is
//! deliberately not `PartialOrd` upstream so no call site can rank on it.
//!
//! # Failure is not emptiness
//!
//! [`DetectionPass::detect`] returns a `Result`, and [`run`] propagates the
//! first error rather than returning the findings it had already gathered. A
//! configured pass that cannot run is a [`DetectionError`], never a clean
//! result and never a silent fall-back to a weaker pass (ADR 0032 §5). The
//! caller is expected to fail closed on it; [`super::PolicyEngine`] denies.

use std::sync::Arc;

use aa_security::canonical::{CanonicalFinding, Recognizer};
use aa_security::{CredentialFinding, CredentialScanner};

use crate::policy::PolicyDocument;

/// The seal. Not re-exported, and deliberately not `pub` beyond this module.
mod sealed {
    /// Marks a detection pass as running inside this process.
    ///
    /// Implemented only for the pass types declared in this file. Because this
    /// module is private, no crate — including this one, outside this file —
    /// can add an implementation, so [`super::DetectionPass`] cannot be
    /// implemented for a type that talks to a provider over a transport.
    pub trait InProcess {}
}

/// One detection source contributing to the gateway's Stage 6 merged findings.
///
/// # Sealed
///
/// This trait cannot be implemented outside this module — see the module
/// documentation for why ADR 0032 validation requirement 10 needs that to be a
/// compiler rule rather than a comment. An implementation attempted from
/// anywhere else fails to satisfy the private supertrait bound:
///
/// ```compile_fail,E0277
/// use aa_gateway::engine::detection::{DetectedFinding, DetectionError, DetectionPass};
/// use aa_security::canonical::Recognizer;
///
/// /// A hypothetical adapter that would call a provider over a socket.
/// struct OutOfProcessProvider;
///
/// impl DetectionPass for OutOfProcessProvider {
///     fn recognizer(&self) -> Recognizer {
///         Recognizer::BuiltinScanner
///     }
///     fn detect(&self, _text: &str, _out: &mut Vec<DetectedFinding>) -> Result<(), DetectionError> {
///         Ok(())
///     }
/// }
/// ```
pub trait DetectionPass: sealed::InProcess {
    /// Which recognizer this pass attributes its findings to.
    ///
    /// Used for reporting and for the pass-ordering assertions in this module's
    /// tests; it is not consulted when deciding anything.
    fn recognizer(&self) -> Recognizer;

    /// Append this pass's findings for `text` onto `out`, in offset order.
    ///
    /// Appends rather than returns a `Vec` so a multi-pass run allocates once,
    /// which matters because this is on the synchronous enforcement path.
    ///
    /// # Errors
    ///
    /// [`DetectionError`] when the pass is configured but cannot run. A pass
    /// that ran and found nothing returns `Ok(())` having pushed nothing; the
    /// two are different outcomes and must not be conflated (ADR 0032 §5).
    fn detect(&self, text: &str, out: &mut Vec<DetectedFinding>) -> Result<(), DetectionError>;
}

/// Why a configured detection pass could not run.
///
/// Distinct from "ran and found nothing", which is `Ok(())` with an empty
/// push. A detection source that cannot answer must never look like one that
/// answered "clean" (ADR 0032 §5, forbidden design #2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetectionError {
    /// `data.locale_packs` named a pack this build does not contain.
    ///
    /// This is the **only** place an unrecognised tag is caught. `aa-policy` is
    /// a leaf crate and cannot see this catalogue, so `PolicyValidator` carries
    /// the operator's tags through verbatim rather than deciding they are wrong
    /// (AAASM-5349 extracted it; before that extraction the check lived at load
    /// time, and moving it here is the layering the extraction forces).
    ///
    /// The consequence is deliberate and worth stating plainly: a typo in
    /// `data.locale_packs` loads successfully and then denies every action,
    /// naming the tag. That is blunt. It is still the right side to fail on —
    /// the alternative is a detector an operator explicitly asked for silently
    /// not running, which is the degrade ADR 0032 §5 exists to forbid.
    UnknownLocalePack {
        /// The tag as written in the policy document.
        tag: String,
    },
}

impl core::fmt::Display for DetectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownLocalePack { tag } => {
                write!(f, "policy names locale pack '{tag}', which this build does not contain")
            }
        }
    }
}

impl std::error::Error for DetectionError {}

/// A deterministic locale recognizer pack this build contains.
///
/// A closed enum rather than a string, for the same reason
/// [`Recognizer`] is one: a pack identity that could be built from runtime
/// bytes would let a policy document name a detector that does not exist and
/// have it silently accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LocalePack {
    /// [`aa_security::locale::zh_tw`] — Taiwanese identity, residence, business
    /// and telephone identifiers (AAASM-5353).
    ZhTw,
}

impl LocalePack {
    /// The BCP-47 tag naming this pack in `data.locale_packs`.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ZhTw => "zh-TW",
        }
    }

    /// Every pack this build contains, in the order they are documented.
    pub const ALL: &'static [LocalePack] = &[Self::ZhTw];

    /// Resolve a policy-supplied tag, case-insensitively.
    ///
    /// Case-insensitive because BCP-47 tags are case-insensitive by definition
    /// (RFC 5646 §2.1.1); the canonical casing is what [`Self::tag`] returns.
    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.tag().eq_ignore_ascii_case(tag))
    }
}

/// Resolve every tag in a policy's `data.locale_packs`, failing closed on one
/// this build does not contain.
///
/// Returns an empty `Vec` — which does not allocate — for the default empty
/// list, so the ungated hot path pays nothing for this feature existing.
///
/// # Errors
///
/// [`DetectionError::UnknownLocalePack`] on the first unrecognised tag.
pub fn resolve_locale_packs(tags: &[String]) -> Result<Vec<LocalePack>, DetectionError> {
    tags.iter()
        .map(|tag| LocalePack::from_tag(tag).ok_or_else(|| DetectionError::UnknownLocalePack { tag: tag.clone() }))
        .collect()
}

/// One finding produced by a pass, in both the tiers the gateway needs.
///
/// # Why two representations rather than one
///
/// The canonical model is the vocabulary this port speaks, but it cannot
/// replace [`CredentialFinding`] at the enforcement tier: redaction splices
/// each finding's published `[REDACTED:<kind>]` label, and those labels are a
/// frozen contract served by `GET /api/v1/scrub/patterns`. So a finding carries
/// its canonical projection *and* the scanner-tier value the existing stages
/// already consume.
///
/// Both fields are `Option`, and each `None` means something specific:
///
/// - `credential: None` — a locale-pack finding. It has no
///   [`CredentialKind`](aa_security::CredentialKind) and inventing one would
///   extend a frozen catalogue by accident, so it redacts through the canonical
///   path to a bare `[REDACTED]`.
/// - `canonical: None` — the lift refused the span. Reachable exactly one way:
///   an operator regex such as `x*` matches zero width, and a canonical finding
///   covers at least one byte. Such a finding is **kept**, not dropped — it
///   still reaches `credential_findings` and still denies under
///   `credential_action: block`, which is what it did before this port existed.
///   Only its canonical projection is absent, and losing a projection is not
///   the same as losing a finding.
///
/// Both `None` at once is unrepresentable: the two constructors are private to
/// this module and each sets at least one.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedFinding {
    canonical: Option<CanonicalFinding>,
    credential: Option<CredentialFinding>,
}

impl DetectedFinding {
    /// A finding that carries a [`CredentialKind`](aa_security::CredentialKind),
    /// lifted into canonical terms.
    ///
    /// The lift stamps provenance from the kind, so a
    /// [`CredentialKind::Custom`](aa_security::CredentialKind::Custom) finding —
    /// the label the scanner reserves for an operator's `sensitive_patterns`
    /// regex — is attributed to [`Recognizer::PolicyRegex`] rather than to the
    /// built-in scanner, which never saw it (AAASM-5352).
    fn from_credential(credential: CredentialFinding) -> Self {
        let canonical = CanonicalFinding::try_from(&credential).ok();
        Self {
            canonical,
            credential: Some(credential),
        }
    }

    /// A locale-pack finding, which has no scanner-tier counterpart.
    const fn from_canonical(canonical: CanonicalFinding) -> Self {
        Self {
            canonical: Some(canonical),
            credential: None,
        }
    }

    /// The canonical projection, absent only when the lift refused the span.
    pub const fn canonical(&self) -> Option<&CanonicalFinding> {
        self.canonical.as_ref()
    }

    /// The enforcement-tier finding, absent for a locale-pack hit.
    pub const fn credential(&self) -> Option<&CredentialFinding> {
        self.credential.as_ref()
    }
}

/// The merged output of a [`run`] over an ordered list of passes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetectionOutcome {
    findings: Vec<DetectedFinding>,
}

impl DetectionOutcome {
    /// Every finding, in pass order and, within a pass, in the order that pass
    /// produced them.
    pub fn findings(&self) -> &[DetectedFinding] {
        &self.findings
    }

    /// `true` when at least one finding has no enforcement-tier counterpart.
    ///
    /// The gateway reads this to decide which redaction primitive applies: with
    /// no such finding the merged list is exactly what the pre-port code
    /// produced and
    /// [`ScanResult::redact`](aa_security::ScanResult) still owns redaction.
    pub fn has_canonical_only(&self) -> bool {
        self.findings.iter().any(|f| f.credential.is_none())
    }

    /// Split into the two lists the Stage 6 stages consume.
    ///
    /// The enforcement-tier list preserves pass order exactly, because
    /// `apply_credential_scan` sorts it with a **stable** sort by offset and
    /// two findings at the same offset must keep the relative order the
    /// open-coded loops gave them. The canonical list is sorted by span, since
    /// nothing downstream depends on its pass order and a deterministic order
    /// is worth more.
    pub fn into_parts(self) -> (Vec<CredentialFinding>, Vec<CanonicalFinding>) {
        let mut credential = Vec::with_capacity(self.findings.len());
        let mut canonical = Vec::with_capacity(self.findings.len());
        for finding in self.findings {
            if let Some(c) = finding.canonical {
                canonical.push(c);
            }
            if let Some(c) = finding.credential {
                credential.push(c);
            }
        }
        canonical.sort_by_key(|f| (f.span().start(), f.span().end()));
        (credential, canonical)
    }
}

/// Run `passes` over `text` in order, merging their findings.
///
/// # Errors
///
/// The first [`DetectionError`] any pass returns, discarding the findings
/// gathered so far. A partial result would be indistinguishable from a complete
/// one to the caller, and a detection run that did not finish must not be able
/// to look like one that found nothing (ADR 0032 §5).
pub fn run(text: &str, passes: &[&dyn DetectionPass]) -> Result<DetectionOutcome, DetectionError> {
    // An installed test double joins the pass list rather than being invoked
    // after the loop, so this function has exactly **one** place a pass error
    // propagates from. With two, a mutation that swallowed the loop's error
    // left the double's `?` intact and no test noticed — which is how the
    // fail-closed assertions passed while the property was broken.
    #[cfg(test)]
    let double = test_double::installed();
    #[cfg(test)]
    let effective: Vec<&dyn DetectionPass> = passes
        .iter()
        .copied()
        .chain(double.iter().map(|d| d as &dyn DetectionPass))
        .collect();
    #[cfg(test)]
    let passes: &[&dyn DetectionPass] = &effective;

    let mut findings = Vec::new();
    for pass in passes {
        pass.detect(text, &mut findings)?;
    }
    Ok(DetectionOutcome { findings })
}

// ---------------------------------------------------------------------------
// Pass 1 — the built-in scanner
// ---------------------------------------------------------------------------

/// The built-in Aho-Corasick credential scan (`aa_security::CredentialScanner`).
pub struct BuiltinScannerPass<'a> {
    scanner: &'a CredentialScanner,
}

impl<'a> BuiltinScannerPass<'a> {
    /// Wrap the engine's construction-time scanner.
    pub const fn new(scanner: &'a CredentialScanner) -> Self {
        Self { scanner }
    }
}

impl sealed::InProcess for BuiltinScannerPass<'_> {}

impl DetectionPass for BuiltinScannerPass<'_> {
    fn recognizer(&self) -> Recognizer {
        Recognizer::BuiltinScanner
    }

    fn detect(&self, text: &str, out: &mut Vec<DetectedFinding>) -> Result<(), DetectionError> {
        out.extend(
            self.scanner
                .scan(text)
                .findings
                .into_iter()
                .map(DetectedFinding::from_credential),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pass 2 — the operator's `data.sensitive_patterns` regexes
// ---------------------------------------------------------------------------

/// Policy-defined regexes already compiled into the engine's cascade state.
///
/// Used by the single-policy path, which pre-compiles the Global document's
/// patterns on every cascade swap so the hot path never compiles a regex.
pub struct CompiledRegexPass<'a> {
    patterns: &'a [regex::Regex],
}

impl<'a> CompiledRegexPass<'a> {
    /// Wrap the pre-compiled patterns held in the engine's cascade state.
    pub const fn new(patterns: &'a [regex::Regex]) -> Self {
        Self { patterns }
    }
}

impl sealed::InProcess for CompiledRegexPass<'_> {}

impl DetectionPass for CompiledRegexPass<'_> {
    fn recognizer(&self) -> Recognizer {
        Recognizer::PolicyRegex
    }

    fn detect(&self, text: &str, out: &mut Vec<DetectedFinding>) -> Result<(), DetectionError> {
        for re in self.patterns {
            push_regex_matches(re, text, out);
        }
        Ok(())
    }
}

/// Policy-defined regexes across a resolved cascade, compiled per evaluation.
///
/// The cascade path has no pre-compiled slot — its patterns come from every
/// document in the resolved chain, not just the Global one — so it compiles as
/// it goes, exactly as the open-coded `collect_cascade_custom_findings` did.
pub struct CascadeRegexPass<'a> {
    cascade: &'a [Arc<PolicyDocument>],
}

impl<'a> CascadeRegexPass<'a> {
    /// Wrap the documents in a resolved cascade.
    pub const fn new(cascade: &'a [Arc<PolicyDocument>]) -> Self {
        Self { cascade }
    }
}

impl sealed::InProcess for CascadeRegexPass<'_> {}

impl DetectionPass for CascadeRegexPass<'_> {
    fn recognizer(&self) -> Recognizer {
        Recognizer::PolicyRegex
    }

    /// # Pre-existing leniency, preserved deliberately
    ///
    /// An unparseable pattern is skipped rather than raised as a
    /// [`DetectionError`]. That is *not* the fail-closed choice, and it is kept
    /// only because changing it would change policy outcomes, which AAASM-5354
    /// forbids. `PolicyValidator` rejects an invalid regex at load time, so this
    /// silently-skipped branch is reachable only for a `PolicyDocument`
    /// constructed without validation. Tightening it is out of this ticket's
    /// scope and is recorded rather than quietly fixed.
    fn detect(&self, text: &str, out: &mut Vec<DetectedFinding>) -> Result<(), DetectionError> {
        for doc in self.cascade {
            if let Some(dp) = &doc.data {
                for pattern in &dp.sensitive_patterns {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        push_regex_matches(&re, text, out);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Append every match of `re` in `text` as a policy-regex finding.
///
/// Shared by both regex passes so the single-policy and cascade paths cannot
/// drift in how they turn a match into a finding.
fn push_regex_matches(re: &regex::Regex, text: &str, out: &mut Vec<DetectedFinding>) {
    for m in re.find_iter(text) {
        out.push(DetectedFinding::from_credential(CredentialFinding::from_regex_match(
            m.start(),
            m.end(),
        )));
    }
}

// ---------------------------------------------------------------------------
// Pass 3 — deterministic locale packs, off unless a policy asks for them
// ---------------------------------------------------------------------------

/// A deterministic locale recognizer pack, run only when `data.locale_packs`
/// names it.
///
/// # Why this is not on by default
///
/// `PolicyEngine::evaluate` is the synchronous **pre-action** path, and
/// `credential_action: block` lives on it. AAASM-5353 measured the 統一編號
/// (business-registration) checksum at a **22.0000%** residual — roughly one in
/// five random eight-digit strings satisfies it. Enabling that by default would
/// aim a detector that is wrong one time in five at the exact failure this Epic
/// exists to correct: a detector firing on ordinary content and denying a
/// Chinese-speaking agent's action. Default-off keeps the ungated path
/// byte-identical; whether to accept that residual for a given deployment is
/// the operator's call, made explicitly in policy.
pub struct LocalePackPass {
    pack: LocalePack,
}

impl LocalePackPass {
    /// Run the named pack.
    pub const fn new(pack: LocalePack) -> Self {
        Self { pack }
    }
}

impl sealed::InProcess for LocalePackPass {}

impl DetectionPass for LocalePackPass {
    fn recognizer(&self) -> Recognizer {
        match self.pack {
            LocalePack::ZhTw => Recognizer::ZhTwLocalePack,
        }
    }

    fn detect(&self, text: &str, out: &mut Vec<DetectedFinding>) -> Result<(), DetectionError> {
        let findings = match self.pack {
            LocalePack::ZhTw => aa_security::locale::zh_tw::scan(text),
        };
        out.extend(findings.into_iter().map(DetectedFinding::from_canonical));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The in-tree test double
// ---------------------------------------------------------------------------

/// A substitutable pass for proving the production path really runs the port.
///
/// Lives here rather than in a test module elsewhere because [`DetectionPass`]
/// is sealed — which is the point: even the double cannot be written outside
/// this file. It is `#[cfg(test)]`, so no production build contains it and no
/// production wiring mentions it; a test installs it on the current thread and
/// [`run`] picks it up.
#[cfg(test)]
pub(crate) mod test_double {
    use super::{DetectedFinding, DetectionError, DetectionPass, Recognizer};
    use aa_security::canonical::{
        ByteSpan, CanonicalCategory, CanonicalFinding, ConfidenceBand, DetectionMethod, FindingStatus, Provenance,
        Severity,
    };
    use aa_security::CredentialKind;
    use std::cell::RefCell;

    thread_local! {
        static INSTALLED: RefCell<Option<FixedPass>> = const { RefCell::new(None) };
    }

    /// A pass that emits a fixed finding whenever `needle` occurs in the text.
    #[derive(Debug, Clone)]
    pub(crate) struct FixedPass {
        needle: String,
        /// When set, `detect` fails instead of reporting, so a test can prove
        /// the caller fails closed rather than proceeding with no findings.
        fail_with: Option<DetectionError>,
        /// `false` emits a canonical-only finding (a locale-pack shape);
        /// `true` also emits the enforcement-tier counterpart.
        enforceable: bool,
        confidence: ConfidenceBand,
    }

    impl FixedPass {
        pub(crate) fn reporting(needle: &str) -> Self {
            Self {
                needle: needle.to_string(),
                fail_with: None,
                enforceable: false,
                confidence: ConfidenceBand::High,
            }
        }

        /// Also emit the enforcement-tier counterpart, so a test can prove the
        /// port carries findings into `credential_findings` and redaction, not
        /// only into the canonical projection.
        pub(crate) fn enforceable(needle: &str) -> Self {
            Self {
                enforceable: true,
                ..Self::reporting(needle)
            }
        }

        /// Vary only the confidence band, so a test can prove the decision does
        /// not move with it (ADR 0032 §4).
        pub(crate) fn with_confidence(mut self, confidence: ConfidenceBand) -> Self {
            self.confidence = confidence;
            self
        }

        pub(crate) fn failing(error: DetectionError) -> Self {
            Self {
                fail_with: Some(error),
                ..Self::reporting("")
            }
        }
    }

    impl super::sealed::InProcess for FixedPass {}

    impl DetectionPass for FixedPass {
        fn recognizer(&self) -> Recognizer {
            Recognizer::ZhTwLocalePack
        }

        fn detect(&self, text: &str, out: &mut Vec<DetectedFinding>) -> Result<(), DetectionError> {
            if let Some(e) = &self.fail_with {
                return Err(e.clone());
            }
            for (start, _) in text.match_indices(&self.needle) {
                let end = start + self.needle.len();
                if self.enforceable {
                    out.push(DetectedFinding::from_credential(
                        aa_security::CredentialFinding::from_regex_match(start, end),
                    ));
                } else {
                    let finding = CanonicalFinding::new(
                        CanonicalCategory::from_credential_kind(&CredentialKind::Custom),
                        Severity::Medium,
                        self.confidence,
                        ByteSpan::new(start, end),
                        DetectionMethod::PolicyDefined,
                        Provenance::new(Recognizer::ZhTwLocalePack, "test-double"),
                        FindingStatus::Suspected,
                    )
                    .expect("the double's spans are non-empty by construction");
                    out.push(DetectedFinding::from_canonical(finding));
                }
            }
            Ok(())
        }
    }

    /// Install `pass` for the current thread until [`clear`] is called.
    pub(crate) fn install(pass: FixedPass) {
        INSTALLED.with(|slot| *slot.borrow_mut() = Some(pass));
    }

    /// Remove any installed double.
    pub(crate) fn clear() {
        INSTALLED.with(|slot| *slot.borrow_mut() = None);
    }

    /// The double installed on this thread, if any.
    pub(super) fn installed() -> Option<FixedPass> {
        INSTALLED.with(|slot| slot.borrow().clone())
    }

    /// Install `pass`, run `body`, then clear — even if `body` panics is *not*
    /// guaranteed, deliberately: a panicking test has already failed, and a
    /// drop guard here would hide which assertion failed behind a poisoned
    /// `RefCell` borrow.
    pub(crate) fn with<R>(pass: FixedPass, body: impl FnOnce() -> R) -> R {
        install(pass);
        let out = body();
        clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_security::canonical::DetectionMethod;
    use aa_security::CredentialKind;

    /// The reference implementation of Stage 6's two passes, transcribed from
    /// `engine/mod.rs` as it stood at `3e8cb4955`, immediately before this port
    /// existed.
    ///
    /// This is the "before" side of the behaviour-identity comparison. It is
    /// kept here rather than derived from the port so the comparison has two
    /// independent sides: a reference that called into the port would agree
    /// with it by construction and prove nothing.
    fn reference_stage6(scanner: &CredentialScanner, patterns: &[regex::Regex], text: &str) -> Vec<CredentialFinding> {
        let scan = scanner.scan(text);
        let mut all_findings = scan.findings;
        for re in patterns {
            for m in re.find_iter(text) {
                all_findings.push(CredentialFinding::from_regex_match(m.start(), m.end()));
            }
        }
        all_findings
    }

    /// Payloads chosen to exercise every ordering hazard the merge has: a clean
    /// payload, one hit per pass, both passes hitting, both hitting at the same
    /// offset (where the stable sort's tie-breaking is observable), overlapping
    /// spans, multi-byte text, and a zero-width regex.
    fn identity_fixtures() -> Vec<(&'static str, Vec<&'static str>)> {
        vec![
            ("list files in /home/user", vec![]),
            ("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", vec![]),
            ("config: api_key=supersecret123", vec![r"api_key=[A-Za-z0-9]+"]),
            (
                "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 and api_key=supersecret123",
                vec![r"api_key=[A-Za-z0-9]+"],
            ),
            // Both passes match at the same offset: the scanner's GitHub PAT
            // detector and an operator regex written over the same literal.
            (
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
                vec![r"ghp_[A-Za-z0-9]+", r"ghp_[A-Z]{4}"],
            ),
            // Overlapping operator patterns.
            ("aaaa-bbbb-cccc", vec![r"a+-b+", r"b+-c+"]),
            // Multi-byte: spans must stay on character boundaries.
            ("使用者的 api_key=秘密 已外洩", vec![r"api_key=\S+"]),
            // Zero-width match: the canonical lift refuses it, the enforcement
            // tier must keep it.
            ("abc", vec![r"x*"]),
            // A payload the zh-TW pack would flag, with the pack absent.
            ("居留證統一證號 A800000005 於系統中建檔。", vec![]),
        ]
    }

    /// AC: the merged findings list is byte-identical to the pre-port merge.
    ///
    /// Identity of the whole `Vec<CredentialFinding>` — kind, offset, label and
    /// order — not "both non-empty". Two of the fixtures produce no findings at
    /// all, so the assertion is additionally guarded below against passing on
    /// an empty corpus.
    #[test]
    fn port_merge_is_byte_identical_to_the_pre_port_merge() {
        let scanner = CredentialScanner::new();
        let mut total_findings = 0usize;
        let mut fixtures_with_findings = 0usize;

        for (text, patterns) in identity_fixtures() {
            let compiled: Vec<regex::Regex> = patterns.iter().map(|p| regex::Regex::new(p).unwrap()).collect();
            let expected = reference_stage6(&scanner, &compiled, text);

            let scanner_pass = BuiltinScannerPass::new(&scanner);
            let regex_pass = CompiledRegexPass::new(&compiled);
            let outcome = run(text, &[&scanner_pass as &dyn DetectionPass, &regex_pass]).expect("no pass fails here");
            let (actual, _) = outcome.into_parts();

            assert_eq!(actual, expected, "merged findings differ for fixture {text:?}");
            total_findings += actual.len();
            if !actual.is_empty() {
                fixtures_with_findings += 1;
            }
        }

        // Guards against the whole comparison passing because every fixture
        // produced an empty list on both sides.
        assert!(
            fixtures_with_findings >= 6 && total_findings >= 10,
            "the identity corpus stopped exercising the merge: \
             {fixtures_with_findings} fixtures with findings, {total_findings} findings total"
        );
    }

    /// AC: pass 2's findings carry `Recognizer::PolicyRegex`, not
    /// `BuiltinScanner` — the variant AAASM-5352 added for exactly these two
    /// call sites.
    #[test]
    fn policy_regex_findings_are_attributed_to_the_policy_regex_recognizer() {
        let scanner = CredentialScanner::new();
        let compiled = vec![regex::Regex::new(r"api_key=[A-Za-z0-9]+").unwrap()];
        let text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 api_key=supersecret123";

        let scanner_pass = BuiltinScannerPass::new(&scanner);
        let regex_pass = CompiledRegexPass::new(&compiled);
        let outcome = run(text, &[&scanner_pass as &dyn DetectionPass, &regex_pass]).unwrap();

        let by_recognizer: Vec<_> = outcome
            .findings()
            .iter()
            .filter_map(|f| f.canonical())
            .map(|c| (c.provenance().recognizer, c.method()))
            .collect();

        assert!(
            by_recognizer.contains(&(Recognizer::BuiltinScanner, DetectionMethod::Deterministic)),
            "expected a built-in scanner finding, got {by_recognizer:?}"
        );
        assert!(
            by_recognizer.contains(&(Recognizer::PolicyRegex, DetectionMethod::PolicyDefined)),
            "expected a policy-regex finding, got {by_recognizer:?}"
        );
        assert!(
            !by_recognizer
                .iter()
                .any(|(r, m)| *r == Recognizer::BuiltinScanner && *m == DetectionMethod::PolicyDefined),
            "a policy-defined finding was attributed to the built-in scanner: {by_recognizer:?}"
        );
    }

    /// A zero-width operator regex is the one reachable way the canonical lift
    /// refuses a span. The finding must survive at the enforcement tier: losing
    /// a projection is not licence to lose a finding.
    #[test]
    fn a_zero_width_regex_match_keeps_its_enforcement_tier_finding() {
        let scanner = CredentialScanner::new();
        let compiled = vec![regex::Regex::new(r"x*").unwrap()];
        let scanner_pass = BuiltinScannerPass::new(&scanner);
        let regex_pass = CompiledRegexPass::new(&compiled);

        let outcome = run("abc", &[&scanner_pass as &dyn DetectionPass, &regex_pass]).unwrap();
        assert!(
            outcome.findings().iter().any(|f| f.canonical().is_none()),
            "expected at least one finding whose canonical lift was refused"
        );
        let (credential, canonical) = outcome.into_parts();
        assert_eq!(
            credential.len(),
            4,
            "a zero-width match at each of 4 positions must still produce 4 findings"
        );
        assert!(credential.iter().all(|f| f.kind == CredentialKind::Custom));
        assert!(
            canonical.is_empty(),
            "no zero-width span may become a canonical finding"
        );
    }

    /// `run` propagates a pass failure instead of returning the findings it had
    /// already collected. A caller must not be able to mistake an incomplete
    /// run for a clean one.
    #[test]
    fn a_failing_pass_discards_earlier_findings_rather_than_returning_them() {
        let scanner = CredentialScanner::new();
        let scanner_pass = BuiltinScannerPass::new(&scanner);
        let text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";

        // Sanity: pass 1 alone finds something, so the error below is really
        // discarding a non-empty prefix.
        let ok = run(text, &[&scanner_pass as &dyn DetectionPass]).unwrap();
        assert!(!ok.findings().is_empty(), "fixture must produce a finding for pass 1");

        let err = test_double::with(
            test_double::FixedPass::failing(DetectionError::UnknownLocalePack { tag: "ja-JP".into() }),
            || run(text, &[&scanner_pass as &dyn DetectionPass]),
        )
        .expect_err("the installed double fails");
        assert_eq!(err, DetectionError::UnknownLocalePack { tag: "ja-JP".into() });
    }

    #[test]
    fn unknown_locale_pack_tags_fail_closed_and_known_ones_resolve() {
        assert_eq!(resolve_locale_packs(&[]).unwrap(), vec![]);
        assert_eq!(
            resolve_locale_packs(&["zh-TW".to_string()]).unwrap(),
            vec![LocalePack::ZhTw]
        );
        // BCP-47 tags are case-insensitive.
        assert_eq!(
            resolve_locale_packs(&["ZH-tw".to_string()]).unwrap(),
            vec![LocalePack::ZhTw]
        );
        assert_eq!(
            resolve_locale_packs(&["zh-TW".to_string(), "ja-JP".to_string()]),
            Err(DetectionError::UnknownLocalePack {
                tag: "ja-JP".to_string()
            })
        );
    }

    /// The zh-TW pass produces canonical-only findings: no `CredentialKind`,
    /// and therefore no `[REDACTED:<kind>]` label to publish.
    #[test]
    fn the_locale_pass_produces_canonical_only_findings() {
        let pass = LocalePackPass::new(LocalePack::ZhTw);
        let outcome = run(
            "居留證統一證號 A800000005 於系統中建檔。",
            &[&pass as &dyn DetectionPass],
        )
        .unwrap();

        assert!(outcome.has_canonical_only());
        let (credential, canonical) = outcome.into_parts();
        assert!(
            credential.is_empty(),
            "a locale finding must not fabricate a CredentialKind"
        );
        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].provenance().recognizer, Recognizer::ZhTwLocalePack);
    }

    /// Ordinary numeric zh-TW prose must produce nothing even with the pack
    /// running — the false-positive side of the Epic's founding defect.
    #[test]
    fn the_locale_pass_is_silent_on_ordinary_numeric_prose() {
        let pass = LocalePackPass::new(LocalePack::ZhTw);
        let text = "閘道器預設監聽 50051 埠，儀表板使用 3000 埠。稽核事件保留 365 天。";
        let outcome = run(text, &[&pass as &dyn DetectionPass]).unwrap();
        assert!(
            outcome.findings().is_empty(),
            "clean prose produced {:?}",
            outcome.findings()
        );
    }

    #[test]
    fn locale_pack_tags_round_trip() {
        for pack in LocalePack::ALL {
            assert_eq!(LocalePack::from_tag(pack.tag()), Some(*pack));
        }
    }
}
