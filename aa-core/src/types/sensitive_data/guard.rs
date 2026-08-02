//! The screened string types, and the guard that stands between a caller and a
//! sensitive-data record.
//!
//! # Why a guard exists at all
//!
//! Everything else in a [`SensitiveDataDecisionEvent`](super::SensitiveDataDecisionEvent)
//! or a [`SensitiveDataFindingRecord`](super::SensitiveDataFindingRecord) is an
//! enum, an integer, or a `&'static str` from `aa-security`'s compiled-in
//! catalogue — none of which can hold bytes the scanner read. The strings a
//! caller supplies are the entire remaining surface through which a raw
//! sensitive value could reach a record, so they are the only thing worth
//! guarding, and guarding them is tractable.
//!
//! ADR 0032's security section asks for these prohibitions to be enforced in
//! the type system "where possible rather than by convention". This is the
//! where-possible part: the records have no constructor that takes a bare
//! `String`, so there is no path to a record field that does not pass through
//! one of the types below.
//!
//! # Two strengths of guarantee, and why they differ
//!
//! | Type | Check |
//! |---|---|
//! | [`AuditLabel`] | shape only — bounded length, no ASCII control characters |
//! | [`FieldPath`], and [`Endpoint`](super::Endpoint) identifiers | shape **and** a credential scan |
//!
//! The split is not laziness, it is a measurement. `AuditLabel` holds
//! system-generated identifiers — a ULID session id, a trace id, a tenant slug —
//! and the scanner flags a ULID: `01HZX9V8ABCDEFGHJKMNPQRSTV` scans as
//! `GenericHighEntropy`, because a detector whose job is to notice high-entropy
//! blobs cannot tell one from a correlation id. Screening those would reject
//! well-formed events for a risk that is not there: an id is minted by the
//! system, never lifted out of the payload being inspected.
//!
//! A field path and an endpoint identifier *are* derived from the inspected
//! request, so they get the scan. The concrete leak this closes is a database
//! URI as a destination — `postgresql://user:password@db.internal/app` is
//! flagged and refused, and the caller has to record the destination without
//! the password in it.
//!
//! # The guard is not a proof
//!
//! Stated plainly, because the neighbouring `aa-security` module was careful to
//! state its own limits and it would be dishonest to overclaim here.
//!
//! The scan can only refuse what the scanner recognises. A sensitive value of a
//! category no detector covers passes, and so does a partial one. What the
//! guard buys is that the *known* categories — every one the product claims to
//! detect — cannot be written into an audit record through the one channel that
//! could carry them, and that the failure is a refusal rather than a silent
//! acceptance.

use alloc::string::String;
use std::sync::OnceLock;

use aa_security::CredentialScanner;

/// Longest accepted [`AuditLabel`], in bytes.
///
/// Generous next to a ULID or a UUID, and small enough that a payload fragment
/// does not fit. A bound also matters because these values reach metric and log
/// contexts where an unbounded string is its own problem.
pub const MAX_LABEL_BYTES: usize = 256;

/// Longest accepted [`FieldPath`], in bytes, across all segments and separators.
pub const MAX_FIELD_PATH_BYTES: usize = 512;

/// The process-wide scanner used for screening.
///
/// Built once: pattern compilation is the expensive part of
/// [`CredentialScanner::new`], and screening happens once per string per event.
fn screening_scanner() -> &'static CredentialScanner {
    static SCANNER: OnceLock<CredentialScanner> = OnceLock::new();
    SCANNER.get_or_init(CredentialScanner::new)
}

/// Why a caller-supplied string was refused as a record field.
///
/// # No offending text
///
/// No variant carries the rejected input, and none ever should. The whole point
/// of [`FieldRejection::CarriesSensitiveValue`] is that the string held
/// something that must not be written down; embedding it in an error would put
/// it straight into the log line that reports the refusal, which is precisely
/// the tier ADR 0032 §9 keeps it out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldRejection {
    /// The input, or one of a path's segments, was empty.
    Empty,
    /// The input exceeded the type's byte limit.
    TooLong,
    /// The input contained an ASCII control character. Beyond being meaningless
    /// in a path or an identifier, a newline forges record boundaries in any
    /// line-oriented sink downstream.
    ControlCharacter,
    /// The credential scanner recognised something in the input. See the module
    /// documentation for what this does and does not prove.
    CarriesSensitiveValue,
}

impl core::fmt::Display for FieldRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Empty => "must not be empty",
            Self::TooLong => "exceeds the maximum length for this field",
            Self::ControlCharacter => "must not contain ASCII control characters",
            Self::CarriesSensitiveValue => "was refused: it matches a sensitive-data detector",
        };
        f.write_str(message)
    }
}

impl std::error::Error for FieldRejection {}

/// Shape check shared by every guarded string: non-empty, bounded, printable.
pub(super) fn check_shape(candidate: &str, limit: usize) -> Result<(), FieldRejection> {
    if candidate.is_empty() {
        return Err(FieldRejection::Empty);
    }
    if candidate.len() > limit {
        return Err(FieldRejection::TooLong);
    }
    if candidate.chars().any(char::is_control) {
        return Err(FieldRejection::ControlCharacter);
    }
    Ok(())
}

/// Shape check plus a credential scan.
///
/// Used for the strings derived from the inspected request — a field path, an
/// endpoint identifier — as opposed to the system-minted ids
/// [`AuditLabel`] holds. `pub(super)` so [`Endpoint`](super::Endpoint) applies
/// the same rule without a second implementation of it.
pub(super) fn screen(candidate: &str, limit: usize) -> Result<(), FieldRejection> {
    check_shape(candidate, limit)?;
    if !screening_scanner().scan(candidate).is_clean() {
        return Err(FieldRejection::CarriesSensitiveValue);
    }
    Ok(())
}

/// A bounded, printable, system-generated identifier: an event id, a tenant, a
/// team, a trace or correlation id, a policy document id, a rule id.
///
/// Shape-checked, not scanned — see the module documentation for the ULID
/// measurement that decides this.
///
/// # Wire format
///
/// Serializes transparently as a JSON string, so a consumer sees an identifier
/// and not a wrapper object:
///
/// ```json
/// "01HZX9V8ABCDEFGHJKMNPQRSTV"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schemars", schemars(transparent))]
pub struct AuditLabel(String);

impl AuditLabel {
    /// Accept an identifier, or say why not.
    ///
    /// # Errors
    ///
    /// [`FieldRejection::Empty`], [`FieldRejection::TooLong`] past
    /// [`MAX_LABEL_BYTES`], or [`FieldRejection::ControlCharacter`].
    pub fn new(value: impl Into<String>) -> Result<Self, FieldRejection> {
        let value = value.into();
        check_shape(&value, MAX_LABEL_BYTES)?;
        Ok(Self(value))
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for AuditLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The dotted name of an inspected field — `body.customer.national_id` — and
/// never its value.
///
/// ADR 0032 §9 makes the field path the drill-down granularity that everything
/// outside the tamper-evident tier gets, in place of the byte offsets it is not
/// allowed. That makes the path the one string in a record that is both
/// caller-supplied and derived from the inspected request, so it is screened
/// with the credential scanner as well as shape-checked.
///
/// # Wire format
///
/// Serializes transparently as the joined path:
///
/// ```json
/// "body.customer.national_id"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schemars", schemars(transparent))]
pub struct FieldPath(String);

impl FieldPath {
    /// Accept a dotted path, or say why not.
    ///
    /// Every `.`-separated segment must be non-empty, so `body..ssn` and a
    /// leading or trailing `.` are refused: an empty segment would make two
    /// different paths render identically and quietly merge two fields in any
    /// aggregate keyed on the path.
    ///
    /// # Errors
    ///
    /// [`FieldRejection::Empty`] for an empty path or segment,
    /// [`FieldRejection::TooLong`] past [`MAX_FIELD_PATH_BYTES`],
    /// [`FieldRejection::ControlCharacter`], or
    /// [`FieldRejection::CarriesSensitiveValue`] when the scanner recognises
    /// something in the path — which is what a value passed where a name
    /// belongs looks like.
    pub fn parse(path: impl Into<String>) -> Result<Self, FieldRejection> {
        let path = path.into();
        screen(&path, MAX_FIELD_PATH_BYTES)?;
        if path.split('.').any(str::is_empty) {
            return Err(FieldRejection::Empty);
        }
        Ok(Self(path))
    }

    /// The whole path as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path's segments, outermost first.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }

    /// How deeply nested the named field is. Always at least 1.
    pub fn depth(&self) -> usize {
        self.segments().count()
    }
}

impl core::fmt::Display for FieldPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measurement the two-strength split rests on. If the scanner ever
    /// stops flagging a ULID, the reason `AuditLabel` is not screened
    /// evaporates and this module's design should be revisited — so it is
    /// asserted rather than left as a claim in a comment.
    #[test]
    fn a_ulid_is_flagged_by_the_scanner_which_is_why_labels_are_not_screened() {
        assert!(
            !screening_scanner().scan("01HZX9V8ABCDEFGHJKMNPQRSTV").is_clean(),
            "a ULID no longer scans as high-entropy; revisit whether AuditLabel should be screened"
        );
        assert!(AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").is_ok());
    }

    /// The leak this guard exists for: a value passed where a name belongs.
    ///
    /// The literal is a documentation-only example from `aa-security`'s own
    /// test corpus, not a live credential.
    #[test]
    fn a_field_path_carrying_a_token_is_refused() {
        assert_eq!(
            FieldPath::parse("body.ghp_16C7e42F292c6912E7710c838347Ae178B4a"),
            Err(FieldRejection::CarriesSensitiveValue)
        );
    }

    /// The other concrete case: a destination-shaped string with a password in
    /// it. Screening is what forces the caller to record the destination
    /// without the credential.
    #[test]
    fn a_path_holding_a_database_uri_is_refused() {
        assert_eq!(
            FieldPath::parse("config.postgresql://user:password@db.internal:5432/app"),
            Err(FieldRejection::CarriesSensitiveValue)
        );
    }

    #[test]
    fn ordinary_paths_are_accepted() {
        for path in [
            "body",
            "body.customer.national_id",
            "headers.authorization",
            "args[0].url",
        ] {
            assert!(FieldPath::parse(path).is_ok(), "rejected a legitimate path: {path}");
        }
    }

    /// An empty segment would render two distinct paths identically and merge
    /// them in any aggregate keyed on the path.
    #[test]
    fn empty_segments_are_refused() {
        assert_eq!(FieldPath::parse("body..ssn"), Err(FieldRejection::Empty));
        assert_eq!(FieldPath::parse(".body"), Err(FieldRejection::Empty));
        assert_eq!(FieldPath::parse("body."), Err(FieldRejection::Empty));
        assert_eq!(FieldPath::parse(""), Err(FieldRejection::Empty));
    }

    /// A newline forges a record boundary in any line-oriented sink.
    #[test]
    fn control_characters_are_refused_in_both_guarded_types() {
        assert_eq!(
            FieldPath::parse("body\nfake_record"),
            Err(FieldRejection::ControlCharacter)
        );
        assert_eq!(
            AuditLabel::new("tenant\nfake_record"),
            Err(FieldRejection::ControlCharacter)
        );
    }

    #[test]
    fn over_long_input_is_refused() {
        assert_eq!(
            AuditLabel::new("x".repeat(MAX_LABEL_BYTES + 1)),
            Err(FieldRejection::TooLong)
        );
        assert!(AuditLabel::new("x".repeat(MAX_LABEL_BYTES)).is_ok());
        assert_eq!(
            FieldPath::parse("x".repeat(MAX_FIELD_PATH_BYTES + 1)),
            Err(FieldRejection::TooLong)
        );
    }

    /// A rejection must not quote what it rejected: the report of a refusal is
    /// itself a log line, and `CarriesSensitiveValue` means the input is the
    /// thing that must not be logged.
    #[test]
    fn a_rejection_never_echoes_the_offending_input() {
        let secret = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
        let rejection = FieldPath::parse(format!("body.{secret}")).unwrap_err();
        let rendered = alloc::format!("{rejection}");
        assert!(
            !rendered.contains(secret),
            "the rejection message quoted the value it exists to keep out of logs"
        );
        let debugged = alloc::format!("{rejection:?}");
        assert!(!debugged.contains(secret), "the Debug rendering quoted the value");
    }

    #[test]
    fn depth_counts_segments() {
        assert_eq!(FieldPath::parse("body").unwrap().depth(), 1);
        assert_eq!(FieldPath::parse("body.customer.national_id").unwrap().depth(), 3);
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    /// Both guarded types are transparent on the wire: a consumer reads a
    /// string, not `{"0":"…"}`.
    #[test]
    fn guarded_strings_serialize_transparently() {
        let path = FieldPath::parse("body.customer.national_id").unwrap();
        assert_eq!(serde_json::to_string(&path).unwrap(), r#""body.customer.national_id""#);

        let label = AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap();
        assert_eq!(
            serde_json::to_string(&label).unwrap(),
            r#""01HZX9V8ABCDEFGHJKMNPQRSTV""#
        );
    }

    /// Deserialization is the guard's back door, and it is open by design: a
    /// stored record must round-trip even if a future build tightens the rules,
    /// or replaying an audit log would fail on its own history.
    ///
    /// Pinned so the trade-off is a decision on the record rather than a
    /// surprise. It is sound because the guard's job is to stop a value being
    /// *written* into a record; a record being read back was already screened
    /// when it was written.
    #[test]
    fn deserialization_does_not_re_run_the_guard() {
        let path: FieldPath = serde_json::from_str(r#""body..not_constructible_via_parse""#).unwrap();
        assert_eq!(path.as_str(), "body..not_constructible_via_parse");
        assert!(FieldPath::parse(path.as_str()).is_err());
    }
}
