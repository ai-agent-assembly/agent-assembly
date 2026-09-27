//! Redaction by construction: the only string type an execution receipt may
//! hold, and the closed set of field names a withholding may be recorded
//! against.
//!
//! AAASM-6166. Two constructors and no others:
//!
//! * [`ReceiptText::token`] takes a `&'static str` — every `as_str()` method on
//!   `aa_isolation`/`aa_core`'s report vocabulary returns one of these, so
//!   nothing built from a runtime `String` (an argv value, an env value, a
//!   free-text policy-rule reason) can reach this constructor. It is a type-
//!   level argument, not a policy this module has to enforce at runtime.
//! * [`ReceiptText::screened`] takes a runtime `&str` and runs it through
//!   [`contains_credential_material`], returning [`ReceiptText::Withheld`] on a
//!   match.
//!
//! The screen is a floor, not a proof: a `false` result means "nothing
//! matched", not "no secret is here" — `aa_core`'s own docs on
//! `contains_credential_material` are explicit about that limit, and this
//! module does not claim otherwise anywhere. The primary redaction guarantee
//! is structural: no field of `ReceiptBody` holds argv, an environment value, a
//! lease's basis reason, or a scope selector *at all* — those travel as digests
//! and counts (see `project.rs`). The screen is the second line of defense for
//! the few fields that do carry operator-visible free text (a policy source
//! path, an `Inconclusive` detail sentence, a residual policy gap).
use aa_core::integration::fingerprint::contains_credential_material;

/// A string a receipt is allowed to hold.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
#[non_exhaustive]
pub enum ReceiptText {
    /// Built from a `&'static str` an upstream type's own vocabulary returned.
    Token(String),
    /// Screened runtime text that did not match the credential screen.
    Value(String),
    /// Matched the credential screen and was not stored. Nothing about the
    /// original string is here, including its length. The field name this was
    /// withheld from is recorded separately, in
    /// [`super::schema::ReceiptBody::withheld_fields`].
    Withheld,
}

impl ReceiptText {
    /// A token from a closed, upstream `&'static str` vocabulary. Never
    /// screened, because nothing built from a runtime `String` can reach this
    /// constructor — the parameter type is the enforcement.
    pub fn token(token: &'static str) -> Self {
        Self::Token(token.to_string())
    }

    /// Runtime text, screened for credential-shaped content before storage.
    pub fn screened(raw: &str) -> Self {
        if contains_credential_material(raw) {
            Self::Withheld
        } else {
            Self::Value(raw.to_string())
        }
    }

    /// Whether this text was withheld by the credential screen.
    pub fn is_withheld(&self) -> bool {
        matches!(self, Self::Withheld)
    }

    /// The text, when it was not withheld.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Token(s) | Self::Value(s) => Some(s.as_str()),
            Self::Withheld => None,
        }
    }
}

/// Closed set of field names a withholding may be recorded against.
///
/// Every [`ReceiptText::Withheld`] occurrence in a body must appear here (rule
/// R6 in `validate.rs`) — a withholding recorded nowhere is indistinguishable
/// from a field that was simply empty, which is exactly the silent-drop defect
/// this type exists to prevent (mirrors `PriorSettingsState::withheld_keys`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FieldName {
    /// `PolicyBinding::source`.
    PolicySource,
    /// `BackendBinding::provenance_source`.
    BackendProvenance,
    /// `ExecutionOutcome::no_code_detail`.
    ExitDetail,
    /// `DomainOutcome::unmeasured_detail`.
    UnmeasuredDetail,
    /// An entry of `DomainOutcome::residual_policy_gaps`.
    ResidualPolicyGap,
    /// An entry of `DegradedCondition::detail`.
    DegradedDetail,
    /// `run.rs`'s deadline-termination detail carried into
    /// `ExecutionOutcome::termination`.
    EvidenceRefDetail,
    /// `AssertedIdentity::agent_id`.
    AssertedIdentityAgentId,
    /// `AssertedIdentity::team_id`.
    AssertedIdentityTeamId,
    /// An entry of `AssertedIdentity::lineage`.
    AssertedIdentityLineage,
    /// `SpecBinding::working_dir_digest`'s corresponding raw path was never
    /// stored as text, but the field name is still needed when the digest
    /// itself could not be computed (non-UTF-8 handling lives at the CLI
    /// boundary, not here — see `project.rs`).
    WorkingDir,
    /// An entry of `CredentialNames::removed`/`delegated`/`ambient_unremoved`.
    CredentialName,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_benign_string_is_stored_as_value() {
        assert_eq!(
            ReceiptText::screened("hello world"),
            ReceiptText::Value("hello world".to_string())
        );
    }

    #[test]
    fn a_credential_shaped_string_is_withheld() {
        // Synthetic literal matching aa-core's own scanner fixture convention
        // (aa-core/src/integration/fingerprint.rs) — never a real credential
        // shape.
        let secret = "sk-ant-api03-AAASM6166SYNTHETICDONOTUSEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(ReceiptText::screened(secret).is_withheld());
    }

    #[test]
    fn a_token_is_never_screened_even_if_it_would_match() {
        // Impossible to construct with credential-shaped content in practice
        // (the parameter is `&'static str` from upstream vocabulary), but the
        // constructor itself performs no screening — this pins that down.
        let t = ReceiptText::token("sk-ant-not-actually-screened");
        assert!(!t.is_withheld());
    }
}
