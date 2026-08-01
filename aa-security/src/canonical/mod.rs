//! The canonical, provider-neutral sensitive-data finding model (ADR 0032 §2).
//!
//! # Why this exists beside [`crate::scanner`]
//!
//! [`CredentialKind`](crate::scanner::CredentialKind) names *what the built-in
//! scanner detects*. Its variants and their `as_str()` redaction labels are a
//! published contract — pinned by the conformance vectors and served by
//! `GET /api/v1/scrub/patterns` — and ADR 0032 §2 freezes them. That contract is
//! worth keeping, but it makes a poor policy vocabulary: it has no locale
//! dimension, and every new detector is a new variant that every policy naming
//! detectors individually must be rewritten for.
//!
//! The canonical model is a parallel representation over the same findings. It
//! adds nothing to detection and takes nothing away: a canonical finding is
//! *derived* from a scanner finding and carries no information the scanner did
//! not already produce.
//!
//! # The taxonomy
//!
//! A category is a [`CategoryBase`] — the coarse, provider-neutral entity a
//! policy names — optionally narrowed by a [`CategoryQualifier`]. It renders as
//! `BASE` or `BASE[qualifier]`.
//!
//! | Base | Meaning |
//! |---|---|
//! | `API_KEY` | vendor API key for a model or SaaS provider |
//! | `CLOUD_ACCESS_KEY` | cloud access-key identifier |
//! | `CLOUD_SERVICE_ACCOUNT_KEY` | cloud service-account key document |
//! | `CLOUD_CONNECTION_STRING` | cloud connection string with an embedded key |
//! | `ACCESS_TOKEN` | bearer token from an identity or SaaS provider |
//! | `DATABASE_CONNECTION_URI` | database URI, conventionally with a password |
//! | `PRIVATE_KEY` | asymmetric private-key material |
//! | `PAYMENT_CARD_NUMBER` | payment card number |
//! | `EMAIL_ADDRESS` | email address |
//! | `NATIONAL_ID` | government-issued personal identifier |
//! | `TAX_IDENTIFIER` | registration number identifying a business to a tax authority |
//! | `PHONE_NUMBER` | telephone number |
//! | `HIGH_ENTROPY_SECRET` | entropy/encoding heuristic hit of unknown kind |
//! | `POLICY_DEFINED_MATCH` | match from an operator-authored policy pattern |
//!
//! ## How a locale qualifier is expressed
//!
//! A locale qualifier is a BCP-47 language tag, a `/`, and the identifier's
//! local name:
//!
//! ```text
//! NATIONAL_ID[zh-TW/arc_new]      Taiwan residence certificate (2021 format)
//! NATIONAL_ID[en-US/ssn]          US Social Security Number
//! ```
//!
//! The base is what a policy names. `NATIONAL_ID` matches both of the above, so
//! adding a locale pack never requires rewriting a policy — which is the whole
//! reason ADR 0032 §2 requires locale-qualified categories instead of new
//! [`CredentialKind`](crate::scanner::CredentialKind) variants. The qualifier is
//! for attribution and reporting, not for a policy author to have to enumerate.
//!
//! The other qualifier namespace is the **scheme**: a vendor or defining format,
//! a `:`, and the form within it — `ACCESS_TOKEN[github:personal_access]`,
//! `PRIVATE_KEY[pem:rsa]`. The two namespaces use different separators so a
//! rendered category is unambiguous on its own, and so a jurisdiction can never
//! be mistaken for a vendor.
//!
//! ## Stability rules
//!
//! - The rendered form is a contract. Renaming a base or a qualifier is a
//!   breaking change to policy and to the event stream.
//! - A new locale or vendor is a **new qualifier under an existing base**, never
//!   a new base and never a new `CredentialKind` variant.
//! - A new base is warranted only for an entity none of the existing bases
//!   describes.
//!
//! # What a canonical finding may not carry
//!
//! [`CanonicalFinding`] has no owned-`String` field at all: category and
//! provenance are built from `&'static str`, and everything else is an enum or
//! a byte offset. A raw matched value is therefore **not produced by any
//! construction path in this crate** — the lift builds category and provenance
//! from compiled-in constants only, never from the bytes it scanned, which is
//! the same guarantee [`CredentialFinding`](crate::scanner::CredentialFinding)
//! gives by storing the redaction label instead of the match (ADR 0032 §9,
//! validation requirement 9).
//!
//! It is *not* unrepresentable, and the difference matters. `Box::leak` turns
//! arbitrary runtime bytes into a `&'static str` in safe stable Rust, so a
//! caller can put a secret in a qualifier or a version string if it sets out to
//! — see the note on [`CategoryQualifier`]. The guarantee is about what this
//! crate constructs, not about what the types forbid.
//!
//! There is no `Deserialize`, so a canonical finding is never reconstructed
//! from bytes — it is always derived from something this process detected.
//! `Serialize` is provided (under the `serde` feature) because emitting
//! findings outward is what the event and metric layers need.
//!
//! # What this model does *not* guarantee
//!
//! Stated plainly, because an earlier draft of these docs overclaimed and the
//! overclaim was wrong in a way that mattered.
//!
//! **It is not an authenticity boundary.** A [`CanonicalFinding`] records what
//! a value *claims*, not that a recognizer really produced it. `Provenance` is
//! stamped by whoever constructs the finding, and while [`Recognizer`] is a
//! closed enum — so an identity cannot be invented from runtime bytes — nothing
//! stops in-process code from stamping `BuiltinScanner` on a finding the
//! scanner never produced.
//!
//! **Absence of `Deserialize` here does not make the model unreachable from a
//! wire.** [`CredentialFinding`](crate::scanner::CredentialFinding) *does*
//! derive `Deserialize` under the same feature, with its `end` field skipped,
//! so a finding rebuilt from JSON arrives with a zero end offset. That is why
//! lifting is `TryFrom` rather than `From`: the span is validated instead of
//! trusted. The check is well-formedness, not provenance — a well-formed
//! forgery is indistinguishable, and no v1 path needs it to be otherwise.
//!
//! **ADR 0032 validation requirement 10 is not what these types satisfy.** That
//! requirement is about no out-of-process provider being reachable from a
//! synchronous enforcement path, which holds here trivially because D-1 means
//! no provider exists. The type-level choices above are worth making on their
//! own merits; they are not a discharge of requirement 10.

mod category;
mod finding;
mod lift;
mod mapping;
#[cfg(feature = "serde")]
mod serde_impls;

pub use category::{CanonicalCategory, CategoryBase, CategoryQualifier};
pub use finding::{
    ByteSpan, CanonicalFinding, ConfidenceBand, DetectionMethod, FindingStatus, Provenance, Recognizer, Severity,
};
pub use lift::{LiftError, POLICY_REGEX_PROVENANCE, SCANNER_PROVENANCE};
pub use mapping::ParseCategoryError;
