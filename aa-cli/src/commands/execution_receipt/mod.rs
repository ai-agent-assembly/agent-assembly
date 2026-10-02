//! Sealed execution receipts (AAASM-6166, ADR 0035 amendment, parent Epic
//! AAASM-6159).
//!
//! # What a holding seal establishes
//!
//! The receipt [`schema::ReceiptBody`] has not changed since it was written,
//! and the canonical form it was digested under
//! ([`canonical::CANONICAL_FORM`]) is the one this build reads.
//!
//! # What it does not establish
//!
//! * **Origin.** Nothing signs a receipt. [`schema::ReceiptSeal`] is a content
//!   digest — `sha256` over [`canonical::canonical_json`] of the body — not a
//!   MAC and not a signature. There is no key anywhere in this design: an
//!   attacker with the same host UID that wrote the receipt can recompute the
//!   same digest over a rewritten body just as easily as this code can, so a
//!   holding seal is *tamper-since-write detection*, not proof that `aasm`
//!   produced it. A MAC was considered and rejected for the same reason:
//!   whatever key the writer held to compute one, an attacker with this UID
//!   holds too, so an HMAC here would buy nothing an unkeyed digest does not
//!   already provide. A MAC or signature earns something only when the
//!   verifier holds a key the writer's host does not — that is a SaaS
//!   ingestion design, explicitly out of scope for this ticket. Compare
//!   `aa_core::integration::store`'s own receipts, which make exactly this
//!   same claim about their own `integrity_of` hash: "corruption detection,
//!   not tamper prevention... not a MAC".
//! * **The identity of the agent the run is attributed to.**
//!   [`schema::AssertedIdentity`] is named `asserted_*` precisely so no reader
//!   mistakes the seal for identity verification — `aa_isolation::IdentityRef`
//!   documents this residual (a caller-supplied reference, not authenticated
//!   by anything in that crate) and nothing here closes it.
//! * **What the seal covers.** The seal digests [`schema::ReceiptBody`] only.
//!   [`schema::ReceiptEnvelope::schema`] and every field of
//!   [`schema::ReceiptSeal`] itself (`sealed_by`, `sealed_at_unix_secs`,
//!   `canonical_form`) sit *outside* the digest and are freely mutable without
//!   producing a mismatch. This is benign today — mutating `schema` produces
//!   [`validate::ReceiptDefect::UnknownSchema`], and only one
//!   `canonical_form` value exists — but it is a real boundary, not a
//!   theoretical one, and [`verify::verify`] is the seam that closes it: it
//!   always runs both the seal check *and* [`validate::defects`], and a
//!   receipt that verifies must pass both.
//! * **That any property recorded as unmeasured actually held.** A domain
//!   whose [`schema::DomainOutcome::evidence_basis`] is anything short of
//!   `decision` cannot carry a prevention claim — [`validate`]'s rules R1–R5
//!   enforce this only at `verify()` time (construction never calls
//!   [`validate::defects`]), so a hand-built receipt with a freshly
//!   recomputed, holding seal still fails `verify()` if it asserts more than
//!   its own evidence supports.
//!
//! A receipt that does not verify (holding seal *and* zero defects) is never
//! acted on by anything reading it.
//!
//! # Why a content digest, never a signature
//!
//! This is a **final, reviewed design decision for this ticket** — see the
//! AAASM-6166 ADR 0035 amendment for the full rationale. Real cryptographic
//! signing needs a key-custody decision and a verifier that does not share the
//! writer's host UID; neither exists for local-first `aasm run`. The word
//! "signature" and the word "signed" do not appear anywhere in this module's
//! types, CLI output, or documentation except in a sentence stating what this
//! is **not**.
//!
//! # Scope
//!
//! Lives inside `aa-cli` rather than as its own crate: nothing outside
//! `aasm run` produces a receipt and nothing outside `aasm receipt verify`
//! reads one (verified: `aa-workspace-tx` has zero consumers via
//! `grep -rln aa-workspace-tx --include=Cargo.toml .`, the one orphan-crate
//! precedent this campaign already produced and does not repeat here). Every
//! file under this module is inside the `devtool` strip-for-publish fence —
//! nothing published to crates.io emits or reads a receipt.
pub mod canonical;
pub mod host;
pub mod inspect;
pub mod project;
pub mod schema;
pub mod store;
pub mod text;
pub mod validate;
pub mod verify;

pub use canonical::{CanonicalError, Digest, CANONICAL_FORM};
pub use inspect::{InspectArgs, RefusalReason};
pub use project::{body_for_run, ReceiptContext, TerminationInput};
pub use schema::{ReceiptBody, ReceiptEnvelope, ReceiptSeal, ReceiptSealKind, RECEIPT_SCHEMA};
pub use store::{ReceiptStore, StoreError};
pub use text::{FieldName, ReceiptText};
pub use validate::ReceiptDefect;
pub use verify::{dispatch, verify, verify_path, ReceiptArgs, SealVerdict, Verification};
