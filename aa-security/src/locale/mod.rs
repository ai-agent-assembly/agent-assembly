//! Deterministic, locale-specific recognizer packs (ADR 0032 §2, AAASM-5353).
//!
//! # Why these are not [`CredentialKind`](crate::scanner::CredentialKind)s
//!
//! ADR 0032 §2 freezes `CredentialKind::ALL`: it is a published wire contract
//! served by `GET /api/v1/scrub/patterns`, and every jurisdiction added as a
//! variant would grow it without bound while forcing a rewrite of any policy
//! that names detectors individually. A locale pack therefore produces
//! [`CanonicalFinding`](crate::canonical::CanonicalFinding)s directly, carrying
//! a locale-qualified category under a base a policy already names —
//! `NATIONAL_ID[zh-TW/arc_new]` is matched by a rule that says `NATIONAL_ID`.
//!
//! The consequence to keep in mind is that these findings have **no
//! `CredentialKind` and no `[REDACTED:<kind>]` label**. They redact to the
//! opaque `[REDACTED]`, because inventing a label would publish a pattern name
//! the frozen catalogue does not list.
//!
//! # Why this is a separate entry point from [`crate::scanner`]
//!
//! [`CredentialScanner::scan`](crate::scanner::CredentialScanner::scan) returns
//! `CredentialFinding`s, which cannot express these categories. Rather than
//! widen that type — and with it the conformance behaviour of 34 committed
//! vectors — a pack is a free function over the same text. `scan` is byte-for-
//! byte unaffected by anything in this module, which is what makes ADR 0015's
//! "existing vectors stay byte-identical" hold trivially rather than by
//! inspection.
//!
//! # What a deterministic pack is, and what it is not
//!
//! Every recognizer here is arithmetic and structure: a checksum, a closed
//! letter table, a fixed digit count, or an area-code gazetteer. There is no
//! model, no network call and no new dependency, which is what lets the same
//! code run in the in-process SDK layer and in WASM.
//!
//! It is not, and cannot be, precise. A checksum over a short numeric domain
//! admits a fixed fraction of random strings, and a phone number has no
//! checksum at all. The residuals are stated per recognizer in
//! [`zh_tw`]'s documentation rather than left for an operator to discover, and
//! they are the reason the packs report a
//! [`ConfidenceBand`](crate::canonical::ConfidenceBand) instead of claiming
//! certainty.

pub mod zh_tw;
