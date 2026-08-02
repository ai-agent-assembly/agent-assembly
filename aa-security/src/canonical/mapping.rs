//! The lossless 1:1 mapping between [`CredentialKind`] and [`CanonicalCategory`].
//!
//! The two `match`es below *are* the taxonomy table; a prose copy of them would
//! only rot. What is worth stating is why they are shaped the way they are.
//!
//! **Forward is exhaustive, reverse is fallible.** Adding a `CredentialKind`
//! variant fails to compile until it is given a category, so a detector cannot
//! silently drop out of the canonical model. The reverse direction returns
//! `Option` because it is genuinely partial and will become more so: the locale
//! packs B-7 adds — `NATIONAL_ID[zh-TW/arc_new]` and its siblings — have no
//! `CredentialKind` and never will, because ADR 0032 §2 freezes
//! `CredentialKind::ALL`. A caller must decide what to do with `None` rather
//! than receive a plausible-looking wrong answer.
//!
//! **Every one of the 28 variants gets a distinct category**, which is what
//! makes the mapping lossless. Where a base alone would collide — five GitHub
//! token kinds are all `ACCESS_TOKEN`, five PEM kinds are all `PRIVATE_KEY` —
//! a scheme qualifier separates them, so no information is lost by round-tripping
//! through the canonical model.
//!
//! **`SsnPattern` becomes `NATIONAL_ID[en-US/ssn]`**, not an `SSN` base. The US
//! Social Security Number is a jurisdiction's national identifier and nothing
//! more special than that; giving it the locale-qualified shape now means the
//! Taiwanese identifiers land beside it under a policy handle that already
//! exists, which is the entire argument of ADR 0032 §2.

use super::category::{CanonicalCategory, CategoryBase as Base, CategoryQualifier as Qual};
use crate::scanner::CredentialKind;

impl CanonicalCategory {
    /// Every category this build can produce.
    ///
    /// The catalogue is the parse domain and the round-trip domain. It exists
    /// because those are **not** the same as "every category derivable from a
    /// `CredentialKind`": ADR 0032 §2 freezes `CredentialKind::ALL`, so the
    /// locale packs AAASM-5353 adds have no kind by design, yet a live
    /// recognizer will emit them and something downstream must parse them back.
    ///
    /// AAASM-5353 extends this list with the six zh-TW locale categories at the
    /// end. `every_credential_kind_category_is_in_all` keeps the first 28 honest
    /// in the direction the compiler cannot; `every_zh_tw_category_is_in_all`
    /// does the same for the six, which need it more — they have no
    /// `CredentialKind` and therefore no exhaustiveness-checked forward mapping
    /// at all, so a category that exists, renders fine, is emitted by a live
    /// recognizer and then fails to parse in the same build is exactly the
    /// silent failure this list prevents.
    pub const ALL: &'static [CanonicalCategory] = &[
        Self::with_scheme(Base::ApiKey, "anthropic", "key"),
        Self::with_scheme(Base::ApiKey, "openai", "key"),
        Self::with_scheme(Base::CloudAccessKey, "aws", "access_key_id"),
        Self::with_scheme(Base::CloudServiceAccountKey, "gcp", "service_account_json"),
        Self::with_scheme(Base::CloudConnectionString, "azure", "storage"),
        Self::with_scheme(Base::AccessToken, "github", "app_installation"),
        Self::with_scheme(Base::AccessToken, "github", "oauth"),
        Self::with_scheme(Base::AccessToken, "github", "personal_access"),
        Self::with_scheme(Base::AccessToken, "github", "refresh"),
        Self::with_scheme(Base::AccessToken, "github", "user_to_server"),
        Self::with_scheme(Base::AccessToken, "slack", "app_level"),
        Self::with_scheme(Base::AccessToken, "slack", "bot"),
        Self::with_scheme(Base::AccessToken, "slack", "oauth"),
        Self::with_scheme(Base::AccessToken, "slack", "refresh"),
        Self::with_scheme(Base::AccessToken, "slack", "user"),
        Self::with_scheme(Base::DatabaseConnectionUri, "mongodb", "uri"),
        Self::with_scheme(Base::DatabaseConnectionUri, "mysql", "uri"),
        Self::with_scheme(Base::DatabaseConnectionUri, "postgresql", "uri"),
        Self::with_scheme(Base::PrivateKey, "pem", "ec"),
        Self::with_scheme(Base::PrivateKey, "pem", "openssh"),
        Self::with_scheme(Base::PrivateKey, "pem", "pgp"),
        Self::with_scheme(Base::PrivateKey, "pem", "pkcs8"),
        Self::with_scheme(Base::PrivateKey, "pem", "rsa"),
        Self::unqualified(Base::PaymentCardNumber),
        Self::unqualified(Base::EmailAddress),
        Self::with_locale(Base::NationalId, "en-US", "ssn"),
        Self::unqualified(Base::HighEntropySecret),
        Self::unqualified(Base::PolicyDefinedMatch),
        // AAASM-5353 — the zh-TW deterministic pack. No `CredentialKind`, by
        // design: ADR 0032 §2 freezes `CredentialKind::ALL`, so these reach the
        // model only through `crate::locale::zh_tw`, and `to_credential_kind`
        // correctly answers `None` for every one of them.
        Self::with_locale(Base::NationalId, "zh-TW", "national_id"),
        Self::with_locale(Base::NationalId, "zh-TW", "arc_new"),
        Self::with_locale(Base::NationalId, "zh-TW", "arc_legacy"),
        Self::with_locale(Base::TaxIdentifier, "zh-TW", "business_id"),
        Self::with_locale(Base::PhoneNumber, "zh-TW", "mobile"),
        Self::with_locale(Base::PhoneNumber, "zh-TW", "landline"),
    ];

    /// The canonical category for a scanner detector kind.
    ///
    /// Total and exhaustive: every [`CredentialKind`] has exactly one category,
    /// and the mapping is injective, so
    /// [`to_credential_kind`](CanonicalCategory::to_credential_kind) recovers
    /// the original kind.
    pub const fn from_credential_kind(kind: &CredentialKind) -> Self {
        match kind {
            // API keys — the vendor is the scheme, so a policy naming `API_KEY`
            // keeps matching when another model vendor is added.
            CredentialKind::AnthropicKey => Self::with_scheme(Base::ApiKey, "anthropic", "key"),
            CredentialKind::OpenAiKey => Self::with_scheme(Base::ApiKey, "openai", "key"),

            // Cloud credentials.
            CredentialKind::AwsAccessKey => Self::with_scheme(Base::CloudAccessKey, "aws", "access_key_id"),
            CredentialKind::GcpServiceAccount => {
                Self::with_scheme(Base::CloudServiceAccountKey, "gcp", "service_account_json")
            }
            CredentialKind::AzureConnectionString => Self::with_scheme(Base::CloudConnectionString, "azure", "storage"),

            // Auth tokens. Ten kinds across two vendors collapse to one base:
            // `ACCESS_TOKEN` is what a policy should have to name.
            CredentialKind::GitHubAppToken => Self::with_scheme(Base::AccessToken, "github", "app_installation"),
            CredentialKind::GitHubOAuthToken => Self::with_scheme(Base::AccessToken, "github", "oauth"),
            CredentialKind::GitHubPat => Self::with_scheme(Base::AccessToken, "github", "personal_access"),
            CredentialKind::GitHubRefreshToken => Self::with_scheme(Base::AccessToken, "github", "refresh"),
            CredentialKind::GitHubUserToken => Self::with_scheme(Base::AccessToken, "github", "user_to_server"),
            CredentialKind::SlackAppToken => Self::with_scheme(Base::AccessToken, "slack", "app_level"),
            CredentialKind::SlackBotToken => Self::with_scheme(Base::AccessToken, "slack", "bot"),
            CredentialKind::SlackOAuthToken => Self::with_scheme(Base::AccessToken, "slack", "oauth"),
            CredentialKind::SlackRefreshToken => Self::with_scheme(Base::AccessToken, "slack", "refresh"),
            CredentialKind::SlackUserToken => Self::with_scheme(Base::AccessToken, "slack", "user"),

            // Database URIs — the engine is the scheme, matching the URI scheme
            // the detector keys off.
            CredentialKind::MongodbUrl => Self::with_scheme(Base::DatabaseConnectionUri, "mongodb", "uri"),
            CredentialKind::MysqlUrl => Self::with_scheme(Base::DatabaseConnectionUri, "mysql", "uri"),
            CredentialKind::PostgresUrl => Self::with_scheme(Base::DatabaseConnectionUri, "postgresql", "uri"),

            // Private keys. `pem` is the scheme because the PEM header is what
            // the detector matches and what distinguishes the five kinds.
            CredentialKind::EcPrivateKey => Self::with_scheme(Base::PrivateKey, "pem", "ec"),
            CredentialKind::OpensshPrivateKey => Self::with_scheme(Base::PrivateKey, "pem", "openssh"),
            CredentialKind::PgpPrivateKey => Self::with_scheme(Base::PrivateKey, "pem", "pgp"),
            CredentialKind::PrivateKey => Self::with_scheme(Base::PrivateKey, "pem", "pkcs8"),
            CredentialKind::RsaPrivateKey => Self::with_scheme(Base::PrivateKey, "pem", "rsa"),

            // PII. `CreditCardLuhn` names its validation method; the canonical
            // category names the entity, which is what a policy cares about.
            CredentialKind::CreditCardLuhn => Self::unqualified(Base::PaymentCardNumber),
            CredentialKind::EmailAddress => Self::unqualified(Base::EmailAddress),
            CredentialKind::SsnPattern => Self::with_locale(Base::NationalId, "en-US", "ssn"),

            // Backstops.
            CredentialKind::GenericHighEntropy => Self::unqualified(Base::HighEntropySecret),
            CredentialKind::Custom => Self::unqualified(Base::PolicyDefinedMatch),
        }
    }

    /// The scanner detector kind this category came from, if any.
    ///
    /// `None` means the category has no `CredentialKind` — which is the normal
    /// case for a locale pack, not an error. It is deliberately not defaulted to
    /// a catch-all kind: a caller that needs a redaction label must handle the
    /// absence explicitly and fail closed, never emit a label that names the
    /// wrong detector (ADR 0032 §5, validation requirement 8).
    pub fn to_credential_kind(&self) -> Option<CredentialKind> {
        let kind = match (self.base(), self.qualifier()) {
            (Base::ApiKey, Some(Qual::Scheme { scheme, variant })) => match (scheme, variant) {
                ("anthropic", "key") => CredentialKind::AnthropicKey,
                ("openai", "key") => CredentialKind::OpenAiKey,
                _ => return None,
            },
            (
                Base::CloudAccessKey,
                Some(Qual::Scheme {
                    scheme: "aws",
                    variant: "access_key_id",
                }),
            ) => CredentialKind::AwsAccessKey,
            (
                Base::CloudServiceAccountKey,
                Some(Qual::Scheme {
                    scheme: "gcp",
                    variant: "service_account_json",
                }),
            ) => CredentialKind::GcpServiceAccount,
            (
                Base::CloudConnectionString,
                Some(Qual::Scheme {
                    scheme: "azure",
                    variant: "storage",
                }),
            ) => CredentialKind::AzureConnectionString,
            (Base::AccessToken, Some(Qual::Scheme { scheme, variant })) => match (scheme, variant) {
                ("github", "app_installation") => CredentialKind::GitHubAppToken,
                ("github", "oauth") => CredentialKind::GitHubOAuthToken,
                ("github", "personal_access") => CredentialKind::GitHubPat,
                ("github", "refresh") => CredentialKind::GitHubRefreshToken,
                ("github", "user_to_server") => CredentialKind::GitHubUserToken,
                ("slack", "app_level") => CredentialKind::SlackAppToken,
                ("slack", "bot") => CredentialKind::SlackBotToken,
                ("slack", "oauth") => CredentialKind::SlackOAuthToken,
                ("slack", "refresh") => CredentialKind::SlackRefreshToken,
                ("slack", "user") => CredentialKind::SlackUserToken,
                _ => return None,
            },
            (Base::DatabaseConnectionUri, Some(Qual::Scheme { scheme, variant: "uri" })) => match scheme {
                "mongodb" => CredentialKind::MongodbUrl,
                "mysql" => CredentialKind::MysqlUrl,
                "postgresql" => CredentialKind::PostgresUrl,
                _ => return None,
            },
            (Base::PrivateKey, Some(Qual::Scheme { scheme: "pem", variant })) => match variant {
                "ec" => CredentialKind::EcPrivateKey,
                "openssh" => CredentialKind::OpensshPrivateKey,
                "pgp" => CredentialKind::PgpPrivateKey,
                "pkcs8" => CredentialKind::PrivateKey,
                "rsa" => CredentialKind::RsaPrivateKey,
                _ => return None,
            },
            (Base::PaymentCardNumber, None) => CredentialKind::CreditCardLuhn,
            (Base::EmailAddress, None) => CredentialKind::EmailAddress,
            (
                Base::NationalId,
                Some(Qual::Locale {
                    tag: "en-US",
                    variant: "ssn",
                }),
            ) => CredentialKind::SsnPattern,
            (Base::HighEntropySecret, None) => CredentialKind::GenericHighEntropy,
            (Base::PolicyDefinedMatch, None) => CredentialKind::Custom,
            _ => return None,
        };
        Some(kind)
    }

    /// The `[REDACTED:…]` label a finding in this category redacts to.
    ///
    /// For a category that maps back to a [`CredentialKind`] this reproduces
    /// that kind's published label exactly, so the canonical model can drive
    /// redaction without moving the frozen label contract (ADR 0032 §2).
    ///
    /// For a category with no `CredentialKind` — every B-7 locale category —
    /// it returns the opaque `[REDACTED]`, the same sentinel
    /// [`ScanResult::redact`](crate::scanner::ScanResult::redact) already emits
    /// when it cannot prove a flagged region was removed. Two things it
    /// deliberately does not do: return nothing, which would degrade an
    /// unmappable finding into a clean result (ADR 0032 §5, forbidden design
    /// #2), and invent a `[REDACTED:<category>]` label, which would publish a
    /// pattern name that `GET /api/v1/scrub/patterns` does not list and so
    /// extend the frozen catalogue by accident.
    pub fn redaction_label(&self) -> String {
        match self.to_credential_kind() {
            Some(kind) => format!("[REDACTED:{}]", kind.as_str()),
            None => "[REDACTED]".to_string(),
        }
    }
}

/// Why a string is not the rendered form of a category this build knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseCategoryError {
    /// The string does not render any category in this build's catalogue.
    ///
    /// The right answer for a category a *newer* build produced — a 5353 locale
    /// category read by a reader that predates it — because the alternative is
    /// fabricating one whose meaning this build does not know (ADR 0032 §5: an
    /// unusable input is a recorded failure, never a clean result).
    ///
    /// It deliberately carries **no recognised base**, even though the base of
    /// `NATIONAL_ID[zh-TW/arc_new]` is legible to a build that has never heard
    /// of that locale, and even though the base is the level policy matches on.
    /// Handing back a base would let an older dashboard route a newer finding,
    /// which is a real cost — but it would also let a *decision* path act on a
    /// category it cannot fully interpret, and the qualifier is not decoration:
    /// a locale can change what a finding means. Degrading to a partial
    /// category is how a confident-looking wrong answer gets made, and ADR 0032
    /// §5 exists to stop exactly that.
    ///
    /// The read path that genuinely wants this is display, not enforcement, and
    /// it should ask for it explicitly rather than receive it as a fallback.
    /// That belongs with AAASM-5355, which owns the dashboard projection and
    /// can add a `parse_base` whose name says it is doing something weaker.
    UnknownCategory,
}

impl core::fmt::Display for ParseCategoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not a category known to this build")
    }
}

impl std::error::Error for ParseCategoryError {}

impl std::str::FromStr for CanonicalCategory {
    type Err = ParseCategoryError;

    /// Parse a rendered category back.
    ///
    /// `Display` and this are inverse over every category in this build's
    /// catalogue ([`CanonicalCategory::ALL`]), which is what makes the rendered
    /// form a contract rather than a debug string — B-9's events and the
    /// dashboard have to read it back.
    ///
    /// Deliberately a **closed** lookup over that catalogue rather than
    /// a grammar-driven parse. A parser that split on the separators would have
    /// to conjure `&'static str` fields out of runtime bytes, which means
    /// `Box::leak`, which would reintroduce exactly the hole the qualifier type
    /// exists to close: an arbitrary attacker-chosen string becoming a category.
    /// Resolving against categories that already exist cannot do that.
    ///
    /// The separator rule (`/` locale, `:` scheme) is what makes the rendering
    /// injective, and `is_well_formed_field` enforces it at construction; the
    /// round-trip test over all 28 is what demonstrates it.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Compared without allocating: `renders_as` writes into a stack buffer
        // via `fmt::Write`, so parsing an event stream does not allocate 28
        // `String`s per record (AAASM-5355/5359 ingest this at volume).
        Self::ALL
            .iter()
            .copied()
            .find(|category| category.renders_as(s))
            .ok_or(ParseCategoryError::UnknownCategory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CategoryQualifier;
    use crate::canonical::{CanonicalFinding, ConfidenceBand, DetectionMethod, FindingStatus, Severity};

    /// Every `CredentialKind`, including the `Custom` variant that
    /// [`CredentialKind::ALL`] deliberately excludes.
    ///
    /// `ALL` is the catalogue of *built-in detectors*, so `Custom` is correctly
    /// absent from it — but `Custom` is still a kind the scanner emits, and it
    /// must round-trip like any other. Iterating `ALL.chain(Custom)` is the same
    /// shape the exhaustiveness guard in `scanner.rs` uses.
    fn every_kind() -> impl Iterator<Item = CredentialKind> {
        CredentialKind::ALL
            .iter()
            .cloned()
            .chain(std::iter::once(CredentialKind::Custom))
    }

    /// The round-trip property, checked over the whole domain rather than a
    /// sample of it: the domain is 28 values, so exhaustive enumeration is both
    /// cheaper and stronger than random generation.
    ///
    /// A newly added `CredentialKind` variant cannot escape this. The forward
    /// `match` is exhaustive so it will not compile without a category, and
    /// this test then requires that category to be reachable in reverse — which
    /// is what catches a variant given a category that collides with, or is
    /// unreadable by, `to_credential_kind`.
    #[test]
    fn every_credential_kind_round_trips_through_its_canonical_category() {
        for kind in every_kind() {
            let category = CanonicalCategory::from_credential_kind(&kind);
            assert_eq!(
                category.to_credential_kind(),
                Some(kind.clone()),
                "{} → {category} did not round-trip",
                kind.as_str()
            );
        }
    }

    /// Losslessness has a second half: the mapping must be injective. Two kinds
    /// sharing a category would round-trip only for whichever one the reverse
    /// `match` happened to name first, and would silently relabel the other.
    #[test]
    fn no_two_credential_kinds_share_a_canonical_category() {
        let mut seen: std::collections::BTreeMap<String, &'static str> = std::collections::BTreeMap::new();
        for kind in every_kind() {
            let rendered = CanonicalCategory::from_credential_kind(&kind).to_string();
            if let Some(other) = seen.insert(rendered.clone(), kind.as_str()) {
                panic!("{} and {} both map to {rendered}", other, kind.as_str());
            }
        }
        assert_eq!(
            seen.len(),
            28,
            "expected 28 distinct categories, one per CredentialKind"
        );
    }

    /// The label a category redacts to must reproduce the frozen published one
    /// where a kind exists, and must fail closed where none does.
    ///
    /// The second half is the one worth a test. An unmappable finding that
    /// produced no label would be indistinguishable from a clean scan by the
    /// time it reached a caller, which is forbidden design #2; one that
    /// produced `[REDACTED:NATIONAL_ID[zh-TW/arc_new]]` would publish a pattern
    /// name absent from `GET /api/v1/scrub/patterns`.
    #[test]
    fn a_category_with_no_detector_redacts_to_the_opaque_label_not_to_nothing() {
        let taiwan_arc = CanonicalCategory::with_locale(Base::NationalId, "zh-TW", "arc_new");
        assert_eq!(taiwan_arc.redaction_label(), "[REDACTED]");

        for kind in every_kind() {
            assert_eq!(
                CanonicalCategory::from_credential_kind(&kind).redaction_label(),
                format!("[REDACTED:{}]", kind.as_str()),
                "canonical redaction label diverged from the frozen label for {}",
                kind.as_str()
            );
        }
    }

    /// A category that no built-in detector produces has no `CredentialKind`,
    /// and the reverse mapping must say so rather than guess. This is the shape
    /// every B-7 locale category will have.
    #[test]
    fn a_category_with_no_detector_maps_back_to_none() {
        let taiwan_arc = CanonicalCategory::with_locale(Base::NationalId, "zh-TW", "arc_new");
        assert_eq!(taiwan_arc.to_credential_kind(), None);
        assert_eq!(taiwan_arc.to_string(), "NATIONAL_ID[zh-TW/arc_new]");

        // Same base as a kind we do detect, so this also pins that the reverse
        // mapping discriminates on the qualifier and not on the base alone.
        assert_eq!(
            CanonicalCategory::with_locale(Base::NationalId, "en-US", "ssn").to_credential_kind(),
            Some(CredentialKind::SsnPattern)
        );
    }

    /// The rendered form of every category, pinned.
    ///
    /// ADR 0032 §2 makes the taxonomy the vocabulary policies and events are
    /// written in, so a rename is a breaking change to both — and unlike a
    /// `CredentialKind` rename, which the conformance vectors catch, nothing
    /// else in the tree would notice. This table is that alarm. It is also the
    /// most readable form of the mapping: reviewing a change to the taxonomy
    /// means reviewing the diff of this list.
    #[test]
    fn every_category_renders_to_its_pinned_form() {
        const EXPECTED: &[(&str, &str)] = &[
            ("AnthropicKey", "API_KEY[anthropic:key]"),
            ("AwsAccessKey", "CLOUD_ACCESS_KEY[aws:access_key_id]"),
            (
                "GcpServiceAccount",
                "CLOUD_SERVICE_ACCOUNT_KEY[gcp:service_account_json]",
            ),
            ("OpenAiKey", "API_KEY[openai:key]"),
            ("AzureConnectionString", "CLOUD_CONNECTION_STRING[azure:storage]"),
            ("GitHubAppToken", "ACCESS_TOKEN[github:app_installation]"),
            ("GitHubOAuthToken", "ACCESS_TOKEN[github:oauth]"),
            ("GitHubPat", "ACCESS_TOKEN[github:personal_access]"),
            ("GitHubRefreshToken", "ACCESS_TOKEN[github:refresh]"),
            ("GitHubUserToken", "ACCESS_TOKEN[github:user_to_server]"),
            ("SlackAppToken", "ACCESS_TOKEN[slack:app_level]"),
            ("SlackBotToken", "ACCESS_TOKEN[slack:bot]"),
            ("SlackOAuthToken", "ACCESS_TOKEN[slack:oauth]"),
            ("SlackRefreshToken", "ACCESS_TOKEN[slack:refresh]"),
            ("SlackUserToken", "ACCESS_TOKEN[slack:user]"),
            ("MongodbUrl", "DATABASE_CONNECTION_URI[mongodb:uri]"),
            ("MysqlUrl", "DATABASE_CONNECTION_URI[mysql:uri]"),
            ("PostgresUrl", "DATABASE_CONNECTION_URI[postgresql:uri]"),
            ("EcPrivateKey", "PRIVATE_KEY[pem:ec]"),
            ("OpensshPrivateKey", "PRIVATE_KEY[pem:openssh]"),
            ("PgpPrivateKey", "PRIVATE_KEY[pem:pgp]"),
            ("PrivateKey", "PRIVATE_KEY[pem:pkcs8]"),
            ("RsaPrivateKey", "PRIVATE_KEY[pem:rsa]"),
            ("CreditCardLuhn", "PAYMENT_CARD_NUMBER"),
            ("EmailAddress", "EMAIL_ADDRESS"),
            ("SsnPattern", "NATIONAL_ID[en-US/ssn]"),
            ("GenericHighEntropy", "HIGH_ENTROPY_SECRET"),
            ("Custom", "POLICY_DEFINED_MATCH"),
        ];

        let rendered: Vec<(String, String)> = every_kind()
            .map(|k| {
                (
                    k.as_str().to_string(),
                    CanonicalCategory::from_credential_kind(&k).to_string(),
                )
            })
            .collect();
        let expected: Vec<(String, String)> = EXPECTED
            .iter()
            .map(|(k, c)| ((*k).to_string(), (*c).to_string()))
            .collect();
        assert_eq!(rendered, expected);
    }

    /// Severity, confidence, method and status for all 28 kinds, pinned.
    ///
    /// These four fields had no coverage at all. Every one of these mutations
    /// passed the entire suite: severity forced to `Low`, `GenericHighEntropy`'s
    /// method changed to `Nlp`, its confidence raised to `High` (which also
    /// flips `status` to `Confirmed`). They are exactly the fields B-9 will put
    /// into events and that operators will read in a false-positive report, so
    /// an unnoticed change to them is a silent change to what those reports say.
    ///
    /// `status` is included because it is derived from confidence rather than
    /// stored, so a change to the confidence table moves it without any line of
    /// the status code being touched.
    #[test]
    fn every_kind_has_its_pinned_severity_confidence_method_and_status() {
        const EXPECTED: &[(&str, &str, &str, &str, &str)] = &[
            ("AnthropicKey", "critical", "high", "deterministic", "confirmed"),
            ("AwsAccessKey", "critical", "high", "deterministic", "confirmed"),
            ("GcpServiceAccount", "critical", "high", "deterministic", "confirmed"),
            ("OpenAiKey", "critical", "high", "deterministic", "confirmed"),
            (
                "AzureConnectionString",
                "critical",
                "high",
                "deterministic",
                "confirmed",
            ),
            ("GitHubAppToken", "critical", "high", "deterministic", "confirmed"),
            ("GitHubOAuthToken", "critical", "high", "deterministic", "confirmed"),
            ("GitHubPat", "critical", "high", "deterministic", "confirmed"),
            ("GitHubRefreshToken", "critical", "high", "deterministic", "confirmed"),
            ("GitHubUserToken", "critical", "high", "deterministic", "confirmed"),
            ("SlackAppToken", "critical", "high", "deterministic", "confirmed"),
            ("SlackBotToken", "critical", "high", "deterministic", "confirmed"),
            ("SlackOAuthToken", "critical", "high", "deterministic", "confirmed"),
            ("SlackRefreshToken", "critical", "high", "deterministic", "confirmed"),
            ("SlackUserToken", "critical", "high", "deterministic", "confirmed"),
            ("MongodbUrl", "high", "high", "deterministic", "confirmed"),
            ("MysqlUrl", "high", "high", "deterministic", "confirmed"),
            ("PostgresUrl", "high", "high", "deterministic", "confirmed"),
            ("EcPrivateKey", "critical", "high", "deterministic", "confirmed"),
            ("OpensshPrivateKey", "critical", "high", "deterministic", "confirmed"),
            ("PgpPrivateKey", "critical", "high", "deterministic", "confirmed"),
            ("PrivateKey", "critical", "high", "deterministic", "confirmed"),
            ("RsaPrivateKey", "critical", "high", "deterministic", "confirmed"),
            ("CreditCardLuhn", "critical", "medium", "deterministic", "suspected"),
            ("EmailAddress", "medium", "medium", "heuristic", "suspected"),
            ("SsnPattern", "critical", "medium", "deterministic", "suspected"),
            ("GenericHighEntropy", "low", "low", "heuristic", "suspected"),
            ("Custom", "high", "high", "policy_defined", "confirmed"),
        ];

        let actual: Vec<(String, String, String, String, String)> = every_kind()
            .map(|k| {
                let confidence = ConfidenceBand::for_credential_kind(&k);
                let status = match confidence {
                    ConfidenceBand::High => FindingStatus::Confirmed,
                    _ => FindingStatus::Suspected,
                };
                (
                    k.as_str().to_string(),
                    Severity::for_credential_kind(&k).as_str().to_string(),
                    confidence.as_str().to_string(),
                    DetectionMethod::for_credential_kind(&k).as_str().to_string(),
                    status.as_str().to_string(),
                )
            })
            .collect();
        let expected: Vec<(String, String, String, String, String)> = EXPECTED
            .iter()
            .map(|(k, s, c, m, st)| {
                (
                    (*k).to_string(),
                    (*s).to_string(),
                    (*c).to_string(),
                    (*m).to_string(),
                    (*st).to_string(),
                )
            })
            .collect();
        assert_eq!(actual, expected);
    }

    /// The status a lifted finding actually carries must match the table above.
    ///
    /// The table derives status from confidence the same way the lift does, so
    /// on its own it would pass even if the lift stopped agreeing with it. This
    /// closes that by reading the status off a real `CanonicalFinding`.
    #[test]
    fn the_lifted_status_agrees_with_the_confidence_band() {
        let scanner = crate::CredentialScanner::new();
        let cases = [
            (
                "token ghp_16C7e42F292c6912E7710c838347Ae178B4a",
                FindingStatus::Confirmed,
            ),
            ("contact alice.smith@example.com now", FindingStatus::Suspected),
            ("employee record 123-45-6789 filed", FindingStatus::Suspected),
        ];
        for (text, expected) in cases {
            let result = scanner.scan(text);
            let finding = CanonicalFinding::try_from(&result.findings[0]).expect("well-formed span");
            assert_eq!(finding.status(), expected, "status wrong for {text:?}");
        }
    }

    /// `Display` and `FromStr` are inverse over every category this build has.
    ///
    /// Without this the rendered form was a one-way debug string: 5355 and 5359
    /// will put it where something must read it back, and nothing defined what
    /// reading it back meant.
    #[test]
    fn every_category_in_the_catalogue_parses_back_to_itself() {
        for category in CanonicalCategory::ALL {
            let rendered = category.to_string();
            assert_eq!(
                rendered.parse::<CanonicalCategory>(),
                Ok(*category),
                "{rendered} did not parse back"
            );
            // The allocation-free comparison must agree with `Display`.
            assert!(category.renders_as(&rendered));
            assert!(!category.renders_as(&format!("{rendered}x")));
        }
    }

    /// The catalogue must contain every category the kind mapping can produce.
    ///
    /// Nothing else enforces this. The forward mapping is exhaustiveness-checked
    /// so a new `CredentialKind` cannot lack a category, but a category absent
    /// from `ALL` renders fine, is emitted by a live recognizer, and then fails
    /// to parse in the same build — silent, and exactly the shape AAASM-5353's
    /// locale packs will have when they extend `ALL`.
    #[test]
    fn every_credential_kind_category_is_in_all() {
        for kind in every_kind() {
            let category = CanonicalCategory::from_credential_kind(&kind);
            assert!(
                CanonicalCategory::ALL.contains(&category),
                "{category} (from {}) is missing from CanonicalCategory::ALL",
                kind.as_str()
            );
        }
        assert_eq!(
            CanonicalCategory::ALL.len(),
            34,
            "catalogue should hold exactly this build's 28 scanner categories \
             plus AAASM-5353's 6 zh-TW locale categories"
        );
    }

    /// The zh-TW locale categories, pinned by their rendered form.
    ///
    /// These have no `CredentialKind`, so none of the guards above touch them:
    /// the forward mapping is exhaustiveness-checked over kinds and there is no
    /// kind here to check. Without this test a locale category could be dropped
    /// from, renamed in, or never added to `ALL` and the whole suite would still
    /// pass — while a live recognizer emitted a category that failed to parse in
    /// the same build. That is the exact failure `an_unknown_rendering_is_refused`
    /// predicted before this ticket landed.
    #[test]
    fn every_zh_tw_category_is_in_all_and_maps_back_to_no_credential_kind() {
        const EXPECTED: &[&str] = &[
            "NATIONAL_ID[zh-TW/national_id]",
            "NATIONAL_ID[zh-TW/arc_new]",
            "NATIONAL_ID[zh-TW/arc_legacy]",
            "TAX_IDENTIFIER[zh-TW/business_id]",
            "PHONE_NUMBER[zh-TW/mobile]",
            "PHONE_NUMBER[zh-TW/landline]",
        ];

        let rendered: Vec<String> = CanonicalCategory::ALL
            .iter()
            .filter(|c| matches!(c.qualifier(), Some(CategoryQualifier::Locale { tag: "zh-TW", .. })))
            .map(ToString::to_string)
            .collect();
        assert_eq!(rendered, EXPECTED);

        for spelling in EXPECTED {
            let parsed = spelling
                .parse::<CanonicalCategory>()
                .unwrap_or_else(|_| panic!("{spelling} is in ALL but does not parse"));
            assert_eq!(
                parsed.to_credential_kind(),
                None,
                "{spelling} must have no CredentialKind — ADR 0032 §2 freezes CredentialKind::ALL"
            );
            // And therefore the opaque label, never a fabricated pattern name.
            assert_eq!(parsed.redaction_label(), "[REDACTED]");
        }
    }

    /// A category this build does not know is refused, not fabricated.
    ///
    /// This is the case a reader older than a locale pack will actually hit.
    /// AAASM-5352 used `NATIONAL_ID[zh-TW/arc_new]` as the example; AAASM-5353
    /// added that recognizer and its `ALL` entry, so it now parses and the
    /// example moved to a jurisdiction this build genuinely has no pack for.
    #[test]
    fn an_unknown_rendering_is_refused() {
        for input in [
            // Constructible in this build via `with_locale`, but not in the
            // catalogue because no recognizer here produces it.
            "NATIONAL_ID[ja-JP/my_number]",
            // A locale pack this build *does* have, with a variant it does not:
            // the qualifier is what discriminates, not the base plus the tag.
            "NATIONAL_ID[zh-TW/no_such_variant]",
            "NOT_A_BASE",
            "ACCESS_TOKEN[github:no_such_variant]",
            "ACCESS_TOKEN[github:personal_access]extra",
            "",
        ] {
            assert_eq!(
                input.parse::<CanonicalCategory>(),
                Err(ParseCategoryError::UnknownCategory),
                "{input:?} should not have parsed"
            );
        }
    }

    /// Qualifier fields carry no separator, which is the premise the whole
    /// disambiguation argument rests on.
    ///
    /// `is_well_formed_field` enforces it at construction, and because the
    /// mapping is `const` a violation is a compile error rather than a runtime
    /// panic. This checks the built-in catalogue actually satisfies it, so the
    /// claim that `/` means locale and `:` means scheme is grounded rather than
    /// merely asserted.
    #[test]
    fn no_qualifier_field_contains_a_separator() {
        for kind in every_kind() {
            let category = CanonicalCategory::from_credential_kind(&kind);
            let Some(qualifier) = category.qualifier() else {
                continue;
            };
            let (a, b) = match qualifier {
                CategoryQualifier::Locale { tag, variant } => (tag, variant),
                CategoryQualifier::Scheme { scheme, variant } => (scheme, variant),
            };
            for field in [a, b] {
                assert!(!field.is_empty(), "empty qualifier field on {category}");
                for bad in ['/', ':', '[', ']'] {
                    assert!(
                        !field.contains(bad),
                        "qualifier field {field:?} on {category} contains {bad:?}"
                    );
                }
            }
            // Exactly one separator in the rendered body, so it cannot be read
            // as both a locale and a scheme.
            let body = category.to_string();
            let body = body.split_once('[').unwrap().1.trim_end_matches(']').to_string();
            assert_eq!(
                usize::from(body.contains('/')) + usize::from(body.contains(':')),
                1,
                "rendered qualifier {body:?} is ambiguous"
            );
        }
    }
}
