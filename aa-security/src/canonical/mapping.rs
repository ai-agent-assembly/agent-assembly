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
}
