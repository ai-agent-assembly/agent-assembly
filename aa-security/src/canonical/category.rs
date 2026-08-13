//! The canonical category: a provider-neutral entity name, optionally qualified.
//!
//! See the [module documentation](super) for the full taxonomy and the rules
//! governing qualifiers.

use core::fmt;

/// The provider-neutral entity a finding is about, without any locale, vendor or
/// encoding detail.
///
/// This is the handle a policy author writes. It is deliberately coarse: a rule
/// that names [`CategoryBase::NationalId`] must keep matching when a new locale
/// pack adds Taiwanese national IDs beside the US SSN, and a rule that names
/// [`CategoryBase::AccessToken`] must keep matching when a new vendor prefix is
/// added to the scanner. Anything finer belongs in a [`CategoryQualifier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CategoryBase {
    /// A vendor API key that authenticates to a model or SaaS provider.
    ApiKey,
    /// A cloud provider access-key identifier.
    CloudAccessKey,
    /// A cloud provider service-account key document.
    CloudServiceAccountKey,
    /// A cloud provider connection string carrying an embedded shared key.
    CloudConnectionString,
    /// A bearer token issued by an identity or SaaS provider.
    AccessToken,
    /// A database connection URI, which conventionally embeds a password.
    DatabaseConnectionUri,
    /// Asymmetric private-key material.
    PrivateKey,
    /// A payment card number.
    PaymentCardNumber,
    /// An email address.
    EmailAddress,
    /// A government-issued personal identifier. Always locale-qualified, because
    /// the identifier's format, checksum and name are properties of the issuing
    /// jurisdiction, not of the category.
    NationalId,
    /// A registration number identifying a **business** to a tax authority, such
    /// as Taiwan's 統一編號 or a US EIN.
    ///
    /// Separate from [`CategoryBase::NationalId`] rather than folded into it,
    /// even though both are government-issued and both are locale-qualified.
    /// `NATIONAL_ID` names a *personal* identifier, and the difference is
    /// operative: a policy that redacts personal identifiers would otherwise
    /// also redact the company number that legitimately appears on every invoice
    /// and contract an agent handles, and an operator reading a report could not
    /// tell the two apart.
    TaxIdentifier,
    /// A telephone number.
    ///
    /// A new base because no existing one describes it — it is neither a
    /// credential nor an identifier a jurisdiction issues to a person, and
    /// mapping it onto any of the above would make the coarse handle lie about
    /// what a policy is matching.
    PhoneNumber,
    /// Unstructured material flagged by an entropy or encoding heuristic rather
    /// than by a recognizer that knows what it found.
    HighEntropySecret,
    /// A match produced by an operator-authored pattern in the active policy.
    PolicyDefinedMatch,
}

impl CategoryBase {
    /// The stable wire spelling of this base, in `SCREAMING_SNAKE_CASE`.
    ///
    /// Part of the canonical category's rendered form and therefore stable:
    /// downstream events, metrics and policies key off it.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ApiKey => "API_KEY",
            Self::CloudAccessKey => "CLOUD_ACCESS_KEY",
            Self::CloudServiceAccountKey => "CLOUD_SERVICE_ACCOUNT_KEY",
            Self::CloudConnectionString => "CLOUD_CONNECTION_STRING",
            Self::AccessToken => "ACCESS_TOKEN",
            Self::DatabaseConnectionUri => "DATABASE_CONNECTION_URI",
            Self::PrivateKey => "PRIVATE_KEY",
            Self::PaymentCardNumber => "PAYMENT_CARD_NUMBER",
            Self::EmailAddress => "EMAIL_ADDRESS",
            Self::NationalId => "NATIONAL_ID",
            Self::TaxIdentifier => "TAX_IDENTIFIER",
            Self::PhoneNumber => "PHONE_NUMBER",
            Self::HighEntropySecret => "HIGH_ENTROPY_SECRET",
            Self::PolicyDefinedMatch => "POLICY_DEFINED_MATCH",
        }
    }
}

impl fmt::Display for CategoryBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The dimension along which a [`CategoryBase`] is narrowed.
///
/// Two namespaces exist and they render with different separators so a rendered
/// category is unambiguous without a schema: `/` introduces a locale, `:` a
/// scheme. `NATIONAL_ID[zh-TW/arc_new]` is a Taiwanese residence-certificate
/// number; `ACCESS_TOKEN[github:personal_access]` is a GitHub PAT.
///
/// Every field is `&'static str`, and the crate never leaks a runtime string
/// into one: `FromStr` resolves against categories that already exist rather
/// than building new ones. So a qualifier names something spelled out in source,
/// and a config file, policy document or wire payload cannot introduce one
/// without a code change. Note this is a property of how the crate uses the
/// type, not of `&'static str` itself — `Box::leak` produces `&'static str` from
/// runtime bytes in safe Rust, which is why identity elsewhere in this model is
/// a closed enum rather than a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CategoryQualifier {
    /// A jurisdiction-specific instance of the base category, rendered
    /// `<bcp47-tag>/<variant>`.
    Locale {
        /// BCP-47 language tag identifying the jurisdiction, e.g. `zh-TW`.
        tag: &'static str,
        /// The identifier's local name within that jurisdiction, e.g. `arc_new`.
        variant: &'static str,
    },
    /// A vendor- or format-specific instance of the base category, rendered
    /// `<scheme>:<variant>`.
    Scheme {
        /// The issuing vendor or defining format, e.g. `github`, `pem`.
        scheme: &'static str,
        /// The specific form within that scheme, e.g. `personal_access`, `rsa`.
        variant: &'static str,
    },
}

impl fmt::Display for CategoryQualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locale { tag, variant } => write!(f, "{tag}/{variant}"),
            Self::Scheme { scheme, variant } => write!(f, "{scheme}:{variant}"),
        }
    }
}

/// A canonical, provider-neutral category: a [`CategoryBase`] plus an optional
/// [`CategoryQualifier`].
///
/// Rendered as `BASE` when unqualified and `BASE[qualifier]` otherwise. The
/// rendered form is the spelling used in events, metric labels and policy, so it
/// is a contract — see the module documentation for the stability rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanonicalCategory {
    base: CategoryBase,
    qualifier: Option<CategoryQualifier>,
}

/// Whether `field` can appear in a qualifier without making the rendered form
/// ambiguous or unparseable.
///
/// The disambiguation argument — `/` introduces a locale, `:` a scheme — only
/// holds if neither separator can occur *inside* a field, and the `[…]` wrapper
/// only delimits if brackets cannot either. `NATIONAL_ID[zh-TW/arc:new]` would
/// otherwise be readable as both, and `API_KEY[a:b]extra]` would not round-trip
/// at all.
///
/// `const fn`, so a category built in a `const` context — which every entry of
/// the `CredentialKind` mapping is — fails to compile rather than merely
/// tripping an assertion at run time.
const fn is_well_formed_field(field: &str) -> bool {
    let bytes = field.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' | b':' | b'[' | b']' => return false,
            _ => i += 1,
        }
    }
    true
}

impl CanonicalCategory {
    /// An unqualified category, e.g. `EMAIL_ADDRESS`.
    pub const fn unqualified(base: CategoryBase) -> Self {
        Self { base, qualifier: None }
    }

    /// A locale-qualified category, e.g. `NATIONAL_ID[zh-TW/arc_new]`.
    ///
    /// # Panics
    ///
    /// If `tag` or `variant` is empty or contains `/`, `:`, `[` or `]`, which
    /// would make the rendered form ambiguous. In a `const` context — where the
    /// whole `CredentialKind` mapping lives — this is a compile error.
    pub const fn with_locale(base: CategoryBase, tag: &'static str, variant: &'static str) -> Self {
        assert!(
            is_well_formed_field(tag) && is_well_formed_field(variant),
            "locale qualifier fields must be non-empty and free of `/`, `:`, `[` and `]`"
        );
        Self {
            base,
            qualifier: Some(CategoryQualifier::Locale { tag, variant }),
        }
    }

    /// A scheme-qualified category, e.g. `ACCESS_TOKEN[github:personal_access]`.
    ///
    /// # Panics
    ///
    /// If `scheme` or `variant` is empty or contains `/`, `:`, `[` or `]`. See
    /// [`with_locale`](Self::with_locale).
    pub const fn with_scheme(base: CategoryBase, scheme: &'static str, variant: &'static str) -> Self {
        assert!(
            is_well_formed_field(scheme) && is_well_formed_field(variant),
            "scheme qualifier fields must be non-empty and free of `/`, `:`, `[` and `]`"
        );
        Self {
            base,
            qualifier: Some(CategoryQualifier::Scheme { scheme, variant }),
        }
    }

    /// The coarse handle a policy rule matches on.
    pub const fn base(&self) -> CategoryBase {
        self.base
    }

    /// The narrowing dimension, if this category has one.
    pub const fn qualifier(&self) -> Option<CategoryQualifier> {
        self.qualifier
    }
}

impl CanonicalCategory {
    /// Whether this category renders exactly as `candidate`, without allocating.
    ///
    /// `to_string() == candidate` allocates once per comparison, and
    /// [`FromStr`](std::str::FromStr) does one comparison per catalogue entry
    /// per parse — 28 allocations per record on the event ingest paths
    /// AAASM-5355/5359 add. This consumes `candidate` fragment by fragment as
    /// `Display` emits them and bails on the first mismatch, so it allocates
    /// nothing and usually stops at the base.
    pub fn renders_as(&self, candidate: &str) -> bool {
        use fmt::Write as _;

        /// Consumes the expected string as `Display` writes fragments into it.
        struct Probe<'a> {
            expected: &'a str,
            matched: bool,
        }
        impl fmt::Write for Probe<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                match self.expected.strip_prefix(s) {
                    Some(rest) => {
                        self.expected = rest;
                        Ok(())
                    }
                    None => {
                        self.matched = false;
                        Err(fmt::Error)
                    }
                }
            }
        }

        let mut probe = Probe {
            expected: candidate,
            matched: true,
        };
        // A write failure means a mismatch was found early; either way the
        // category matches only if every fragment was consumed exactly.
        let _ = write!(probe, "{self}");
        probe.matched && probe.expected.is_empty()
    }
}

impl fmt::Display for CanonicalCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.qualifier {
            Some(q) => write!(f, "{}[{q}]", self.base),
            None => write!(f, "{}", self.base),
        }
    }
}
