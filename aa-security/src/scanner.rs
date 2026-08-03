//! Credential leak detection using Aho-Corasick multi-pattern scanning.
//!
//! Only compiled when the `std` feature is enabled. The [`CredentialScanner`]
//! is pre-compiled at construction time so each call to [`CredentialScanner::scan`]
//! pays zero pattern-compilation cost.

use aho_corasick::AhoCorasick;

// ---------------------------------------------------------------------------
// AC literal patterns — order matters: earlier index wins on same-position match.
// sk-ant- must precede sk- so Anthropic keys are not misclassified as OpenAI keys.
// ---------------------------------------------------------------------------

const AC_PATTERNS: &[&str] = &[
    "sk-ant-",                               // 0  AnthropicKey
    "sk-",                                   // 1  OpenAiKey
    "AKIA",                                  // 2  AwsAccessKey
    "\"type\": \"service_account\"",         // 3  GcpServiceAccount
    "DefaultEndpointsProtocol=",             // 4  AzureConnectionString
    "ghp_",                                  // 5  GitHubPat
    "ghs_",                                  // 6  GitHubAppToken
    "xoxb-",                                 // 7  SlackBotToken
    "xoxp-",                                 // 8  SlackUserToken
    "xoxa-",                                 // 9  SlackOAuthToken
    "postgres://",                           // 10 PostgresUrl
    "mysql://",                              // 11 MysqlUrl
    "mongodb://",                            // 12 MongodbUrl
    "-----BEGIN RSA PRIVATE KEY-----",       // 13 RsaPrivateKey
    "-----BEGIN EC PRIVATE KEY-----",        // 14 EcPrivateKey
    "-----BEGIN OPENSSH PRIVATE KEY-----",   // 15 OpensshPrivateKey
    "-----BEGIN PRIVATE KEY-----",           // 16 PrivateKey
    "-----BEGIN PGP PRIVATE KEY BLOCK-----", // 17 PgpPrivateKey
    // AAASM-3727: GCP service-account JSON whitespace variants. A compact
    // serializer emits no space after the colon, and some emit a space before
    // it; index 3's single-space literal misses both. These map to the same
    // GcpServiceAccount kind so the realistic serialized forms are all caught.
    "\"type\":\"service_account\"",   // 18 GcpServiceAccount (compact, no space)
    "\"type\" :\"service_account\"",  // 19 GcpServiceAccount (space before colon)
    "\"type\" : \"service_account\"", // 20 GcpServiceAccount (spaces around colon)
    // AAASM-4128: near-parity token prefixes that share a brand stem with the
    // detectors above. The brand prefix dilutes each token's run entropy below
    // the 4.5 gate (and `xapp-` tokens exceed the 20–64 whitespace-token window),
    // so the entropy backstop never catches them — literal-prefix detection is
    // the only reliable path. `github_pat_` (fine-grained PAT) and `ASIA` (STS
    // temporary access key ID) are the same credential kind as their siblings,
    // mirroring the GCP multi-pattern → single-kind mapping above.
    "gho_",        // 21 GitHubOAuthToken
    "ghu_",        // 22 GitHubUserToken
    "ghr_",        // 23 GitHubRefreshToken
    "github_pat_", // 24 GitHubPat (fine-grained PAT)
    "xapp-",       // 25 SlackAppToken
    "xoxr-",       // 26 SlackRefreshToken
    "ASIA",        // 27 AwsAccessKey (STS temporary access key ID)
];

/// Maps AC pattern index → [`CredentialKind`].
const AC_KINDS: &[CredentialKind] = &[
    CredentialKind::AnthropicKey,          // 0
    CredentialKind::OpenAiKey,             // 1
    CredentialKind::AwsAccessKey,          // 2
    CredentialKind::GcpServiceAccount,     // 3
    CredentialKind::AzureConnectionString, // 4
    CredentialKind::GitHubPat,             // 5
    CredentialKind::GitHubAppToken,        // 6
    CredentialKind::SlackBotToken,         // 7
    CredentialKind::SlackUserToken,        // 8
    CredentialKind::SlackOAuthToken,       // 9
    CredentialKind::PostgresUrl,           // 10
    CredentialKind::MysqlUrl,              // 11
    CredentialKind::MongodbUrl,            // 12
    CredentialKind::RsaPrivateKey,         // 13
    CredentialKind::EcPrivateKey,          // 14
    CredentialKind::OpensshPrivateKey,     // 15
    CredentialKind::PrivateKey,            // 16
    CredentialKind::PgpPrivateKey,         // 17
    CredentialKind::GcpServiceAccount,     // 18 (compact JSON)
    CredentialKind::GcpServiceAccount,     // 19 (space before colon)
    CredentialKind::GcpServiceAccount,     // 20 (spaces around colon)
    CredentialKind::GitHubOAuthToken,      // 21
    CredentialKind::GitHubUserToken,       // 22
    CredentialKind::GitHubRefreshToken,    // 23
    CredentialKind::GitHubPat,             // 24 (fine-grained PAT)
    CredentialKind::SlackAppToken,         // 25
    CredentialKind::SlackRefreshToken,     // 26
    CredentialKind::AwsAccessKey,          // 27 (STS temporary access key ID)
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Category of a detected credential or sensitive value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CredentialKind {
    // API keys
    /// Anthropic API key (prefix `sk-ant-`).
    AnthropicKey,
    /// AWS access key ID (long-term prefix `AKIA`, STS temporary prefix `ASIA`).
    AwsAccessKey,
    /// GCP service account JSON credential (contains `"type": "service_account"`).
    GcpServiceAccount,
    /// OpenAI API key (prefix `sk-`).
    OpenAiKey,
    // Cloud credentials
    /// Azure Storage connection string (prefix `DefaultEndpointsProtocol=`).
    AzureConnectionString,
    // Auth tokens
    /// GitHub App installation token (prefix `ghs_`).
    GitHubAppToken,
    /// GitHub OAuth access token (prefix `gho_`).
    GitHubOAuthToken,
    /// GitHub personal access token (classic prefix `ghp_`, fine-grained prefix `github_pat_`).
    GitHubPat,
    /// GitHub refresh token (prefix `ghr_`).
    GitHubRefreshToken,
    /// GitHub user-to-server token (prefix `ghu_`).
    GitHubUserToken,
    /// Slack app-level token (prefix `xapp-`).
    SlackAppToken,
    /// Slack bot token (prefix `xoxb-`).
    SlackBotToken,
    /// Slack OAuth token (prefix `xoxa-`).
    SlackOAuthToken,
    /// Slack refresh token (prefix `xoxr-`).
    SlackRefreshToken,
    /// Slack user token (prefix `xoxp-`).
    SlackUserToken,
    // Database URLs
    /// MongoDB connection URI (prefix `mongodb://`).
    MongodbUrl,
    /// MySQL connection URI (prefix `mysql://`).
    MysqlUrl,
    /// PostgreSQL connection URI (prefix `postgres://`).
    PostgresUrl,
    // Private keys
    /// PEM-encoded EC private key (`-----BEGIN EC PRIVATE KEY-----`).
    EcPrivateKey,
    /// PEM-encoded OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    OpensshPrivateKey,
    /// PEM-encoded PGP private key block (`-----BEGIN PGP PRIVATE KEY BLOCK-----`).
    PgpPrivateKey,
    /// PEM-encoded PKCS#8 private key (`-----BEGIN PRIVATE KEY-----`).
    PrivateKey,
    /// PEM-encoded RSA private key (`-----BEGIN RSA PRIVATE KEY-----`).
    RsaPrivateKey,
    // PII
    /// Credit card number validated by the Luhn algorithm (13–19 digits).
    CreditCardLuhn,
    /// Email address containing `@` and a dot-separated domain.
    EmailAddress,
    /// US Social Security Number in `DDD-DD-DDDD` format.
    SsnPattern,
    // Generic
    /// High-entropy or long encoded token: a whitespace token of length 20–64
    /// with Shannon entropy > 4.5 bits/char, a contiguous hex run ≥ 64 chars, or
    /// a contiguous base64 run ≥ 20 chars above the entropy gate.
    GenericHighEntropy,
    // Policy-defined
    /// A pattern defined in the policy document's `data.sensitive_patterns` field.
    Custom,
}

impl CredentialKind {
    /// Every built-in detector kind, in a stable declaration order.
    ///
    /// This is the single source of truth for enumerating the effective
    /// pattern catalogue (e.g. over HTTP via the DLP/scrub API, AAASM-5174).
    /// It intentionally excludes [`CredentialKind::Custom`], which is not a
    /// built-in detector but the label applied to matches produced by
    /// policy-defined `data.sensitive_patterns` regexes; those are enumerated
    /// from the active policy, not from this list.
    ///
    /// A compile-time exhaustiveness test in this module asserts every variant
    /// except `Custom` appears here exactly once, so a newly-added detector
    /// kind cannot silently drop out of the catalogue.
    pub const ALL: &'static [CredentialKind] = &[
        Self::AnthropicKey,
        Self::AwsAccessKey,
        Self::GcpServiceAccount,
        Self::OpenAiKey,
        Self::AzureConnectionString,
        Self::GitHubAppToken,
        Self::GitHubOAuthToken,
        Self::GitHubPat,
        Self::GitHubRefreshToken,
        Self::GitHubUserToken,
        Self::SlackAppToken,
        Self::SlackBotToken,
        Self::SlackOAuthToken,
        Self::SlackRefreshToken,
        Self::SlackUserToken,
        Self::MongodbUrl,
        Self::MysqlUrl,
        Self::PostgresUrl,
        Self::EcPrivateKey,
        Self::OpensshPrivateKey,
        Self::PgpPrivateKey,
        Self::PrivateKey,
        Self::RsaPrivateKey,
        Self::CreditCardLuhn,
        Self::EmailAddress,
        Self::SsnPattern,
        Self::GenericHighEntropy,
    ];

    /// Coarse detector family for grouping in the catalogue UI: one of
    /// `"api_key"`, `"cloud_credential"`, `"auth_token"`, `"database_url"`,
    /// `"private_key"`, `"pii"`, or `"generic"`.
    pub fn category(&self) -> &'static str {
        match self {
            Self::AnthropicKey | Self::OpenAiKey => "api_key",
            Self::AwsAccessKey | Self::GcpServiceAccount | Self::AzureConnectionString => "cloud_credential",
            Self::GitHubAppToken
            | Self::GitHubOAuthToken
            | Self::GitHubPat
            | Self::GitHubRefreshToken
            | Self::GitHubUserToken
            | Self::SlackAppToken
            | Self::SlackBotToken
            | Self::SlackOAuthToken
            | Self::SlackRefreshToken
            | Self::SlackUserToken => "auth_token",
            Self::MongodbUrl | Self::MysqlUrl | Self::PostgresUrl => "database_url",
            Self::EcPrivateKey
            | Self::OpensshPrivateKey
            | Self::PgpPrivateKey
            | Self::PrivateKey
            | Self::RsaPrivateKey => "private_key",
            Self::CreditCardLuhn | Self::EmailAddress | Self::SsnPattern => "pii",
            Self::GenericHighEntropy => "generic",
            Self::Custom => "custom",
        }
    }

    /// Relative leak severity of this kind: `"critical"`, `"high"`, `"medium"`,
    /// or `"low"`.
    ///
    /// Live credentials and private keys (which grant direct access) are
    /// `critical`; regulated PII (`CreditCardLuhn`, `SsnPattern`) is also
    /// `critical`. Database connection URIs are `high`. Email PII is `medium`.
    /// The generic high-entropy backstop is `low` because it is the least
    /// specific signal. This is a fixed classification, not a live-computed
    /// value.
    pub fn severity(&self) -> &'static str {
        match self {
            Self::AnthropicKey
            | Self::OpenAiKey
            | Self::AwsAccessKey
            | Self::GcpServiceAccount
            | Self::AzureConnectionString
            | Self::GitHubAppToken
            | Self::GitHubOAuthToken
            | Self::GitHubPat
            | Self::GitHubRefreshToken
            | Self::GitHubUserToken
            | Self::SlackAppToken
            | Self::SlackBotToken
            | Self::SlackOAuthToken
            | Self::SlackRefreshToken
            | Self::SlackUserToken
            | Self::EcPrivateKey
            | Self::OpensshPrivateKey
            | Self::PgpPrivateKey
            | Self::PrivateKey
            | Self::RsaPrivateKey
            | Self::CreditCardLuhn
            | Self::SsnPattern => "critical",
            Self::MongodbUrl | Self::MysqlUrl | Self::PostgresUrl => "high",
            Self::EmailAddress => "medium",
            Self::GenericHighEntropy => "low",
            Self::Custom => "high",
        }
    }

    /// Returns the string used in the `[REDACTED:<kind>]` label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AnthropicKey => "AnthropicKey",
            Self::AwsAccessKey => "AwsAccessKey",
            Self::AzureConnectionString => "AzureConnectionString",
            Self::CreditCardLuhn => "CreditCardLuhn",
            Self::EcPrivateKey => "EcPrivateKey",
            Self::EmailAddress => "EmailAddress",
            Self::GcpServiceAccount => "GcpServiceAccount",
            Self::GenericHighEntropy => "GenericHighEntropy",
            Self::GitHubAppToken => "GitHubAppToken",
            Self::GitHubOAuthToken => "GitHubOAuthToken",
            Self::GitHubPat => "GitHubPat",
            Self::GitHubRefreshToken => "GitHubRefreshToken",
            Self::GitHubUserToken => "GitHubUserToken",
            Self::MongodbUrl => "MongodbUrl",
            Self::MysqlUrl => "MysqlUrl",
            Self::OpenAiKey => "OpenAiKey",
            Self::OpensshPrivateKey => "OpensshPrivateKey",
            Self::PgpPrivateKey => "PgpPrivateKey",
            Self::PostgresUrl => "PostgresUrl",
            Self::PrivateKey => "PrivateKey",
            Self::RsaPrivateKey => "RsaPrivateKey",
            Self::SlackAppToken => "SlackAppToken",
            Self::SlackBotToken => "SlackBotToken",
            Self::SlackOAuthToken => "SlackOAuthToken",
            Self::SlackRefreshToken => "SlackRefreshToken",
            Self::SlackUserToken => "SlackUserToken",
            Self::SsnPattern => "SsnPattern",
            Self::Custom => "Custom",
        }
    }

    /// Whether this kind is a PEM private-key block detected by its
    /// `-----BEGIN … PRIVATE KEY-----` header.
    ///
    /// Used to extend the finding span through the block's `-----END …-----`
    /// marker when the block ends in a base64 line too short for the
    /// length-gated entropy pass, so that short trailing line of key material
    /// cannot slip past redaction (ADR 0015 §2/§5.1, AAASM-4946).
    fn is_pem_private_key(&self) -> bool {
        matches!(
            self,
            Self::EcPrivateKey | Self::OpensshPrivateKey | Self::PgpPrivateKey | Self::PrivateKey | Self::RsaPrivateKey
        )
    }

    /// Relative confidence of this kind when two overlapping findings are
    /// coalesced into one span.
    ///
    /// When several detectors match the same byte region (e.g. a GitHub PAT is
    /// also flagged as a `GenericHighEntropy` token, or a database URL embeds an
    /// `EmailAddress`), the merged span must carry the label of the most
    /// specific, highest-confidence detector — never a generic backstop. A
    /// higher number wins. Specific literal-prefix and PEM detectors and
    /// policy-defined `Custom` patterns outrank the generic
    /// `GenericHighEntropy` / `EmailAddress` heuristics.
    fn priority(&self) -> u8 {
        match self {
            // Generic / heuristic backstops — lowest confidence.
            Self::GenericHighEntropy => 0,
            Self::EmailAddress => 1,
            // Specific, high-signal detectors — they identify the exact
            // credential kind and must win over the generic backstops above.
            Self::AnthropicKey
            | Self::AwsAccessKey
            | Self::AzureConnectionString
            | Self::CreditCardLuhn
            | Self::EcPrivateKey
            | Self::GcpServiceAccount
            | Self::GitHubAppToken
            | Self::GitHubOAuthToken
            | Self::GitHubPat
            | Self::GitHubRefreshToken
            | Self::GitHubUserToken
            | Self::MongodbUrl
            | Self::MysqlUrl
            | Self::OpenAiKey
            | Self::OpensshPrivateKey
            | Self::PgpPrivateKey
            | Self::PostgresUrl
            | Self::PrivateKey
            | Self::RsaPrivateKey
            | Self::SlackAppToken
            | Self::SlackBotToken
            | Self::SlackOAuthToken
            | Self::SlackRefreshToken
            | Self::SlackUserToken
            | Self::SsnPattern
            | Self::Custom => 2,
        }
    }
}

/// A single detected credential finding.
///
/// `offset` is the byte offset in the original text where the pattern was found.
/// `matched` is the redacted label, e.g. `[REDACTED:AwsAccessKey]`. The raw
/// secret is never stored.
///
/// The `end` field is intentionally private; it is used by [`ScanResult::redact`]
/// to splice the original match without exposing raw length arithmetic to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialFinding {
    /// Category of the detected credential.
    pub kind: CredentialKind,
    /// Byte offset in the original text where the pattern begins.
    pub offset: usize,
    /// Redacted label replacing the secret, e.g. `[REDACTED:AwsAccessKey]`.
    pub matched: String,
    #[cfg_attr(feature = "serde", serde(skip))]
    end: usize,
}

impl CredentialFinding {
    fn new(kind: CredentialKind, offset: usize, end: usize) -> Self {
        let label = format!("[REDACTED:{}]", kind.as_str());
        Self {
            kind,
            offset,
            matched: label,
            end,
        }
    }

    /// Byte offset one past the end of the match.
    ///
    /// Deliberately `pub(crate)`. A length paired with a category can identify a
    /// value in a small domain, so ADR 0032 §9 permits offsets and lengths only
    /// in the tamper-evident audit tier; keeping the end offset crate-private
    /// stops it reaching an API response or a metric label by accident. The
    /// canonical model reads it to build a [`ByteSpan`](crate::canonical::ByteSpan),
    /// which carries the same restriction.
    pub(crate) fn end(&self) -> usize {
        self.end
    }

    /// Construct a finding for a match produced by a policy-defined regex pattern.
    ///
    /// Used by `aa-gateway` when custom `data.sensitive_patterns` regexes match.
    /// The `offset` and `end` are byte positions returned by the regex engine.
    pub fn from_regex_match(offset: usize, end: usize) -> Self {
        Self::new(CredentialKind::Custom, offset, end)
    }
}

/// The result of a [`CredentialScanner::scan`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScanResult {
    /// All credential findings detected in the scanned text, sorted by byte offset.
    pub findings: Vec<CredentialFinding>,
}

impl ScanResult {
    /// Returns `true` if no credential findings were detected.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns a copy of `text` with every finding replaced by its redacted label.
    ///
    /// Overlapping findings are first coalesced into non-overlapping byte spans so
    /// no region is ever partially redacted (which previously left raw secret
    /// fragments and mangled labels in the output). The merged spans are then
    /// spliced in reverse offset order so earlier byte positions remain valid
    /// after each replacement.
    ///
    /// A span whose bounds are out of range or do not fall on UTF-8 character
    /// boundaries cannot be spliced without panicking, but it still marks a
    /// region the scanner flagged as a secret. Rather than skip it — which would
    /// emit that region's raw bytes and leak the secret (fail-open) — the whole
    /// value is replaced with a single opaque redaction label (fail-closed).
    /// This branch is unreachable for spans the scanner produces over `text`
    /// (offsets are always valid char boundaries of the scanned text); it exists
    /// so a caller that ever pairs mismatched spans with `text` cannot leak a
    /// secret through this path.
    pub fn redact(&self, text: &str) -> String {
        let merged = coalesce_findings(&self.findings);
        let mut result = text.to_string();
        // Splice merged spans in reverse offset order so earlier positions stay valid.
        for span in merged.iter().rev() {
            if span.end <= result.len()
                && span.offset <= span.end
                && result.is_char_boundary(span.offset)
                && result.is_char_boundary(span.end)
            {
                result.replace_range(span.offset..span.end, &span.label);
            } else {
                // Fail closed: we cannot prove this flagged region has been
                // removed, so never return the raw text with a secret intact.
                return "[REDACTED]".to_string();
            }
        }
        result
    }
}

/// Configuration for the credential scanner.
///
/// Controls whether scanning is enabled and allows adding custom literal
/// patterns beyond the built-in set.
#[derive(Debug, Clone, Default)]
pub struct ScannerConfig {
    /// When `true`, scanning is disabled and [`CredentialScanner::scan`] always
    /// returns an empty [`ScanResult`].
    pub disabled: bool,
    /// Additional literal prefixes to detect as [`CredentialKind::Custom`].
    /// Each string is compiled into the Aho-Corasick automaton alongside the
    /// built-in patterns.
    pub custom_patterns: Vec<String>,
}

/// Pre-compiled multi-pattern credential scanner.
///
/// Construct once with [`CredentialScanner::new`] (or [`CredentialScanner::with_config`])
/// and call [`CredentialScanner::scan`] repeatedly. Pattern compilation happens at
/// construction time; each scan call is O(n) in the length of the input text.
pub struct CredentialScanner {
    patterns: AhoCorasick,
    /// Maps each AC pattern index to its [`CredentialKind`]. Built-in patterns
    /// use the static `AC_KINDS` entries; custom patterns are appended as
    /// [`CredentialKind::Custom`].
    kinds: Vec<CredentialKind>,
    /// When `true`, [`scan`](Self::scan) short-circuits and returns an empty result.
    disabled: bool,
}

impl Default for CredentialScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialScanner {
    /// Build the scanner with all built-in patterns and scanning enabled.
    ///
    /// # Panics
    ///
    /// Panics only if the hard-coded AC patterns are somehow invalid — this
    /// cannot happen in practice.
    pub fn new() -> Self {
        Self::with_config(ScannerConfig::default())
    }

    /// Build the scanner from explicit configuration.
    ///
    /// Custom patterns are appended after the built-in set and are tagged as
    /// [`CredentialKind::Custom`]. If `config.disabled` is true the scanner
    /// is inert — [`scan`](Self::scan) always returns an empty result.
    pub fn with_config(config: ScannerConfig) -> Self {
        let mut all_patterns: Vec<&str> = AC_PATTERNS.to_vec();
        // Collect custom pattern references — lifetime tied to `config`.
        let custom_refs: Vec<&str> = config.custom_patterns.iter().map(|s| s.as_str()).collect();
        all_patterns.extend_from_slice(&custom_refs);

        let mut kinds: Vec<CredentialKind> = AC_KINDS.to_vec();
        kinds.extend(std::iter::repeat(CredentialKind::Custom).take(config.custom_patterns.len()));

        let ac = AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostFirst)
            // AAASM-3727: scheme prefixes (postgres://), PEM headers, and the
            // GCP JSON key are case-insensitive in the wild (RFC 3986 schemes,
            // lower/mixed-case PEM). Match case-insensitively so case variants
            // cannot bypass detection. Prefixes like AKIA / ghp_ stay high-signal.
            .ascii_case_insensitive(true)
            .build(&all_patterns)
            .expect("AC patterns are always valid");

        Self {
            patterns: ac,
            kinds,
            disabled: config.disabled,
        }
    }

    /// Scan `text` for credential patterns and return a [`ScanResult`].
    ///
    /// Four passes are performed:
    /// 1. Aho-Corasick literal prefix scan — O(n), 28 patterns covering API keys,
    ///    auth tokens, cloud credentials, database URLs, and PEM private key headers.
    /// 2. Credit card and SSN digit-sequence scan.
    /// 3. Email address scan.
    /// 4. Generic high-entropy / long-encoded-blob scan: a 20–64 whitespace token
    ///    above the entropy gate, a contiguous hex run ≥ 64 chars, or a base64
    ///    run ≥ 20 chars above the gate (see [`scan_high_entropy`]).
    pub fn scan(&self, text: &str) -> ScanResult {
        if self.disabled {
            return ScanResult { findings: Vec::new() };
        }

        let mut findings = Vec::new();

        // Phase 1: AC literal prefix scan (API keys, auth tokens, cloud creds,
        //          database URLs, PEM private key headers — 28 patterns + custom)
        for mat in self.patterns.find_iter(text) {
            let kind = self.kinds[mat.pattern()].clone();
            let offset = mat.start();
            let mut end = token_end(text, mat.end());
            // ADR 0015 §2/§5.1 (AAASM-4946): a PEM private-key block whose body
            // is entropy-caught but ends in a base64 line too short for the
            // run-length gate leaves that trailing line of key material in the
            // clear. Extend the literal finding through the block's END marker
            // so it subsumes the overlapping `GenericHighEntropy` body span and
            // the short tail as one label. The trigger is narrow (see
            // [`pem_short_tail_block_end`]) so the common-case PEM vectors —
            // whose current spans are a documented, accepted residual — stay
            // byte-identical.
            if kind.is_pem_private_key() {
                if let Some(block_end) = pem_short_tail_block_end(text, mat.end()) {
                    end = end.max(block_end);
                }
            }
            findings.push(CredentialFinding::new(kind, offset, end));
        }

        // Phase 2: PII — credit card numbers and SSN patterns
        scan_digit_sequences(text, &mut findings);

        // Phase 3: Email addresses
        scan_emails(text, &mut findings);

        // Phase 4: High-entropy / long-hex tokens (encoding & length evasions, AAASM-3870)
        scan_high_entropy(text, &mut findings);

        // Phase 5: Azure `AccountKey=` values wherever they appear in a
        //          connection string (AAASM-3997).
        scan_azure_account_key(text, &mut findings);

        findings.sort_by_key(|f| f.offset);
        dedupe_same_kind_overlaps(&mut findings);
        ScanResult { findings }
    }
}

/// Collapse findings of the **same kind** whose byte spans overlap into one
/// finding per overlapping cluster, so a single secret caught by two passes of
/// one detector is reported once — while keeping the survivor's span equal to
/// the **union** of the overlapping spans so redaction still covers the whole
/// secret.
///
/// The high-entropy detector runs additive passes (whitespace-token, long-hex,
/// long-base64, separator-grouped-hex): a base64 secret that is *also* a
/// whitespace token — e.g. a PEM
/// body on its own line, or a bare `token=<b64>` — trips both the token pass and
/// the base64-run pass, yielding two overlapping `GenericHighEntropy` findings
/// for one secret. This collapses that double-count.
///
/// AAASM-4093: the overlapping finding must be *merged into* the survivor, not
/// dropped outright. Dropping it discarded the longer overlapping pass whenever
/// the shorter pass happened to sort first — e.g. a ≥64-char hex run
/// (`[start, 64)`) is kept and the base64 run over the same start plus a non-hex
/// base64 tail (`[start, 64+K)`) is dropped — so `redact` (which coalesces only
/// the surviving findings) left bytes `[64, 64+K)` un-redacted on the
/// sanitize-and-forward path. Extending `k.end = max(k.end, f.end)` keeps the
/// reported count at one per cluster (unchanged from AAASM-4071) while making the
/// span the full union.
///
/// Only *same-kind* overlaps are merged: overlaps across different kinds are
/// deliberately kept, because a connection URL legitimately produces distinct
/// coincident findings (e.g. `PostgresUrl` + `GenericHighEntropy` + `EmailAddress`
/// over the same region) that `redact` coalesces into one span but that callers
/// count as separate detections. `findings` must already be sorted by `offset`,
/// so any earlier same-kind finding `k` has `k.offset <= f.offset`; the spans
/// therefore overlap exactly when `f.offset < k.end`.
fn dedupe_same_kind_overlaps(findings: &mut Vec<CredentialFinding>) {
    let mut kept: Vec<CredentialFinding> = Vec::with_capacity(findings.len());
    for f in findings.drain(..) {
        match kept.iter_mut().find(|k| k.kind == f.kind && f.offset < k.end) {
            // Same secret caught by another pass: keep one finding but widen its
            // span to the union so no tail byte of the longer pass survives.
            Some(k) => k.end = k.end.max(f.end),
            None => kept.push(f),
        }
    }
    *findings = kept;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// A single non-overlapping byte span to be replaced by `redact`.
struct MergedSpan {
    offset: usize,
    end: usize,
    label: String,
    /// Kind whose `label` the span currently carries — retained so a later
    /// overlapping finding of higher [`CredentialKind::priority`] can claim the
    /// merged span's label.
    kind: CredentialKind,
}

/// Coalesce findings into non-overlapping, offset-ordered spans.
///
/// Findings are sorted by `(offset, end)` and any subsequent finding whose
/// `offset` falls before the current span's `end` is merged into it (extending
/// the span's `end` to the maximum, i.e. the union of overlapping spans so no
/// raw secret fragment can survive). The merged span carries the label of the
/// highest-[`CredentialKind::priority`] finding in the run, so a specific,
/// high-confidence detector (e.g. `GitHubPat`, `PostgresUrl`) always wins over a
/// generic backstop (`GenericHighEntropy`, `EmailAddress`) regardless of byte
/// offset. This guarantees `redact` never leaves a region partially replaced and
/// never downgrades a credential's label to a less specific kind.
fn coalesce_findings(findings: &[CredentialFinding]) -> Vec<MergedSpan> {
    let mut sorted: Vec<&CredentialFinding> = findings.iter().collect();
    sorted.sort_by_key(|f| (f.offset, f.end));

    let mut merged: Vec<MergedSpan> = Vec::with_capacity(sorted.len());
    for f in sorted {
        match merged.last_mut() {
            // Overlapping (or touching) the current span — extend it to the
            // union and adopt the higher-priority kind's label.
            Some(last) if f.offset < last.end => {
                last.end = last.end.max(f.end);
                if f.kind.priority() > last.kind.priority() {
                    last.label = f.matched.clone();
                    last.kind = f.kind.clone();
                }
            }
            _ => merged.push(MergedSpan {
                offset: f.offset,
                end: f.end,
                label: f.matched.clone(),
                kind: f.kind.clone(),
            }),
        }
    }
    merged
}

/// Redact the secret value of every Azure `AccountKey=<value>` in `text`,
/// regardless of its position in a connection string (AAASM-3997).
///
/// The `DefaultEndpointsProtocol=` prefix detector coalesces its span only up to
/// the first `;` (see [`token_end`]), so in a canonical
/// `DefaultEndpointsProtocol=...;AccountName=...;AccountKey=<secret>` string the
/// `AccountKey` — which sits after two `;` separators — was left in the clear.
/// This pass targets the key's value directly: it spans from the `AccountKey=`
/// marker to the next `;`, token terminator, or end of input, so the secret is
/// redacted wherever it falls in the string.
fn scan_azure_account_key(text: &str, findings: &mut Vec<CredentialFinding>) {
    const MARKER: &str = "AccountKey=";
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(MARKER) {
        let offset = search_from + rel;
        let value_start = offset + MARKER.len();
        // The value ends at the next connection-string delimiter (`;`), a
        // whitespace/quote/bracket token terminator, or the end of the input.
        let end = text[value_start..]
            .find(|c: char| c.is_whitespace() || matches!(c, ';' | '"' | '\'' | ',' | ')' | ']' | '}'))
            .map(|i| value_start + i)
            .unwrap_or(text.len());
        findings.push(CredentialFinding::new(
            CredentialKind::AzureConnectionString,
            offset,
            end,
        ));
        // Advance past this marker (at least) so overlapping/repeated keys still progress.
        search_from = end.max(value_start);
    }
}

/// Returns the byte index of the first token-terminating character at or after
/// `from`. Token terminators are whitespace and common delimiters.
fn token_end(text: &str, from: usize) -> usize {
    text[from..]
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')' | ']' | '}'))
        .map(|i| from + i)
        .unwrap_or(text.len())
}

/// Byte index just past the `-----END …-----` marker of the PEM private-key
/// block whose header ended at `header_end`, **but only** when the block ends in
/// a base64 line too short for the entropy pass to catch. Returns `None`
/// otherwise, leaving the finding's header-only span untouched.
///
/// ADR 0015 §2/§5.1 (AAASM-4946). The literal detector matches only a PEM key's
/// `-----BEGIN … PRIVATE KEY-----` header; the base64 body is covered by the
/// entropy pass, which length-gates base64 runs at [`BASE64_RUN_MIN_LEN`]. A
/// block laid out as long body line(s) plus a short final line therefore leaks
/// that final line (real key material) — the residual the reverted AAASM-4936
/// change tried, and mis-implemented, to close.
///
/// The trigger is deliberately narrow so it partitions cleanly against the
/// existing conformance vectors, which must stay byte-identical: extend **only**
/// when the block body contains a base64 run of length ≥ [`BASE64_RUN_MIN_LEN`]
/// (so the entropy pass emits an overlapping `GenericHighEntropy` finding the
/// extended literal span subsumes per §2) **and** its final base64 run is
/// shorter than that gate (the uncovered tail). A block whose only body line is
/// itself short/low-entropy (its body already in the clear as a documented,
/// accepted residual) has no long run and is left unchanged; a fully
/// entropy-covered block has no short tail and is likewise left unchanged.
fn pem_short_tail_block_end(text: &str, header_end: usize) -> Option<usize> {
    let end_rel = text[header_end..].find("-----END")?;
    let end_marker_start = header_end + end_rel;

    // Measure the longest and the final contiguous base64 run in the block body
    // (everything between the header line and the END marker). `=` padding and
    // newlines are run separators, so a `wJ8=` tail measures as a run of 3.
    let mut max_run = 0usize;
    let mut last_run = 0usize;
    let mut cur = 0usize;
    for &b in &text.as_bytes()[header_end..end_marker_start] {
        if is_base64_char(b) {
            cur += 1;
        } else if cur > 0 {
            max_run = max_run.max(cur);
            last_run = cur;
            cur = 0;
        }
    }
    if cur > 0 {
        max_run = max_run.max(cur);
        last_run = cur;
    }

    if max_run < BASE64_RUN_MIN_LEN || last_run == 0 || last_run >= BASE64_RUN_MIN_LEN {
        return None;
    }

    // Consume through the END marker's closing dashes so the whole block —
    // including the short trailing line and the marker — is inside the span.
    let after_end_keyword = end_marker_start + "-----END".len();
    let closing = text[after_end_keyword..].find("-----")?;
    Some(after_end_keyword + closing + "-----".len())
}

/// Returns `true` if `s` matches the SSN format `DDD-DD-DDDD` exactly.
fn is_ssn(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 11
        && b[0..3].iter().all(u8::is_ascii_digit)
        && b[3] == b'-'
        && b[4..6].iter().all(u8::is_ascii_digit)
        && b[6] == b'-'
        && b[7..11].iter().all(u8::is_ascii_digit)
}

/// Returns `true` if `digits` (ASCII digit characters only, no separators) passes
/// the Luhn checksum algorithm used by credit card numbers.
fn luhn_valid(digits: &str) -> bool {
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        let Some(d) = ch.to_digit(10) else {
            return false;
        };
        let val = if double {
            let v = d * 2;
            if v > 9 {
                v - 9
            } else {
                v
            }
        } else {
            d
        };
        sum += val;
        double = !double;
    }
    sum % 10 == 0
}

/// Maximum number of characters consumed into one digit segment.
///
/// Bounds the per-segment work just above the longest value either detector
/// recognises. The binding case is **not** the bare 19-digit card number: it is
/// a 19-digit card written in separator-delimited groups of four, which is 19
/// digits plus 4 separators — 23 characters. An 11-character SSN is well under
/// that. Do not "tidy" this down to 20: doing so truncates a grouped card
/// mid-number, and, worse, a budget that lands on a Luhn-valid prefix of a
/// longer digit run reports a card that is not there (see
/// `digit_run_longer_than_the_segment_budget_stays_clean_in_both_widths`).
///
/// The budget counts **characters, not bytes**, so it does not shrink on
/// multi-byte input — a byte budget would truncate a segment written in
/// multi-byte digits partway through the number and lose the match.
const DIGIT_SEGMENT_MAX_CHARS: usize = 24;

/// The ASCII digit equivalent of `c` — `c` itself for `'0'..='9'`, and the
/// corresponding ASCII digit for the full-width forms `'０'..='９'`
/// (U+FF10–U+FF19). `None` for anything else.
///
/// AAASM-5345: full-width digits render near-identically to ASCII in most
/// fonts, are one keystroke away on any CJK input method, and round-trip
/// through JSON unchanged — so a card number or SSN typed in full-width form
/// was a working evasion of both PII detectors, which compared raw ASCII bytes.
///
/// Normalisation is for **matching only**. A full-width digit occupies three
/// UTF-8 bytes against ASCII's one, so callers must keep every reported offset
/// in terms of the original text; normalising the text and matching on the
/// result would yield offsets that index the wrong bytes.
///
/// `pub(crate)` rather than private so [`crate::locale`] shares this exact
/// mapping instead of copying it. A locale pack that matched raw ASCII bytes
/// would reintroduce AAASM-5345's evasion one recognizer at a time, and a second
/// copy of the table would be free to drift from this one — the digits a
/// Taiwanese identifier is written in are the same digits a card number is
/// written in, so there is one correct answer and it should have one definition.
pub(crate) fn ascii_digit_of(c: char) -> Option<char> {
    match c {
        '0'..='9' => Some(c),
        '\u{FF10}'..='\u{FF19}' => char::from_u32(c as u32 - 0xFF10 + u32::from(b'0')),
        _ => None,
    }
}

/// The ASCII separator equivalent of `c` for [`digit_segment`]'s walk — `' '`
/// for the space forms, `'-'` for the hyphen forms, `None` for anything else.
///
/// AAASM-5364: [`ascii_digit_of`] closed the full-width *digit* evasion, which
/// is the whole of the credit-card case because a bare card carries no
/// separators. It is not the whole of the SSN case: [`is_ssn`] matches the exact
/// shape `DDD-DD-DDDD`, so the hyphens have to normalise too, and the
/// space-grouped card form has the same problem. A CJK input method in full-width
/// mode emits **U+FF0D** when the hyphen key is pressed and **U+3000** for the
/// space bar, so an SSN or a grouped card typed the natural way by a Taiwanese or
/// Japanese user went undetected while its ASCII twin did not.
///
/// The normalisation is for **matching only**, exactly as for digits: both
/// full-width forms are three UTF-8 bytes against ASCII's one, so the caller
/// pushes the ASCII equivalent into the normalised string while advancing `end`
/// by the *original* character's width.
///
/// # The boundary, and why it stops here
///
/// U+2010–U+2015 (hyphen, non-breaking hyphen, figure/en/em dash, horizontal bar)
/// and U+00A0 (no-break space) were considered and **declined**:
///
/// * No input method emits any of them for the hyphen or space key, so admitting
///   them buys nothing against the evasion this rule exists to close — the threat
///   is an input-mode switch, not an arbitrary look-alike glyph.
/// * Each admitted separator lengthens the run [`digit_segment`] will join, and
///   every additional joined run is an independent ~10% chance of a coincidental
///   Luhn pass. The en dash is the standard glyph for a numeric *range*
///   (`1990–2000`, `第 12–15 頁`) — precisely where two unrelated numbers sit
///   adjacent with a dash between them — so it carries that risk at the highest
///   rate of the set for no coverage in return.
///
/// The boundary is cheap to move if a payload is ever observed using one of them;
/// `digit_separator_boundary_declines_en_dash_and_nbsp` pins it so the decision
/// is visible rather than implicit.
fn ascii_separator_of(c: char) -> Option<char> {
    match c {
        ' ' | '\u{3000}' => Some(' '),
        '-' | '\u{FF0D}' => Some('-'),
        _ => None,
    }
}

/// Result of walking one digit segment (see [`digit_segment`]).
struct DigitSegment {
    /// Byte offset just past the segment — where the outer scan resumes, and
    /// the `end` of any finding the segment produces.
    end: usize,
    /// The segment's digits — normalised to ASCII by [`ascii_digit_of`] — and
    /// the separators between them, in order. Matched against the
    /// `DDD-DD-DDDD` SSN shape by [`is_ssn`].
    normalised: String,
    /// The segment's normalised digits only, without separators — what
    /// [`luhn_valid`] computes the checksum over.
    digits: String,
}

/// Walk the digit segment beginning at byte offset `start` (which must be the
/// boundary of a digit character).
///
/// The walk advances one whole character at a time, so [`DigitSegment::end`] is
/// always a valid UTF-8 char boundary of `text`. That is a correctness
/// requirement rather than a nicety: [`ScanResult::redact`] splices the original
/// bytes at a finding's offsets, and a bound landing mid-character would make it
/// fail closed and replace the entire payload with an opaque label.
fn digit_segment(text: &str, start: usize) -> DigitSegment {
    let mut normalised = String::new();
    let mut digits = String::new();
    let mut chars = 0usize;
    let mut end = start;

    while chars < DIGIT_SEGMENT_MAX_CHARS {
        let Some(c) = text[end..].chars().next() else { break };

        if let Some(d) = ascii_digit_of(c) {
            normalised.push(d);
            digits.push(d);
            // Advance by the *original* character's width, never the ASCII
            // equivalent's, so `end` stays an offset into `text`.
            end += c.len_utf8();
            chars += 1;
            continue;
        }

        // Only consume a separator that sits *between* digits. A trailing
        // separator must not be swallowed into the segment, or an SSN like
        // "123-45-6789 " would become 12 bytes and fail the exact-11-byte
        // `is_ssn` check, letting the PII through unredacted (AAASM-4820).
        if let Some(sep) = ascii_separator_of(c) {
            if !digits.is_empty()
                && chars + 1 < DIGIT_SEGMENT_MAX_CHARS
                && text[end + c.len_utf8()..]
                    .chars()
                    .next()
                    .and_then(ascii_digit_of)
                    .is_some()
            {
                // The ASCII equivalent, so `is_ssn`'s exact-11-byte shape check
                // sees `DDD-DD-DDDD` whichever width the hyphens were typed in
                // (AAASM-5364). `end` still advances by the original width.
                normalised.push(sep);
                end += c.len_utf8();
                chars += 1;
                continue;
            }
        }

        break;
    }

    DigitSegment {
        end,
        normalised,
        digits,
    }
}

/// Scans `text` for credit card numbers (Luhn-validated) and SSN patterns (`DDD-DD-DDDD`).
///
/// Digits are normalised by [`ascii_digit_of`] and the separators between them by
/// [`ascii_separator_of`], so a value written in full-width digits (AAASM-5345)
/// or grouped by a full-width hyphen / ideographic space (AAASM-5364) is detected
/// as the same kind as its ASCII equivalent. Findings still span the **original**
/// text: normalisation never reaches the offsets, only the strings the two checks
/// are run against.
fn scan_digit_sequences(text: &str, findings: &mut Vec<CredentialFinding>) {
    let mut i = 0usize;
    while i < text.len() {
        // `i` is always on a char boundary: it advances either by one whole
        // character or to a segment's `end`, which is itself a boundary.
        let Some(c) = text[i..].chars().next() else { break };
        if ascii_digit_of(c).is_none() {
            i += c.len_utf8();
            continue;
        }

        let start = i;
        let segment = digit_segment(text, start);
        let end = segment.end;

        if is_ssn(&segment.normalised) {
            findings.push(CredentialFinding::new(CredentialKind::SsnPattern, start, end));
        } else if segment.digits.len() >= 13 && segment.digits.len() <= 19 && luhn_valid(&segment.digits) {
            findings.push(CredentialFinding::new(CredentialKind::CreditCardLuhn, start, end));
        }
        i = end.max(start + c.len_utf8());
    }
}

/// Computes the Shannon entropy of `s` in bits per **byte**.
///
/// Callers must pass an ASCII-only slice. Bytes and characters coincide only
/// for ASCII, and every threshold this result is compared against
/// ([`ENTROPY_BITS_GATE`]) is specified per character. Feeding it multi-byte
/// UTF-8 measures the encoding rather than the text: Han characters spread
/// their bytes widely and land at 4.6-4.9 bits, above a gate calibrated on
/// English prose, which is how ordinary Chinese was reported as leaked secrets
/// (AAASM-5344). Every call site therefore narrows to an ASCII run first.
fn shannon_entropy(s: &str) -> f64 {
    shannon_entropy_joined(s, "")
}

/// Shannon entropy of `a` followed by `b`, in bits per **byte**, without
/// materialising the concatenation.
///
/// [`scan_separated_base64_runs`] scores a *pair* of runs, because the pair —
/// not either half — is the candidate once a secret has been split. Joining them
/// into a `String` first would put one allocation on the scanner's hot path for
/// every word boundary in the payload, so the frequency table is accumulated over
/// both slices instead. The ASCII-only precondition [`shannon_entropy`] documents
/// applies to both halves for the same reason.
fn shannon_entropy_joined(a: &str, b: &str) -> f64 {
    let total = a.len() + b.len();
    if total == 0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &byte in a.as_bytes().iter().chain(b.as_bytes()) {
        freq[byte as usize] += 1;
    }
    let len = total as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Shannon-entropy gate, in bits per character, over **ASCII** text.
///
/// Base64/base85 encodings of random bytes sit around 5-6 bits/char, while
/// English prose and `snake_case` / `kebab-case` identifiers stay below this.
/// The corpus behind that calibration is ASCII, and the gate is only meaningful
/// against ASCII — see [`shannon_entropy`] for why non-ASCII input measures the
/// UTF-8 encoding instead of the text (AAASM-5344).
/// Note hex tops out at `log2(16) = 4.0` bits/char, so hex-encoded secrets never
/// trip this gate — they are caught by the dedicated hex rule (see
/// [`HEX_RUN_MIN_LEN`]).
const ENTROPY_BITS_GATE: f64 = 4.5;

/// Minimum length of a contiguous hex run (`[0-9a-fA-F]`) flagged as a secret.
///
/// Set to 64 — the length of a hex-encoded 256-bit key (and of a SHA-256
/// digest). The threshold is deliberately high to avoid redacting the shorter
/// hex blobs that pervade normal payloads: 32-char MD5/UUID hex and 40-char git
/// SHA-1 hashes stay below it and are **not** flagged. The accepted tradeoff is
/// that hex blobs of 64+ chars — including SHA-256 digests — are redacted; this
/// is harmless (redacting a public hash leaks nothing) and is the price of
/// closing the hex-encoded-secret evasion, since a hex secret is byte-for-byte
/// indistinguishable from a hash of the same length.
const HEX_RUN_MIN_LEN: usize = 64;

/// Minimum length of a contiguous base64/base64url run flagged as a secret.
///
/// Set to 20 — the same floor the whitespace-token pass uses (AAASM-4071). The
/// token pass only inspects `split_whitespace()` tokens, so a base64 secret in a
/// punctuation-delimited (compact-JSON) context — e.g. `{"api_token":"<64 b64>"}`
/// — is invisible to it: the whole payload is one whitespace token > 64 chars, so
/// pass 1 skips it, and the quote-delimited run was exactly 64 chars, which the
/// old strictly-greater `> 64` bound also skipped, letting a 64-char base64 secret
/// survive `scan()` clean on the authoritative enforce path. Mirroring the pass-1
/// floor here (with `>=`, matching [`HEX_RUN_MIN_LEN`]) closes that gap; the
/// [`ENTROPY_BITS_GATE`] — not the length — is what bounds false positives, so
/// benign structured runs (hex ids, UUIDs, connection strings) stay below the gate
/// and clean regardless of length.
const BASE64_RUN_MIN_LEN: usize = 20;

/// Yields each maximal run of ASCII bytes in `s` as `(byte offset in s, run)`.
///
/// The whitespace-token entropy pass needs this because both halves of its gate
/// are byte-denominated while their thresholds are character-denominated: a
/// 7-character Han phrase is 21 bytes, already inside the 20-64 "looks like a
/// secret" window, and [`shannon_entropy`] then scores its UTF-8 bytes above a
/// gate calibrated on English. Narrowing to ASCII runs restores bytes ==
/// characters, which is what both thresholds were written for (AAASM-5344).
///
/// Runs — rather than dropping any token that holds a non-ASCII byte — is the
/// security-critical part. A secret worth hiding is ASCII by construction
/// (base64, hex, base62 key material), so a whole-token test would let an
/// attacker prepend one glyph from any non-Latin script and carry the secret
/// straight through the gate. Segmenting keeps a *contiguous* ASCII candidate
/// visible no matter what surrounds it.
///
/// # The residual this used to carry is closed (AAASM-5368)
///
/// Because non-ASCII is purely a run boundary here, a glyph inserted into the
/// *middle* of a secret splits it into two runs, and if both fall under the
/// 20-character floor neither is scored by this pass. That was true of a plain
/// **space**, tab or newline before this function existed — separator-splitting
/// defeated the length gate for every separator class, and this function only
/// made a non-ASCII separator behave like the whitespace separators beside it.
///
/// [`scan_separated_base64_runs`] now closes that gap for every separator class
/// at once, by scoring an adjacent *pair* of base64 runs joined across a single
/// separator character. This function is deliberately left alone: narrowing to ASCII runs
/// is what stops the gate scoring UTF-8 bytes, and re-widening it to recover the
/// split case would reintroduce the false-positive defect it exists to fix. The
/// recovery belongs in an additive pass, which is where it now lives.
///
/// What remains open is stated on [`scan_separated_base64_runs`] rather than here:
/// a gap of more than one character, and a secret cut into three or more pieces.
fn ascii_runs(s: &str) -> impl Iterator<Item = (usize, &str)> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while i < bytes.len() && !bytes[i].is_ascii() {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii() {
            i += 1;
        }
        // Both bounds are ASCII-adjacent, hence UTF-8 char boundaries: `start`
        // is an ASCII byte and `i` is either the end of `s` or the lead byte of
        // a multi-byte sequence, since a continuation byte never follows ASCII.
        (start < i).then(|| (start, &s[start..i]))
    })
}

/// Returns `true` if `b` is in the base64 / base64url alphabet
/// (alphanumerics plus `+ / - _`). `=` padding and all delimiters are excluded.
fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_')
}

/// Scans `text` for generic secret-like tokens, reporting them as
/// [`CredentialKind::GenericHighEntropy`]. Four additive passes run; each only
/// *adds* findings, so the literal/URL/PEM detectors are never displaced and the
/// conformance behaviour of the original whitespace pass is preserved exactly.
/// A secret caught by more than one pass yields overlapping same-kind findings
/// that [`scan`]'s final [`dedupe_same_kind_overlaps`] collapses back to one:
///
/// 1. **Whitespace-token entropy** (unchanged spec behaviour for ASCII input) —
///    an ASCII run *within* a whitespace token, of length 20–64 with Shannon
///    entropy > [`ENTROPY_BITS_GATE`]. For ASCII-only text the run and the
///    token are the same slice, so this is the original rule; for mixed text it
///    is what stops the gate scoring UTF-8 bytes (see [`ascii_runs`]).
/// 2. **Long hex run** (AAASM-3870) — a contiguous hex run ≥ [`HEX_RUN_MIN_LEN`],
///    closing the hex-encoding evasion (hex entropy is capped at 4.0 bits/char,
///    below the gate, so pass 1 never catches it at any length).
/// 3. **Base64 run** (AAASM-3870, AAASM-4071) — a contiguous base64/base64url run
///    ≥ [`BASE64_RUN_MIN_LEN`] whose entropy exceeds the gate, closing both the
///    old > 64-char length evasion and the compact-JSON evasion where a base64
///    secret carries no whitespace and its delimited run is ≤ 64 chars.
/// 4. **Separator-grouped hex run** (AAASM-4075) — a hex run broken into groups
///    by `:` / `-` separators (e.g. `de:ad:be:ef:…`) whose total hex-digit count
///    reaches [`HEX_RUN_MIN_LEN`]. Such reformatting splits the contiguous run
///    into 2-char groups that clear neither the pass-2 length bar nor (with `-`
///    kept inside the base64 alphabet) the pass-3 entropy gate, so it evades
///    passes 1-3 entirely; this pass closes that gap.
/// 5. **Separator-split base64 run** (AAASM-5368) — pass 3's rule applied to two
///    adjacent runs joined across a single separator character, closing the
///    length-gate evasion where a secret is simply cut in two, for every
///    separator class at once (see [`scan_separated_base64_runs`]).
///
/// Passes 2-4 need no ASCII narrowing of their own: every byte they accept is
/// selected by an ASCII predicate (`is_ascii_hexdigit`, [`is_base64_char`],
/// [`is_hex_group_separator`]), and every byte of a multi-byte UTF-8 sequence
/// is ≥ `0x80`, so non-ASCII terminates their runs exactly as whitespace does.
/// Their runs are therefore ASCII by construction and score correctly already.
fn scan_high_entropy(text: &str, findings: &mut Vec<CredentialFinding>) {
    // Pass 1: whitespace-delimited high-entropy tokens, length 20–64.
    let mut offset = 0usize;
    for token in text.split_whitespace() {
        let token_offset = text[offset..].find(token).map(|i| offset + i).unwrap_or(offset);
        let whitespace_end = token_offset + token.len();
        // Gate each of the token's ASCII runs, not the token itself. A script
        // that does not delimit words with spaces (Chinese, Japanese, Thai)
        // makes one "token" an entire clause, and both the length window and
        // the entropy gate then measure UTF-8 bytes against character-scale
        // thresholds — which classified ordinary Chinese prose as leaked
        // secrets. See [`ascii_runs`] for why this segments rather than skips
        // (AAASM-5344). For ASCII-only text the run is the whole token, so
        // every pre-existing finding is reproduced byte-identically.
        for (run_offset, run) in ascii_runs(token) {
            let run_start = token_offset + run_offset;
            if (20..=64).contains(&run.len()) && shannon_entropy(run) > ENTROPY_BITS_GATE {
                // The whitespace token can still carry trailing delimiters when a
                // secret is embedded in structured text (e.g. `...key"}]}` in compact
                // JSON). Clamp the finding's `end` at the first token-terminating
                // character so the span covers only the credential — matching how the
                // AC literal scan derives its `end`. The run's own end bounds it too,
                // so a trailing non-ASCII neighbour is never swallowed into the span.
                let end = token_end(text, run_start).min(run_start + run.len());
                findings.push(CredentialFinding::new(
                    CredentialKind::GenericHighEntropy,
                    run_start,
                    end,
                ));
            }
        }
        offset = whitespace_end;
    }

    // Passes 2 & 3: contiguous encoded-blob runs that the token pass misses.
    scan_long_hex_runs(text, findings);
    scan_long_base64_runs(text, findings);
    // Pass 4: separator-grouped hex runs the contiguous passes miss (AAASM-4075).
    scan_separated_hex_runs(text, findings);
    // Pass 5: a base64 run cut in two by one separator (AAASM-5368).
    scan_separated_base64_runs(text, findings);
}

/// Pass 2 — flag every contiguous hex run of length ≥ [`HEX_RUN_MIN_LEN`].
fn scan_long_hex_runs(text: &str, findings: &mut Vec<CredentialFinding>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i - start >= HEX_RUN_MIN_LEN {
            findings.push(CredentialFinding::new(CredentialKind::GenericHighEntropy, start, i));
        }
    }
}

/// Pass 3 — flag every contiguous base64/base64url run of length
/// ≥ [`BASE64_RUN_MIN_LEN`] whose Shannon entropy exceeds [`ENTROPY_BITS_GATE`].
fn scan_long_base64_runs(text: &str, findings: &mut Vec<CredentialFinding>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_base64_char(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_base64_char(bytes[i]) {
            i += 1;
        }
        let run = &text[start..i];
        if run.len() >= BASE64_RUN_MIN_LEN && shannon_entropy(run) > ENTROPY_BITS_GATE {
            findings.push(CredentialFinding::new(CredentialKind::GenericHighEntropy, start, i));
        }
    }
}

/// Returns `true` for the intra-token separators that a secret can be rewritten
/// around to split it into small groups (`de:ad:be:ef…`, `de-ad-be-ef…`). Note
/// `-` is also a base64url character, so dash-grouping additionally dilutes the
/// per-run entropy below [`ENTROPY_BITS_GATE`] — both reasons the contiguous
/// passes miss these tokens.
fn is_hex_group_separator(b: u8) -> bool {
    matches!(b, b':' | b'-')
}

/// Pass 4 — flag a hex run split into groups by `:` / `-` separators whose total
/// hex-digit count reaches [`HEX_RUN_MIN_LEN`] (AAASM-4075).
///
/// Scans each maximal run of `[0-9a-fA-F:-]`, counts only the hex digits (the
/// separators are the evasion and are not part of the secret's entropy), and
/// flags the run — trimmed to its first/last hex digit — when it both contains a
/// separator (a contiguous run is already handled by [`scan_long_hex_runs`]) and
/// carries at least [`HEX_RUN_MIN_LEN`] hex digits. Keying the bar on the same
/// 64-digit threshold as the contiguous rule keeps benign grouped hex — MAC
/// addresses (12 digits) and dash-delimited UUIDs (32 digits) — below the bar.
/// Result of scanning one maximal `[0-9a-fA-F:-]` run (see [`scan_hex_run`]).
struct HexRun {
    /// Byte offset just past the run — where the outer scan resumes.
    end: usize,
    /// Number of hex digits in the run (separators excluded).
    hex_count: usize,
    /// Whether the run contained at least one `:`/`-` separator.
    has_separator: bool,
    /// Offset of the first hex digit, if any (the flagged span's start).
    first_hex: Option<usize>,
    /// Offset of the last hex digit seen (the flagged span's inclusive end).
    last_hex: usize,
}

/// Scan the maximal `[0-9a-fA-F:-]` run beginning at `start`, tallying the hex
/// digits and separators so the caller can decide whether it clears the gate.
fn scan_hex_run(bytes: &[u8], start: usize) -> HexRun {
    let mut i = start;
    let mut hex_count = 0usize;
    let mut has_separator = false;
    let mut first_hex: Option<usize> = None;
    let mut last_hex = start;
    while i < bytes.len() && (bytes[i].is_ascii_hexdigit() || is_hex_group_separator(bytes[i])) {
        if bytes[i].is_ascii_hexdigit() {
            hex_count += 1;
            first_hex.get_or_insert(i);
            last_hex = i;
        } else {
            has_separator = true;
        }
        i += 1;
    }
    HexRun {
        end: i,
        hex_count,
        has_separator,
        first_hex,
        last_hex,
    }
}

fn scan_separated_hex_runs(text: &str, findings: &mut Vec<CredentialFinding>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() && !is_hex_group_separator(bytes[i]) {
            i += 1;
            continue;
        }
        let run = scan_hex_run(bytes, i);
        i = run.end;
        if run.has_separator && run.hex_count >= HEX_RUN_MIN_LEN {
            if let Some(span_start) = run.first_hex {
                findings.push(CredentialFinding::new(
                    CredentialKind::GenericHighEntropy,
                    span_start,
                    run.last_hex + 1,
                ));
            }
        }
    }
}

/// Minimum number of distinct byte values a candidate must carry before
/// [`ENTROPY_BITS_GATE`] can possibly be cleared.
///
/// Not a heuristic and not a filter — an exact necessary condition, used as a
/// fast path. Shannon entropy over an alphabet of `d` distinct symbols is at
/// most `log2(d)`, so a candidate can only exceed 4.5 bits if `log2(d) > 4.5`,
/// i.e. `d > 22.63`, i.e. `d >= 23`. Testing it before scoring therefore cannot
/// change any verdict; it exists so [`scan_separated_base64_runs`] does not clear
/// a 1 KiB frequency table for every word boundary in the payload.
/// `the_distinct_byte_fast_path_cannot_change_a_verdict` pins it from both
/// sides — 22 can never pass the gate, and 23 can.
const MIN_DISTINCT_BYTES_FOR_GATE: u32 = 23;

/// Number of distinct byte values across `a` followed by `b`.
///
/// A 256-bit set held in four words, so the count costs one pass and four
/// `popcount`s with no allocation and no table to clear per candidate.
fn distinct_bytes(a: &str, b: &str) -> u32 {
    let mut seen = [0u64; 4];
    for &byte in a.as_bytes().iter().chain(b.as_bytes()) {
        seen[(byte >> 6) as usize] |= 1u64 << (byte & 63);
    }
    seen.iter().map(|w| w.count_ones()).sum()
}

/// Yields each maximal base64/base64url run in `text` as `(start, end)` byte
/// offsets — the same runs [`scan_long_base64_runs`] scores, exposed as an
/// iterator so pass 5 can look at two of them at once.
///
/// Byte-wise rather than char-wise, and still boundary-safe: [`is_base64_char`]
/// accepts only ASCII, and every byte of a multi-byte UTF-8 sequence is ≥ `0x80`,
/// so a run bound is either an ASCII byte or a lead byte — never a continuation
/// byte. Same argument as [`ascii_runs`].
fn base64_runs(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while i < bytes.len() && !is_base64_char(bytes[i]) {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_base64_char(bytes[i]) {
            i += 1;
        }
        (start < i).then_some((start, i))
    })
}

/// Pass 5 — a base64 run cut in two by a single separator character
/// (AAASM-5368).
///
/// Pass 3 gates a contiguous base64 run at [`BASE64_RUN_MIN_LEN`], so a secret
/// split into two sub-20-character pieces clears neither half of the bar and is
/// not scored — by a space, a tab, a newline or a non-ASCII glyph alike.
/// Separator-splitting was a fully open evasion of the length gate on `main` for
/// every separator class at once.
///
/// This is [`scan_separated_hex_runs`] (AAASM-4075) applied to the entropy gate
/// rather than to a hex-digit count, which is the generalisation that ticket's
/// shape was always pointing at: scan the runs, exclude the separator from what
/// is scored — it is the evasion, not part of the secret's entropy — and hold the
/// rejoined value to the bar its unsplit form would have faced.
///
/// # Why this does not become a false-positive explosion
///
/// Joining fragments freely until the length window is reached swallows whole
/// clauses of running text, which is the defect AAASM-5344 was opened to fix.
/// Three properties bound it instead, and all three are load-bearing:
///
/// * **Base64 alphabet.** The candidate must be drawn from the alphabet encoded
///   key material is drawn from ([`is_base64_char`]) — the same restriction pass 3
///   already applies. This is what keeps ordinary punctuated prose out: without
///   it, joining `RBAC/NetworkPolicy` to `hardening).` clears the gate, because a
///   near-all-distinct string of 27 characters scores `log2(27)` whatever it says.
/// * **Pairs only, both below [`BASE64_RUN_MIN_LEN`].** At most two runs are ever
///   joined, and only when *neither* could have been scored alone — which is
///   exactly the case pass 3 cannot see. Without the second half of that
///   condition the pass reaches past an already-detected secret into the next
///   word: `tok=<40-char PAT> done` would redact ` done`, and a PEM body line
///   would swallow its `-----END` marker.
/// * **A one-character gap.** The evasion is the insertion of *a* separator into
///   a secret. A longer gap — indentation, a paragraph break, sentence spacing —
///   is ordinary text structure with no matching evasion story. It also bounds
///   the span: it can cover at most one character that is not candidate material.
///
/// Measured over 1.8 MB of this repository's own English and Chinese prose and
/// over the committed clean zh-TW corpus, this pass adds **zero** findings.
///
/// # What it does and does not recover
///
/// A split secret now faces exactly the bar its unsplit form faces — no lower,
/// which is the point, and no higher. Because [`ENTROPY_BITS_GATE`] is 4.5 bits
/// and a random base64 run of length `n` scores about `log2(n)` minus its
/// collisions, that bar is only really met from the low thirties upward: a random
/// 24-character run clears it about 6% of the time whether it is split or not,
/// rising to ~90% at 36 and ~96% at 38 (the longest a two-piece split with both
/// halves under the floor can be). Pass 5 does not change that calibration in
/// either direction; it removes the separator as a way of avoiding it.
///
/// # What is still open
///
/// A gap of more than one character, and a split into pieces small enough that no
/// *adjacent pair* reaches [`BASE64_RUN_MIN_LEN`] — a three-way split of a long
/// secret is still caught pairwise, a many-way split into short pieces is not.
/// Both are pinned by `multi_character_gaps_and_many_way_splits_are_documented_residuals`
/// so they stay visible rather than being rediscovered by an attacker. Widening
/// either is a measurable follow-on, not a free change — it is precisely the
/// multi-fragment join the three properties above exist to prevent.
///
/// # The span
///
/// `[first run start, second run end)` — both runs and the one separator between
/// them, following [`scan_separated_hex_runs`], which likewise spans its internal
/// separators. Unlike pass 1 there is no [`token_end`] clamp: the candidate
/// deliberately spans a separator, so clamping at the first delimiter could
/// truncate the span *inside the first run* and leave secret material in the
/// clear. The compact-JSON tail that clamp exists for is covered by pass 3.
fn scan_separated_base64_runs(text: &str, findings: &mut Vec<CredentialFinding>) {
    let mut prev: Option<(usize, usize)> = None;
    for (start, end) in base64_runs(text) {
        if let Some((p_start, p_end)) = prev {
            // Both runs must fall *below* pass 3's floor. A run at or above it is
            // pass 3's to score, and joining it to its neighbour would pull
            // ordinary text into the span — the clause-swallowing shape this pass
            // must not reproduce.
            let both_below_floor = p_end - p_start < BASE64_RUN_MIN_LEN && end - start < BASE64_RUN_MIN_LEN;
            if both_below_floor && text[p_end..start].chars().count() == 1 {
                let (a, b) = (&text[p_start..p_end], &text[start..end]);
                let joined_len = (p_end - p_start) + (end - start);
                if (BASE64_RUN_MIN_LEN..=64).contains(&joined_len)
                    && distinct_bytes(a, b) >= MIN_DISTINCT_BYTES_FOR_GATE
                    && shannon_entropy_joined(a, b) > ENTROPY_BITS_GATE
                {
                    findings.push(CredentialFinding::new(CredentialKind::GenericHighEntropy, p_start, end));
                }
            }
        }
        prev = Some((start, end));
    }
}

/// RFC 5321 caps the local-part of an address at 64 octets. A run longer than
/// this cannot be a legitimate email, so it is skipped — this also bounds the
/// per-`@` work on delimiter-free input (AAASM-3988).
const MAX_EMAIL_LOCAL_LEN: usize = 64;

/// RFC 5321 caps the domain of an address at 255 octets. Capping the forward
/// domain scan at this length keeps [`scan_emails`] linear on pathological
/// input (e.g. `a@a@a@…`) without affecting any real address (AAASM-3988).
const MAX_EMAIL_DOMAIN_LEN: usize = 255;

/// Like [`token_end`] but scans at most `max_len` bytes forward, returning a
/// valid char boundary. Bounding the scan prevents a single `@` from costing
/// O(n) on delimiter-free input, keeping [`scan_emails`] linear overall.
fn bounded_token_end(text: &str, from: usize, max_len: usize) -> usize {
    let mut end = from;
    for (i, c) in text[from..].char_indices() {
        if i >= max_len {
            return from + i;
        }
        if c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')' | ']' | '}') {
            return from + i;
        }
        end = from + i + c.len_utf8();
    }
    end
}

/// Scans `text` for email addresses in a single forward pass.
///
/// The local-part start is tracked as the byte offset just past the most recent
/// token-delimiting character, so it is known in O(1) per `@` rather than an
/// O(n) backward rescan. Combined with the local/domain length caps this keeps
/// the scan linear even on adversarial input such as ~1 MB of consecutive `@`
/// with no delimiters (AAASM-3988 — quadratic-time DoS).
fn scan_emails(text: &str, findings: &mut Vec<CredentialFinding>) {
    // Byte offset just past the most recent delimiter — i.e. the local-part
    // start for the next `@` encountered. Equivalent to the old backward
    // `rfind`, computed incrementally.
    let mut local_start = 0usize;

    for (idx, c) in text.char_indices() {
        if c == '@' {
            // Skip an empty or over-long local-part. The length cap also gates
            // the domain scan below so delimiter-free runs stay linear.
            if idx == local_start || idx - local_start > MAX_EMAIL_LOCAL_LEN {
                continue;
            }

            let domain_start = idx + 1;
            let domain_end = bounded_token_end(text, domain_start, MAX_EMAIL_DOMAIN_LEN);
            let domain = &text[domain_start..domain_end];

            if domain.contains('.') && domain.len() >= 3 {
                findings.push(CredentialFinding::new(
                    CredentialKind::EmailAddress,
                    local_start,
                    domain_end,
                ));
            }
            continue;
        }

        if c.is_whitespace() || matches!(c, '<' | ',' | ';' | '"' | '\'') {
            local_start = idx + c.len_utf8();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- CredentialKind::as_str ---

    #[test]
    fn credential_kind_as_str_round_trips() {
        assert_eq!(CredentialKind::AnthropicKey.as_str(), "AnthropicKey");
        assert_eq!(CredentialKind::AwsAccessKey.as_str(), "AwsAccessKey");
        assert_eq!(CredentialKind::GenericHighEntropy.as_str(), "GenericHighEntropy");
    }

    // --- CredentialKind::ALL catalogue (AAASM-5174) ---

    /// `ALL` must enumerate every built-in kind exactly once and never include
    /// `Custom`. This is the compile-time-ish guard promised in `ALL`'s doc:
    /// the `match` below is exhaustive, so adding a new `CredentialKind`
    /// variant forces a decision here, and the count/uniqueness asserts catch a
    /// variant that was added to the enum but forgotten in `ALL`.
    #[test]
    fn all_enumerates_every_builtin_kind_exactly_once() {
        // 27 built-in detector kinds today; `Custom` is excluded by design.
        assert_eq!(CredentialKind::ALL.len(), 27, "ALL must list all 27 built-in kinds");

        // No duplicates.
        let mut seen = std::collections::BTreeSet::new();
        for k in CredentialKind::ALL {
            assert!(seen.insert(k.as_str()), "duplicate kind in ALL: {}", k.as_str());
        }

        // Custom must not appear in the built-in catalogue.
        assert!(
            !CredentialKind::ALL.contains(&CredentialKind::Custom),
            "Custom is policy-defined, not a built-in — it must not be in ALL"
        );

        // Exhaustiveness: every variant is accounted for. Adding a variant
        // without deciding whether it belongs in `ALL` will fail to compile.
        for k in CredentialKind::ALL
            .iter()
            .chain(std::iter::once(&CredentialKind::Custom))
        {
            match k {
                CredentialKind::AnthropicKey
                | CredentialKind::AwsAccessKey
                | CredentialKind::GcpServiceAccount
                | CredentialKind::OpenAiKey
                | CredentialKind::AzureConnectionString
                | CredentialKind::GitHubAppToken
                | CredentialKind::GitHubOAuthToken
                | CredentialKind::GitHubPat
                | CredentialKind::GitHubRefreshToken
                | CredentialKind::GitHubUserToken
                | CredentialKind::SlackAppToken
                | CredentialKind::SlackBotToken
                | CredentialKind::SlackOAuthToken
                | CredentialKind::SlackRefreshToken
                | CredentialKind::SlackUserToken
                | CredentialKind::MongodbUrl
                | CredentialKind::MysqlUrl
                | CredentialKind::PostgresUrl
                | CredentialKind::EcPrivateKey
                | CredentialKind::OpensshPrivateKey
                | CredentialKind::PgpPrivateKey
                | CredentialKind::PrivateKey
                | CredentialKind::RsaPrivateKey
                | CredentialKind::CreditCardLuhn
                | CredentialKind::EmailAddress
                | CredentialKind::SsnPattern
                | CredentialKind::GenericHighEntropy
                | CredentialKind::Custom => {}
            }
        }
    }

    #[test]
    fn category_and_severity_are_defined_for_every_kind() {
        for k in CredentialKind::ALL {
            assert!(!k.category().is_empty(), "empty category for {}", k.as_str());
            assert!(
                ["critical", "high", "medium", "low"].contains(&k.severity()),
                "unexpected severity {:?} for {}",
                k.severity(),
                k.as_str()
            );
        }
    }

    // --- API key patterns ---

    #[test]
    fn detects_anthropic_key() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("auth: sk-ant-api03-XXXXXXXXXXXXXXXXXXXX");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::AnthropicKey));
    }

    #[test]
    fn detects_openai_key_not_misclassified_as_anthropic() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("key: sk-proj-XXXXXXXXXXXXXXXXXXXX");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::OpenAiKey));
        assert!(!result.findings.iter().any(|f| f.kind == CredentialKind::AnthropicKey));
    }

    #[test]
    fn detects_aws_access_key() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::AwsAccessKey));
    }

    #[test]
    fn detects_gcp_service_account() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan(r#"{"type": "service_account", "project_id": "my-project"}"#);
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::GcpServiceAccount));
    }

    // --- AAASM-3727: case / whitespace bypass variants ---

    #[test]
    fn detects_gcp_service_account_compact_json() {
        // Compact serializer output (no space after the colon) must be caught.
        let scanner = CredentialScanner::new();
        let result = scanner.scan(r#"{"type":"service_account","project_id":"p"}"#);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::GcpServiceAccount),
            "compact GCP service-account JSON must be detected"
        );
    }

    #[test]
    fn detects_gcp_service_account_spaces_around_colon() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan(r#"{ "type" : "service_account" }"#);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::GcpServiceAccount),
            "spaced-colon GCP service-account JSON must be detected"
        );
    }

    #[test]
    fn detects_postgres_url_uppercase_scheme() {
        // RFC 3986 schemes are case-insensitive; an upper-case scheme must not bypass.
        let scanner = CredentialScanner::new();
        let result = scanner.scan("DATABASE_URL=POSTGRES://user:password@host:5432/db");
        assert!(
            result.findings.iter().any(|f| f.kind == CredentialKind::PostgresUrl),
            "upper-case POSTGRES:// scheme must be detected"
        );
    }

    #[test]
    fn detects_lowercase_pem_private_key_header() {
        let scanner = CredentialScanner::new();
        let result =
            scanner.scan("-----begin rsa private key-----\nMIIEpAIBAAKCAQEA...\n-----end rsa private key-----");
        assert!(
            result.findings.iter().any(|f| f.kind == CredentialKind::RsaPrivateKey),
            "lower-case PEM header must be detected"
        );
    }

    // --- Auth token patterns ---

    #[test]
    fn detects_github_pat() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("token: ghp_1234567890abcdefghijklmnopqrstuvwxyz");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::GitHubPat));
    }

    #[test]
    fn detects_github_app_token() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("token: ghs_1234567890abcdefghijklmnopqrstuvwxyz");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::GitHubAppToken));
    }

    #[test]
    fn detects_slack_bot_token() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("SLACK_BOT_TOKEN=xoxb-123456789012-123456789012-XXXXXXXXXXXX");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::SlackBotToken));
    }

    #[test]
    fn detects_slack_user_token() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("token=xoxp-123456789012-123456789012-XXXXXXXXXXXX");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::SlackUserToken));
    }

    #[test]
    fn detects_slack_oauth_token() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("oauth=xoxa-123456789012-123456789012-XXXXXXXXXXXX");
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::SlackOAuthToken));
    }

    // --- AAASM-4128: sibling token prefixes the entropy backstop misses ---

    #[test]
    fn detects_and_redacts_github_oauth_token() {
        let scanner = CredentialScanner::new();
        let text = "token: gho_1234567890abcdefghijklmnopqrstuvwxyz";
        let result = scanner.scan(text);
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::GitHubOAuthToken));
        let redacted = result.redact(text);
        assert!(!redacted.contains("gho_"));
        assert!(redacted.contains("[REDACTED:GitHubOAuthToken]"));
    }

    #[test]
    fn detects_and_redacts_github_user_token() {
        let scanner = CredentialScanner::new();
        let text = "token: ghu_1234567890abcdefghijklmnopqrstuvwxyz";
        let result = scanner.scan(text);
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::GitHubUserToken));
        let redacted = result.redact(text);
        assert!(!redacted.contains("ghu_"));
        assert!(redacted.contains("[REDACTED:GitHubUserToken]"));
    }

    #[test]
    fn detects_and_redacts_github_refresh_token() {
        let scanner = CredentialScanner::new();
        let text = "token: ghr_1234567890abcdefghijklmnopqrstuvwxyz";
        let result = scanner.scan(text);
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::GitHubRefreshToken));
        let redacted = result.redact(text);
        assert!(!redacted.contains("ghr_"));
        assert!(redacted.contains("[REDACTED:GitHubRefreshToken]"));
    }

    #[test]
    fn detects_and_redacts_github_fine_grained_pat() {
        let scanner = CredentialScanner::new();
        let text = "token: github_pat_11ABCDE0000abcdefghij_1234567890abcdefghijklmnopqrstuvwxyzABCDEF";
        let result = scanner.scan(text);
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::GitHubPat));
        let redacted = result.redact(text);
        assert!(!redacted.contains("github_pat_"));
        assert!(redacted.contains("[REDACTED:GitHubPat]"));
    }

    #[test]
    fn detects_and_redacts_slack_app_token() {
        let scanner = CredentialScanner::new();
        let text = "SLACK_APP_TOKEN=xapp-1-A012345678-1234567890123-abcdef0123456789abcdef0123456789abcdef";
        let result = scanner.scan(text);
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::SlackAppToken));
        let redacted = result.redact(text);
        assert!(!redacted.contains("xapp-"));
        assert!(redacted.contains("[REDACTED:SlackAppToken]"));
    }

    #[test]
    fn detects_and_redacts_slack_refresh_token() {
        let scanner = CredentialScanner::new();
        let text = "token=xoxr-123456789012-123456789012-XXXXXXXXXXXX";
        let result = scanner.scan(text);
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::SlackRefreshToken));
        let redacted = result.redact(text);
        assert!(!redacted.contains("xoxr-"));
        assert!(redacted.contains("[REDACTED:SlackRefreshToken]"));
    }

    /// AAASM-4936 (L1): `redact` must fail closed when a finding's span cannot
    /// be spliced. An out-of-range `end` previously hit the implicit skip and
    /// returned the raw text with the flagged secret intact; it must instead
    /// return an opaque redaction so no secret bytes escape.
    #[test]
    fn redact_fails_closed_on_out_of_bounds_span() {
        let text = "the secret is hunter2";
        let result = ScanResult {
            findings: vec![CredentialFinding::from_regex_match(14, 999)],
        };
        let redacted = result.redact(text);
        assert!(!redacted.contains("hunter2"), "raw secret must not leak: {redacted}");
        assert_eq!(redacted, "[REDACTED]");
    }

    /// AAASM-4936 (L1): a span whose bound lands mid-codepoint (not on a UTF-8
    /// char boundary) must also fail closed rather than leave the secret raw.
    #[test]
    fn redact_fails_closed_on_non_char_boundary_span() {
        // "é" occupies bytes 6..8; a span ending at byte 7 is mid-codepoint.
        let text = "secretémore";
        let result = ScanResult {
            findings: vec![CredentialFinding::from_regex_match(0, 7)],
        };
        let redacted = result.redact(text);
        assert!(!redacted.contains("secret"), "raw secret must not leak: {redacted}");
        assert_eq!(redacted, "[REDACTED]");
    }

    // --- AAASM-4946: PEM literal span subsumes overlapping entropy + covers a
    //     short trailing base64 line (ADR 0015 §2/§5.1) ---

    /// A PEM private key laid out as a long (entropy-caught) body line plus a
    /// short final base64 line must redact to a **single** `[REDACTED:<kind>]`
    /// label covering the whole block: the extended literal span subsumes the
    /// overlapping `GenericHighEntropy` body span, and the short tail — which the
    /// length-gated entropy pass misses — cannot leak. This is the invariant the
    /// reverted AAASM-4936 attempt violated by leaving a coexisting entropy label
    /// and the END marker in the clear.
    #[test]
    fn pem_short_trailing_line_subsumed_into_single_label() {
        let scanner = CredentialScanner::new();
        let text = "key=-----BEGIN EC PRIVATE KEY-----\n\
                    MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
                    wJ8=\n\
                    -----END EC PRIVATE KEY-----";
        let redacted = scanner.scan(text).redact(text);
        assert_eq!(
            redacted, "key=[REDACTED:EcPrivateKey]",
            "whole PEM block must collapse to one EcPrivateKey label: {redacted}"
        );
        assert!(
            !redacted.contains("wJ8="),
            "short trailing line must not leak: {redacted}"
        );
        assert!(
            !redacted.contains("[REDACTED:GenericHighEntropy]"),
            "the entropy span must be subsumed, not left coexisting: {redacted}"
        );
        assert!(
            !redacted.contains("-----END"),
            "END marker must fall inside the subsuming span: {redacted}"
        );
    }

    /// The common PEM case — a body fully covered by the entropy pass with no
    /// short trailing line — must keep its existing span: the literal header
    /// label and a separate `GenericHighEntropy` body label, with the END marker
    /// (non-secret) in the clear. Guards against regressing to the reverted
    /// universal block extension, which collapsed this to one label.
    #[test]
    fn pem_fully_covered_body_is_not_extended() {
        let scanner = CredentialScanner::new();
        let text = "KEY=-----BEGIN EC PRIVATE KEY-----\n\
                    MHQCAQEEIOaRgVBExLFbHznv7gHsepSPpLUFKr\n\
                    -----END EC PRIVATE KEY-----";
        let redacted = scanner.scan(text).redact(text);
        assert_eq!(
            redacted, "KEY=[REDACTED:EcPrivateKey]\n[REDACTED:GenericHighEntropy]\n-----END EC PRIVATE KEY-----",
            "fully entropy-covered PEM block must keep its two-span behaviour: {redacted}"
        );
    }

    /// A PEM block whose single body line is itself short/low-entropy (no long
    /// entropy-caught run) has no overlapping entropy span to subsume; its body
    /// in the clear is a documented, accepted residual. It must be left unchanged
    /// so the trigger stays narrow and the existing conformance vectors
    /// (`private_keys_openssh`, `private_keys_pgp`, `private_keys_generic`) stay
    /// byte-identical.
    #[test]
    fn pem_single_short_body_line_is_not_extended() {
        let scanner = CredentialScanner::new();
        let text = "KEY=-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBGRkZGQBCACx\n-----END PGP PRIVATE KEY BLOCK-----";
        let redacted = scanner.scan(text).redact(text);
        assert_eq!(
            redacted, "KEY=[REDACTED:PgpPrivateKey]\n\nlQOYBGRkZGQBCACx\n-----END PGP PRIVATE KEY BLOCK-----",
            "single-short-line PEM block must keep its header-only span: {redacted}"
        );
    }

    #[test]
    fn detects_and_redacts_aws_sts_temporary_key() {
        let scanner = CredentialScanner::new();
        let text = "AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE";
        let result = scanner.scan(text);
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::AwsAccessKey));
        let redacted = result.redact(text);
        assert!(!redacted.contains("ASIA"));
        assert!(redacted.contains("[REDACTED:AwsAccessKey]"));
    }

    // --- Cloud credential patterns ---

    #[test]
    fn detects_azure_connection_string() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=XXXX");
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::AzureConnectionString));
    }

    #[test]
    fn redacts_azure_account_key_value_after_semicolons() {
        // AAASM-3997: the `DefaultEndpointsProtocol=` prefix detector stops at the
        // first `;`, so the AccountKey — which appears two segments later — used to
        // survive redaction in the clear. The dedicated AccountKey pass must redact
        // the secret wherever it falls in the connection string.
        let scanner = CredentialScanner::new();
        let secret = "abc123DEF456ghi789JKL012mno345PQR678stu901VWX234yz==";
        let input = format!(
            "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey={secret};EndpointSuffix=core.windows.net"
        );
        let redacted = scanner.scan(&input).redact(&input);
        assert!(
            !redacted.contains(secret),
            "Azure AccountKey secret leaked past redaction: {redacted}"
        );
        assert!(
            redacted.contains("[REDACTED:AzureConnectionString]"),
            "expected an AzureConnectionString redaction label: {redacted}"
        );
        // The trailing segment after the key is preserved (only the value is redacted).
        assert!(redacted.contains("EndpointSuffix=core.windows.net"));
    }

    // --- Database URL patterns ---

    #[test]
    fn detects_postgres_url() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("DATABASE_URL=postgres://user:password@host:5432/db");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::PostgresUrl));
    }

    #[test]
    fn detects_mysql_url() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("db=mysql://user:secret@localhost/mydb");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::MysqlUrl));
    }

    #[test]
    fn detects_mongodb_url() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("uri=mongodb://admin:pass@cluster0.mongodb.net/mydb");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::MongodbUrl));
    }

    // --- Private key patterns ---

    #[test]
    fn detects_rsa_private_key() {
        let scanner = CredentialScanner::new();
        let result =
            scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::RsaPrivateKey));
    }

    #[test]
    fn detects_ec_private_key() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI...\n-----END EC PRIVATE KEY-----");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::EcPrivateKey));
    }

    #[test]
    fn detects_openssh_private_key() {
        let scanner = CredentialScanner::new();
        let result = scanner
            .scan("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkAAAA=\n-----END OPENSSH PRIVATE KEY-----");
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::OpensshPrivateKey));
    }

    #[test]
    fn detects_generic_private_key() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgk=\n-----END PRIVATE KEY-----");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::PrivateKey));
    }

    #[test]
    fn detects_pgp_private_key() {
        let scanner = CredentialScanner::new();
        let result =
            scanner.scan("-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::PgpPrivateKey));
    }

    // --- PII patterns ---

    #[test]
    fn detects_credit_card_luhn() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("card: 4532015112830366");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::CreditCardLuhn));
    }

    #[test]
    fn detects_credit_card_with_spaces() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("card: 4532 0151 1283 0366");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::CreditCardLuhn));
    }

    #[test]
    fn does_not_flag_invalid_luhn() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("num: 4532015112830367");
        assert!(!result.findings.iter().any(|f| f.kind == CredentialKind::CreditCardLuhn));
    }

    #[test]
    fn detects_ssn() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("SSN: 123-45-6789");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::SsnPattern));
    }

    #[test]
    fn detects_ssn_trailed_by_space() {
        // Regression (AAASM-4820): a trailing space must not be swallowed into the
        // digit segment, which would defeat the exact-11-byte SSN check and forward
        // the PII unredacted.
        let scanner = CredentialScanner::new();
        let text = "SSN 123-45-6789 was leaked";
        let result = scanner.scan(text);
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::SsnPattern));
        let redacted = result.redact(text);
        assert!(!redacted.contains("123-45-6789"));
        assert!(redacted.contains("[REDACTED:SsnPattern]"));
    }

    #[test]
    fn detects_ssn_trailed_by_hyphen() {
        // Regression (AAASM-4820): a trailing hyphen must likewise not be consumed.
        let scanner = CredentialScanner::new();
        let text = "SSN 123-45-6789-leaked";
        let result = scanner.scan(text);
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::SsnPattern));
        let redacted = result.redact(text);
        assert!(!redacted.contains("123-45-6789"));
        assert!(redacted.contains("[REDACTED:SsnPattern]"));
    }

    // --- AAASM-5345: full-width digits (U+FF10–U+FF19) must not evade the
    //     credit-card and SSN detectors. All fixtures are synthetic. ---

    #[test]
    fn detects_fullwidth_credit_card_as_the_same_kind_as_ascii() {
        // The same synthetic Visa test number in both digit widths must be
        // classified identically — switching input mode must not change the
        // verdict.
        let scanner = CredentialScanner::new();
        let ascii = scanner.scan("card=4532015112830366");
        let fullwidth = scanner.scan("card=４５３２０１５１１２８３０３６６");

        let kinds = |r: &ScanResult| r.findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>();
        assert_eq!(kinds(&ascii), vec![CredentialKind::CreditCardLuhn]);
        assert_eq!(kinds(&fullwidth), kinds(&ascii));
    }

    #[test]
    fn detects_fullwidth_ssn_as_the_same_kind_as_ascii() {
        // The SSN detector matches an exact `DDD-DD-DDDD` shape, so it is the
        // detector most likely to be broken by normalisation changing the
        // string's length — assert it survives in full-width form.
        let scanner = CredentialScanner::new();
        let ascii = scanner.scan("ssn=123-45-6789");
        let fullwidth = scanner.scan("ssn=１２３-４５-６７８９");

        let kinds = |r: &ScanResult| r.findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>();
        assert_eq!(kinds(&ascii), vec![CredentialKind::SsnPattern]);
        assert_eq!(kinds(&fullwidth), kinds(&ascii));
    }

    #[test]
    fn detects_mixed_width_credit_card() {
        // A single full-width digit inside an otherwise ASCII number is the
        // cheapest form of the evasion and the case where the byte-offset
        // arithmetic is least uniform — one 3-byte character among 15 1-byte
        // ones.
        let scanner = CredentialScanner::new();
        let result = scanner.scan("card=4532０15112830366");
        assert_eq!(
            result.findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>(),
            vec![CredentialKind::CreditCardLuhn],
        );
    }

    /// Every digit character a redacted payload must never still contain —
    /// both widths, so a partial splice cannot hide behind the assertion.
    fn contains_no_digit(s: &str) -> bool {
        !s.chars().any(|c| c.is_ascii_digit() || matches!(c, '０'..='９'))
    }

    #[test]
    fn redacts_a_fullwidth_credit_card_to_exact_bytes() {
        // Counting findings is not enough: the failure mode this fix risks is a
        // span that is off by a byte or two, which still yields one finding but
        // splices the wrong region and leaves digits in the clear. Assert the
        // exact output bytes.
        let scanner = CredentialScanner::new();
        let text = "card=４５３２０１５１１２８３０３６６";
        let redacted = scanner.scan(text).redact(text);

        assert_eq!(redacted, "card=[REDACTED:CreditCardLuhn]");
        assert!(contains_no_digit(&redacted), "residual digits: {redacted}");
    }

    #[test]
    fn redacts_a_fullwidth_ssn_to_exact_bytes() {
        // The SSN span mixes 3-byte digits with 1-byte separators, so its end
        // offset is the one least likely to survive a width assumption.
        let scanner = CredentialScanner::new();
        let text = "ssn=１２３-４５-６７８９";
        let redacted = scanner.scan(text).redact(text);

        assert_eq!(redacted, "ssn=[REDACTED:SsnPattern]");
        assert!(contains_no_digit(&redacted), "residual digits: {redacted}");
    }

    #[test]
    fn redacts_a_mixed_width_credit_card_to_exact_bytes() {
        let scanner = CredentialScanner::new();
        let text = "card=4532０15112830366";
        let redacted = scanner.scan(text).redact(text);

        assert_eq!(redacted, "card=[REDACTED:CreditCardLuhn]");
        assert!(contains_no_digit(&redacted), "residual digits: {redacted}");
    }

    #[test]
    fn fullwidth_finding_spans_are_char_boundaries_of_the_original_text() {
        // The span contract `redact` depends on, asserted directly rather than
        // inferred from redaction output: offsets index the *original* text and
        // land on character boundaries. A span that satisfies this can always be
        // spliced; one that does not sends `redact` down its fail-closed path.
        let scanner = CredentialScanner::new();
        for text in [
            "card=４５３２０１５１１２８３０３６６",
            "ssn=１２３-４５-６７８９",
            "card=4532０15112830366",
        ] {
            let result = scanner.scan(text);
            assert!(!result.findings.is_empty(), "no finding for {text:?}");
            for f in &result.findings {
                assert!(
                    text.is_char_boundary(f.offset),
                    "offset {} splits a character",
                    f.offset
                );
                assert!(text.is_char_boundary(f.end), "end {} splits a character", f.end);
                // The span must cover the whole value, not a prefix of it.
                assert!(contains_no_digit(&text[..f.offset]));
                assert!(contains_no_digit(&text[f.end..]));
            }
        }
    }

    #[test]
    fn does_not_flag_a_fullwidth_number_that_fails_luhn() {
        // The point of the fix is to widen what reaches the checksum, not to
        // weaken the checksum. A full-width number with one digit altered must
        // be rejected exactly as its ASCII equivalent is
        // (`does_not_flag_invalid_luhn` above).
        let scanner = CredentialScanner::new();
        let result = scanner.scan("num=４５３２０１５１１２８３０３６７");
        assert!(
            !result.findings.iter().any(|f| f.kind == CredentialKind::CreditCardLuhn),
            "Luhn gate must reject a full-width number too: {:?}",
            result.findings,
        );
    }

    #[test]
    fn does_not_flag_a_short_fullwidth_digit_run() {
        // An 8-digit run is below the 13-digit card floor and is not SSN-shaped,
        // so it must stay clean. Full-width digits are ordinary content — order
        // numbers, dates, quantities — in CJK text, and flagging them would make
        // the detector unusable in exactly the locales this fix serves.
        let scanner = CredentialScanner::new();
        let result = scanner.scan("qty=１２３４５６７８");
        assert!(result.is_clean(), "short run must stay clean: {:?}", result.findings);
    }

    #[test]
    fn redact_fails_closed_on_a_span_inside_a_fullwidth_digit() {
        // The concrete instance of the fail-closed guard this change puts at
        // risk. `redact` must never emit the payload with the flagged region
        // intact, so a span landing inside a full-width digit's three bytes has
        // to collapse the whole value to an opaque label rather than splice.
        // Exercised rather than assumed, because the guard is the only thing
        // standing between a mis-computed span and a leak.
        let text = "card=４５３２０１５１１２８３０３６６";
        // `card=` is five bytes; the first full-width digit occupies bytes 5..8,
        // so byte 6 is mid-character.
        let result = ScanResult {
            findings: vec![CredentialFinding::new(CredentialKind::CreditCardLuhn, 5, 6)],
        };

        let redacted = result.redact(text);
        assert_eq!(redacted, "[REDACTED]");
        assert!(contains_no_digit(&redacted), "residual digits: {redacted}");
    }

    #[test]
    fn digit_run_longer_than_the_segment_budget_stays_clean_in_both_widths() {
        // Pins `DIGIT_SEGMENT_MAX_CHARS`, the refactor's riskiest invariant.
        //
        // The budget decides how much of a long digit run one segment swallows,
        // and shrinking it fails in the *false positive* direction: a 30-digit
        // run is not a card number, but its first 19 digits here are
        // Luhn-valid, so a budget of 19 would truncate the segment exactly onto
        // that prefix and report a card that is not there. On the enforce path
        // that means redacting a legitimate payload — worse than the missed
        // detection a too-large budget would cause.
        //
        // The synthetic 19-digit prefix is Luhn-valid by construction; the
        // trailing zeros only push the run past the budget.
        let scanner = CredentialScanner::new();
        let ascii = "num=004532015112830366500000000000";
        let fullwidth = "num=００４５３２０１５１１２８３０３６６５００００００００００００";

        for text in [ascii, fullwidth] {
            let result = scanner.scan(text);
            assert!(
                !result.findings.iter().any(|f| f.kind == CredentialKind::CreditCardLuhn),
                "over-long digit run must not yield a card finding: {:?}",
                result.findings,
            );
        }
    }

    // --- AAASM-5364: the full-width hyphen (U+FF0D) and the ideographic space
    //     (U+3000) are what a CJK input method emits for the hyphen and space
    //     keys, so they must separate digits exactly as their ASCII twins do.
    //     All fixtures are synthetic. ---

    #[test]
    fn detects_an_ssn_grouped_by_the_fullwidth_hyphen() {
        // The case AAASM-5345 left open: it normalised the digits, but `is_ssn`
        // still demanded ASCII hyphens, so a wholly full-width SSN — what a
        // full-width IME actually produces — read as an ungrouped 9-digit run
        // and was not SSN-shaped at all.
        let scanner = CredentialScanner::new();
        let ascii = scanner.scan("ssn=123-45-6789");
        let fullwidth = scanner.scan("ssn=１２３－４５－６７８９");

        let kinds = |r: &ScanResult| r.findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>();
        assert_eq!(kinds(&ascii), vec![CredentialKind::SsnPattern]);
        assert_eq!(kinds(&fullwidth), kinds(&ascii));
    }

    #[test]
    fn detects_an_ssn_whose_digits_are_ascii_but_whose_hyphens_are_not() {
        // The cheapest form of the evasion, and the one a user reaches by
        // accident: ASCII digits typed with the IME still in full-width mode, so
        // only the two separators differ from the detected form.
        let scanner = CredentialScanner::new();
        let result = scanner.scan("ssn=123－45－6789");
        assert_eq!(
            result.findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>(),
            vec![CredentialKind::SsnPattern],
        );
    }

    #[test]
    fn detects_a_card_grouped_by_the_ideographic_space() {
        // The space-grouped card form. Grouping is how card numbers are written
        // on the card itself, so this is the *natural* rendering rather than an
        // adversarial one — and U+3000 is what the space bar emits in full-width
        // mode.
        let scanner = CredentialScanner::new();
        let result = scanner.scan("card=４５３２　０１５１　１２８３　０３６６");
        assert_eq!(
            result.findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>(),
            vec![CredentialKind::CreditCardLuhn],
        );
    }

    #[test]
    fn redacts_fullwidth_separated_values_to_exact_bytes() {
        // Counting findings is not enough: a separator is three bytes here
        // against ASCII's one, so an end offset computed on the normalised form
        // splices the wrong region — one finding, digits still in the clear.
        let scanner = CredentialScanner::new();
        for (text, expected) in [
            ("ssn=１２３－４５－６７８９", "ssn=[REDACTED:SsnPattern]"),
            ("ssn=123－45－6789", "ssn=[REDACTED:SsnPattern]"),
            (
                "card=４５３２　０１５１　１２８３　０３６６",
                "card=[REDACTED:CreditCardLuhn]",
            ),
        ] {
            let redacted = scanner.scan(text).redact(text);
            assert_eq!(redacted, expected, "wrong redaction for {text:?}");
            assert!(contains_no_digit(&redacted), "residual digits: {redacted}");
        }
    }

    #[test]
    fn fullwidth_separated_spans_are_char_boundaries_of_the_original_text() {
        // The span contract `redact` depends on, asserted directly. A separator
        // is the newest way for an offset to land mid-character, since it is the
        // one part of the segment whose normalised width (1 byte) differs from
        // its original width (3 bytes) *and* which the walk may or may not
        // consume depending on what follows it.
        let scanner = CredentialScanner::new();
        for text in [
            "ssn=１２３－４５－６７８９",
            "ssn=123－45－6789",
            "card=４５３２　０１５１　１２８３　０３６６",
        ] {
            let result = scanner.scan(text);
            assert!(!result.findings.is_empty(), "no finding for {text:?}");
            for f in &result.findings {
                assert!(
                    text.is_char_boundary(f.offset),
                    "offset {} splits a character in {text:?}",
                    f.offset
                );
                assert!(
                    text.is_char_boundary(f.end),
                    "end {} splits a character in {text:?}",
                    f.end
                );
                // The span must cover the whole value, not a prefix of it.
                assert!(contains_no_digit(&text[..f.offset]));
                assert!(contains_no_digit(&text[f.end..]));
            }
        }
    }

    #[test]
    fn does_not_flag_a_fullwidth_separated_number_that_fails_luhn() {
        // Widening what reaches the checksum must not weaken the checksum. The
        // final digit is altered from the detected form above, so the only
        // difference between this and a reported card is the Luhn result.
        let scanner = CredentialScanner::new();
        let result = scanner.scan("num=４５３２　０１５１　１２８３　０３６７");
        assert!(
            !result.findings.iter().any(|f| f.kind == CredentialKind::CreditCardLuhn),
            "Luhn gate must reject a full-width-separated number too: {:?}",
            result.findings,
        );
    }

    #[test]
    fn a_grouped_19_digit_card_still_fits_the_segment_budget_in_full_width() {
        // `DIGIT_SEGMENT_MAX_CHARS` is 24 because the binding case is a 19-digit
        // card written in groups of four — 19 digits plus 4 separators, 23
        // characters. That arithmetic is in *characters*, so it has to survive
        // separators that are three bytes each, not just digits that are. A
        // budget accidentally counted in bytes would truncate this segment
        // one-third of the way in and lose the card entirely.
        //
        // The 19-digit number is Luhn-valid by construction, not observed.
        let scanner = CredentialScanner::new();
        for text in [
            "card=4532-0151-1283-0366-500",
            "card=４５３２－０１５１－１２８３－０３６６－５００",
            "card=４５３２　０１５１　１２８３　０３６６　５００",
        ] {
            let result = scanner.scan(text);
            assert_eq!(
                result.findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>(),
                vec![CredentialKind::CreditCardLuhn],
                "grouped 19-digit card must fit the segment budget: {text:?}",
            );
        }
    }

    #[test]
    fn digit_separator_boundary_declines_en_dash_and_nbsp() {
        // Pins the boundary [`ascii_separator_of`] documents, so the decision is
        // visible rather than implicit. U+2013 (en dash) and U+00A0 (no-break
        // space) are *not* separators: no input method emits either for the
        // hyphen or space key, so admitting them would buy no coverage against
        // the input-mode evasion while adding runs for the Luhn check to trip
        // over — the en dash being the standard glyph for a numeric range, i.e.
        // exactly where two unrelated numbers sit adjacent with a dash between.
        //
        // Asserted as **not detected**, deliberately. If a payload is ever
        // observed using one of these, widen `ascii_separator_of` and rewrite
        // this test — do not delete it.
        let scanner = CredentialScanner::new();
        for text in [
            "card=4532\u{2013}0151\u{2013}1283\u{2013}0366",
            "card=4532\u{00A0}0151\u{00A0}1283\u{00A0}0366",
            "ssn=123\u{2013}45\u{2013}6789",
            "ssn=123\u{00A0}45\u{00A0}6789",
        ] {
            assert!(
                scanner.scan(text).is_clean(),
                "separator set widened past its stated boundary for {text:?}",
            );
        }
    }

    #[test]
    fn fullwidth_separators_do_not_flag_ordinary_cjk_prose() {
        // The false-positive guard the widened separator set needs. Dates,
        // phone numbers, ranges and identifiers written with U+FF0D and U+3000
        // are ordinary content in Traditional-Chinese and Japanese documents —
        // they are, in fact, *more* common than the SSN this rule exists to
        // catch. Every line below now reaches the joined-segment path that only
        // ASCII text reached before, and must still produce nothing.
        let scanner = CredentialScanner::new();
        for text in [
            "報表期間　２０２４－０１－０１　至　２０２４－１２－３１，共 365 天。",
            "聯絡電話　０２－１２３４－５６７８，分機 21。",
            "發票號碼　ＡＢ－１２３４５６７８，金額 1,250 元。",
            "會議時間　１０：００－１１：３０，地點　Ｂ棟　３０５　會議室。",
            "版本區間　１．０．０－２．３．４，共 12 個修訂。",
        ] {
            let result = scanner.scan(text);
            assert!(
                result.is_clean(),
                "clean CJK prose produced {:?} for {text:?}",
                result.findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>(),
            );
        }
    }

    #[test]
    fn detects_email_address() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("contact: user@example.com for support");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::EmailAddress));
    }

    #[test]
    fn detects_email_after_delimiter() {
        // The forward-pass local-part tracking must start after the delimiter,
        // matching the previous backward-rfind behaviour.
        let input = "mail to: <alice@example.org>";
        let scanner = CredentialScanner::new();
        let result = scanner.scan(input);
        // The local-part must begin at 'alice' (just past '<'), not at '<'.
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::EmailAddress
                    && input[f.offset..f.end].starts_with("alice@example.org"))
        );
    }

    #[test]
    fn email_scan_is_linear_on_pathological_at_run() {
        // Regression for AAASM-3988: ~1 MB of consecutive '@' with no
        // delimiters previously drove scan_emails to O(n²) (~1e12 ops),
        // hanging the enforcement/redaction path. It must now complete
        // near-instantly and flag nothing.
        let scanner = CredentialScanner::new();
        let payload = "@".repeat(1_000_000);

        let start = std::time::Instant::now();
        let result = scanner.scan(&payload);
        let elapsed = start.elapsed();

        assert!(
            !result.findings.iter().any(|f| f.kind == CredentialKind::EmailAddress),
            "delimiter-free '@' run must not be flagged as an email",
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "email scan took {elapsed:?}; expected well under a second",
        );
    }

    #[test]
    fn email_scan_is_linear_on_alternating_at_run() {
        // A delimiter-free `a@a@a@…` run keeps the domain token scan bounded.
        let scanner = CredentialScanner::new();
        let payload = "a@".repeat(500_000);

        let start = std::time::Instant::now();
        let _ = scanner.scan(&payload);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "alternating '@' run must scan in linear time",
        );
    }

    // --- High-entropy ---

    #[test]
    fn detects_high_entropy_token() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("secret: xK9mP2nQvR7sT4wY1aB6dF3hJ8lN0eC5");
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::GenericHighEntropy));
    }

    #[test]
    fn does_not_flag_short_token_as_high_entropy() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("word: hello");
        assert!(!result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::GenericHighEntropy));
    }

    // --- AAASM-3870: encoding / length evasions ---

    /// A 64-char lowercase-hex secret (hex-encoded 256-bit key) has entropy
    /// capped at 4.0 bits/char, so it slipped past the old 4.5-bit gate. The
    /// dedicated long-hex rule must now flag it.
    #[test]
    fn detects_64_char_lowercase_hex_secret() {
        let scanner = CredentialScanner::new();
        // 64 lowercase hex chars.
        let secret = "deadbeefcafebabe0123456789abcdef0123456789abcdeffedcba9876543210";
        assert_eq!(secret.len(), 64, "fixture must be exactly 64 hex chars");
        let result = scanner.scan(&format!("token={secret}"));
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::GenericHighEntropy),
            "64-char hex secret must be flagged: {:?}",
            result.findings
        );
        assert!(!scanner.scan(secret).is_clean());
    }

    /// A single base64 token longer than 64 chars was skipped entirely by the
    /// old length-bounded rule. Removing the upper bound must now flag it.
    #[test]
    fn detects_base64_token_beyond_64_chars() {
        let scanner = CredentialScanner::new();
        // 88-char base64 of random-looking bytes (entropy well above the gate).
        let secret = "aGVsbG9Xb3JsZFRoaXNJc0FWZXJ5TG9uZ0Jhc2U2NFNlY3JldFRva2VuQmV5b25kU2l4dHlGb3VyQ2hhcnM5OQ";
        assert!(secret.len() > 64, "fixture must exceed the old 64-char cap");
        let result = scanner.scan(&format!("authorization: {secret}"));
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::GenericHighEntropy),
            ">64-char base64 token must be flagged: {:?}",
            result.findings
        );
    }

    /// AAASM-4075: a 64-hex secret reformatted with `:` (or `-`) separators
    /// splits into 2-char groups that clear neither the contiguous-hex length bar
    /// nor the base64 entropy gate, evading passes 1-3. The separator-grouped pass
    /// must still flag it once the total hex-digit count reaches 64.
    #[test]
    fn detects_separator_delimited_hex_secret() {
        let scanner = CredentialScanner::new();
        // The 64-hex secret from `detects_64_char_lowercase_hex_secret`, regrouped
        // into colon-separated byte pairs (32 groups × 2 hex = 64 hex digits).
        let raw = "deadbeefcafebabe0123456789abcdef0123456789abcdeffedcba9876543210";
        let colon = raw
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let dash = colon.replace(':', "-");
        for secret in [&colon, &dash] {
            let result = scanner.scan(&format!("token={secret}"));
            assert!(
                result
                    .findings
                    .iter()
                    .any(|f| f.kind == CredentialKind::GenericHighEntropy),
                "separator-delimited hex secret must be flagged: {secret:?} -> {:?}",
                result.findings
            );
            // And end-to-end the raw secret must not survive redaction.
            let text = format!(r#"{{"api_token":"{secret}"}}"#);
            let redacted = scanner.scan(&text).redact(&text);
            assert!(!redacted.contains(secret.as_str()), "raw secret survived: {redacted}");
        }
    }

    /// A MAC address (12 hex digits) and a dash-delimited UUID (32 hex digits)
    /// carry separators but stay well under the 64-digit bar, so the AAASM-4075
    /// pass must leave them clean — no new false positives.
    #[test]
    fn does_not_flag_short_separated_hex() {
        let scanner = CredentialScanner::new();
        for text in ["mac de:ad:be:ef:00:01 up", "id 550e8400-e29b-41d4-a716-446655440000 ok"] {
            let result = scanner.scan(text);
            assert!(
                !result
                    .findings
                    .iter()
                    .any(|f| f.kind == CredentialKind::GenericHighEntropy),
                "short separated hex wrongly flagged: {text:?} -> {:?}",
                result.findings
            );
        }
    }

    /// A 64-char base64 secret in punctuation-delimited (compact-JSON) context —
    /// `{"api_token":"<64 b64>"}` — has no whitespace, so the whole payload is one
    /// token > 64 chars that pass 1 skips, and the quote-delimited run is exactly
    /// 64 chars, which the old strictly-greater `> 64` bound also skipped, letting
    /// the secret survive `scan()` clean. Lowering the base64-run floor to 20 with
    /// `>=` (AAASM-4071) must now flag and redact it. (Regression.)
    #[test]
    fn detects_64_char_base64_secret_in_compact_json() {
        let scanner = CredentialScanner::new();
        // 64 base64 chars, Shannon entropy ~5.6 bits/char (well above the gate).
        let secret = "xK9mP2nQvR7sT4wY1aB6dF3hJ8lN0cE5gI7kM1oQ3uW9zA2bD4fH6jL8pR0tV5xZ";
        assert_eq!(secret.len(), 64, "fixture must be exactly 64 base64 chars");
        let text = format!(r#"{{"api_token":"{secret}"}}"#);
        let result = scanner.scan(&text);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::GenericHighEntropy),
            "64-char base64 secret in compact JSON must be flagged: {:?}",
            result.findings
        );
        let redacted = result.redact(&text);
        assert!(!redacted.contains(secret), "raw base64 secret survived: {redacted}");
    }

    /// Branded literal prefixes must remain detected after the rewrite — the
    /// long-token rules must not displace the high-signal AC matchers.
    #[test]
    fn branded_prefixes_still_flagged_after_rewrite() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("k=AKIAIOSFODNN7EXAMPLE p=ghp_0123456789abcdefghijklmnopqrstuvwxyz");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::AwsAccessKey));
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::GitHubPat));
    }

    /// Common shorter hex blobs (32-char MD5/UUID, 40-char git SHA-1) and a
    /// plain English sentence must NOT be flagged — the 64-char hex bar and the
    /// 20-char/4.5-bit entropy gate keep these benign payloads clean.
    #[test]
    fn does_not_flag_benign_hex_ids_or_prose() {
        let scanner = CredentialScanner::new();
        let benign = [
            // 40-char git SHA-1.
            "commit 0123456789abcdef0123456789abcdef01234567 fixed it",
            // 32-char MD5 / dashless UUID.
            "etag d41d8cd98f00b204e9800998ecf8427e cached",
            // 36-char UUID with dashes.
            "id 550e8400-e29b-41d4-a716-446655440000 ok",
            // Plain prose and a short id.
            "The quarterly report is ready for review by the team.",
            "user id 42 logged in",
        ];
        for text in &benign {
            let result = scanner.scan(text);
            assert!(
                !result
                    .findings
                    .iter()
                    .any(|f| f.kind == CredentialKind::GenericHighEntropy),
                "benign text wrongly flagged: {:?} -> {:?}",
                text,
                result.findings
            );
        }
    }

    /// End-to-end: a 64-char hex secret embedded in JSON is fully redacted with
    /// no raw fragment surviving.
    #[test]
    fn redact_removes_long_hex_secret() {
        let scanner = CredentialScanner::new();
        let secret = "deadbeefcafebabe0123456789abcdef0123456789abcdeffedcba9876543210";
        let text = format!(r#"{{"api_token":"{secret}"}}"#);
        let result = scanner.scan(&text);
        let redacted = result.redact(&text);
        assert!(!redacted.contains(secret), "raw hex secret survived: {redacted}");
        assert!(redacted.contains("[REDACTED:GenericHighEntropy]"));
    }

    /// AAASM-4093: a `<64-hex><base64-tail>` run trips both the long-hex pass
    /// (span `[start, 64)`) and the base64-run pass (span `[start, 64+K)`). Both
    /// are `GenericHighEntropy` at the same offset; the shorter hex finding sorts
    /// first. The same-kind dedupe must *widen* the survivor's span to the union
    /// rather than drop the longer base64 finding, or `redact` forwards the tail
    /// bytes `[64, 64+K)` in the clear. Assert the full run is masked and that the
    /// secret is still counted exactly once.
    #[test]
    fn redact_covers_base64_tail_after_long_hex_run() {
        let scanner = CredentialScanner::new();
        // 64 hex digits followed by a non-hex base64 tail; the whole contiguous
        // run is base64 and its Shannon entropy clears the gate, so the base64
        // pass spans the full 84 chars while the hex pass stops at 64.
        let hex = "deadbeefcafebabe0123456789abcdef0123456789abcdeffedcba9876543210";
        let tail = "GHIJKLMNOPQRSTUVWXYZ";
        let secret = format!("{hex}{tail}");
        assert_eq!(hex.len(), 64);
        assert!(!tail.is_empty(), "tail must add bytes beyond the 64-hex span");

        let text = format!(r#"{{"api_token":"{secret}"}}"#);
        let result = scanner.scan(&text);

        // Exactly one GenericHighEntropy finding for the run (count unchanged
        // from the AAASM-4071 same-kind dedupe).
        let entropy_findings = result
            .findings
            .iter()
            .filter(|f| f.kind == CredentialKind::GenericHighEntropy)
            .count();
        assert_eq!(
            entropy_findings, 1,
            "expected exactly one GenericHighEntropy finding: {:?}",
            result.findings
        );

        // The whole run — including the base64 tail bytes [64, 64+K) — is masked.
        let redacted = result.redact(&text);
        assert!(!redacted.contains(&secret), "raw secret survived: {redacted}");
        assert!(!redacted.contains(tail), "base64 tail survived un-redacted: {redacted}");
        assert!(!redacted.contains(hex), "hex prefix survived: {redacted}");
        assert!(redacted.contains("[REDACTED:GenericHighEntropy]"));
    }

    /// The additive passes must not disturb the original whitespace-token
    /// behaviour: a database URL still yields its specific URL finding plus the
    /// whole-blob GenericHighEntropy at offset 0 (3 findings), exactly as the
    /// conformance spec encodes it.
    #[test]
    fn additive_passes_preserve_url_and_whole_blob_entropy_findings() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("MONGO_URI=mongodb://admin:pass@cluster0.mongodb.net/mydb");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::MongodbUrl));
        assert!(result
            .findings
            .iter()
            .any(|f| f.kind == CredentialKind::GenericHighEntropy && f.offset == 0));
    }

    // --- luhn_valid helper ---

    #[test]
    fn luhn_valid_visa_test_number() {
        assert!(luhn_valid("4532015112830366"));
    }

    #[test]
    fn luhn_valid_mastercard_test_number() {
        assert!(luhn_valid("5425233430109903"));
    }

    #[test]
    fn luhn_valid_amex_test_number() {
        assert!(luhn_valid("371449635398431"));
    }

    #[test]
    fn luhn_valid_discover_test_number() {
        assert!(luhn_valid("6011111111111117"));
    }

    #[test]
    fn luhn_invalid_altered_digit() {
        assert!(!luhn_valid("4532015112830367"));
    }

    #[test]
    fn luhn_rejects_too_short() {
        assert!(!luhn_valid("123456789012"));
    }

    #[test]
    fn luhn_rejects_too_long() {
        assert!(!luhn_valid("45320151128303661234"));
    }

    // --- shannon_entropy helper ---

    #[test]
    fn entropy_zero_for_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_low_for_repeated_char() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaaaaaaaa") < 1.0);
    }

    #[test]
    fn entropy_high_for_random_base64() {
        assert!(shannon_entropy("xK9mP2nQvR7sT4wY1aB6dF3hJ8lN0") > 4.0);
    }

    #[test]
    fn entropy_moderate_for_english_text() {
        let e = shannon_entropy("Thequickbrownfoxjumpsoverthelazydog");
        assert!(e > 3.0 && e < 5.0);
    }

    // --- ScanResult::redact() and is_clean() ---

    #[test]
    fn redact_replaces_github_pat() {
        let scanner = CredentialScanner::new();
        let text = "key: ghp_abc123XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX end";
        let result = scanner.scan(text);
        let redacted = result.redact(text);
        assert!(!redacted.contains("ghp_"));
        assert!(redacted.contains("[REDACTED:GitHubPat]"));
    }

    #[test]
    fn redact_is_deterministic() {
        let scanner = CredentialScanner::new();
        let text = "key: ghp_abc123XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let result = scanner.scan(text);
        assert_eq!(result.redact(text), result.redact(text));
    }

    #[test]
    fn redact_clean_text_unchanged() {
        let scanner = CredentialScanner::new();
        let text = "This is a normal sentence with no secrets.";
        let result = scanner.scan(text);
        assert!(result.is_clean());
        assert_eq!(result.redact(text), text);
    }

    #[test]
    fn redact_multiple_findings_in_one_pass() {
        let scanner = CredentialScanner::new();
        let text = "a=ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX b=postgres://u:p@host/db";
        let result = scanner.scan(text);
        let redacted = result.redact(text);
        assert!(!redacted.contains("ghp_"));
        assert!(!redacted.contains("postgres://"));
        assert!(redacted.contains("[REDACTED:GitHubPat]"));
        assert!(redacted.contains("[REDACTED:PostgresUrl]"));
    }

    #[test]
    fn is_clean_true_for_benign_text() {
        let scanner = CredentialScanner::new();
        assert!(scanner.scan("Hello, world! No secrets here.").is_clean());
    }

    // --- AAASM-3689: overlapping-findings redaction must not leak fragments ---

    #[test]
    fn redact_overlapping_findings_leaks_no_secret_fragment() {
        // A GitHub PAT embedded in an email-shaped string, adjacent to a
        // postgres URL — the AC-prefix, email, and high-entropy passes produce
        // overlapping byte ranges over the same region. Pre-fix this spliced
        // mangled labels and left raw secret bytes (e.g. "stgresUrl]]").
        let scanner = CredentialScanner::new();
        let text = "user@ghp_tokenAAAAAAAAAAAAAAAAAAAAAAAA.example.com_postgres://x:y@h/d";
        let result = scanner.scan(text);
        let redacted = result.redact(text);

        // No raw secret fragment from a matched region survives.
        assert!(!redacted.contains("ghp_"), "raw GitHub PAT prefix leaked: {redacted}");
        assert!(!redacted.contains("postgres://"), "raw postgres URL leaked: {redacted}");
        assert!(!redacted.contains("tokenAAAA"), "raw token body leaked: {redacted}");
        assert!(
            !redacted.contains("stgresUrl"),
            "mangled-splice secret fragment leaked: {redacted}"
        );
        // Output contains only well-formed redaction labels — no mangled splices.
        assert!(redacted.contains("[REDACTED:"));
        assert!(!redacted.contains("]]"), "malformed nested label produced: {redacted}");
        // Every '[REDACTED:' opener has a matching ']' closer with a known kind —
        // a mangled splice would have left an opener without a clean close.
        for label in redacted.match_indices("[REDACTED:").map(|(i, _)| &redacted[i..]) {
            let close = label.find(']').expect("redaction label must be closed");
            let kind = &label["[REDACTED:".len()..close];
            assert!(!kind.is_empty(), "empty/mangled redaction kind in: {redacted}");
        }
    }

    #[test]
    fn redact_overlap_at_multibyte_boundary_does_not_panic() {
        // Overlapping matches whose region spans multi-byte UTF-8 codepoints.
        // Pre-fix, an overlap boundary landing mid-codepoint panicked in
        // replace_range; the char-boundary guard now makes this impossible.
        let scanner = CredentialScanner::new();
        let text = "postgres://é:é@hosté.com sk-ant-éXXXXXXXXXXXXXXXXXXXX";
        let result = scanner.scan(text);
        // Must not panic, and must not leave the raw scheme behind.
        let redacted = result.redact(text);
        assert!(!redacted.contains("postgres://"), "raw scheme survived: {redacted}");
    }

    #[test]
    fn redact_adjacent_overlapping_findings_merge_into_one_span() {
        // Two findings sharing an offset (prefix + high-entropy over the same
        // token) coalesce so the token is replaced exactly once, not double-spliced.
        let scanner = CredentialScanner::new();
        let text = "tok=ghp_abcdefABCDEF0123456789ABCDEF0123456789 done";
        let result = scanner.scan(text);
        let redacted = result.redact(text);
        assert!(!redacted.contains("ghp_"));
        assert!(!redacted.contains("abcdefABCDEF"), "raw token body leaked: {redacted}");
        assert!(
            redacted.contains(" done"),
            "trailing context must be preserved: {redacted}"
        );
    }

    #[test]
    fn coalesce_keeps_specific_kind_label_over_generic() {
        // A GitHub PAT is also flagged as GenericHighEntropy over the same token.
        // The GenericHighEntropy finding starts at the earlier offset, but the
        // merged span must carry the specific GitHubPat label, not the generic
        // backstop — kind priority wins over offset order.
        let scanner = CredentialScanner::new();
        let text = "token=ghp_abcdefABCDEF0123456789ABCDEF0123456789";
        let result = scanner.scan(text);
        // Sanity: both detectors fired over the same region.
        assert!(
            result.findings.iter().any(|f| f.kind == CredentialKind::GitHubPat),
            "expected a GitHubPat finding: {:?}",
            result.findings
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::GenericHighEntropy),
            "expected a GenericHighEntropy finding: {:?}",
            result.findings
        );
        let redacted = result.redact(text);
        assert!(
            redacted.contains("[REDACTED:GitHubPat]"),
            "merged label must be the specific GitHubPat kind, not GenericHighEntropy: {redacted}"
        );
        assert!(
            !redacted.contains("GenericHighEntropy"),
            "generic backstop label must not win over a specific detector: {redacted}"
        );
        assert!(!redacted.contains("ghp_"), "raw token survived: {redacted}");
    }

    #[test]
    fn coalesce_keeps_db_url_label_over_embedded_email() {
        // A database URL embeds an EmailAddress-shaped span (user@host). The
        // merged span must keep the specific PostgresUrl label, not collapse to
        // the generic EmailAddress backstop.
        let scanner = CredentialScanner::new();
        let text = "DATABASE_URL=postgres://user:password@db.internal:5432/mydb";
        let result = scanner.scan(text);
        let redacted = result.redact(text);
        assert_eq!(
            redacted, "[REDACTED:PostgresUrl]",
            "db-url region must redact to the specific PostgresUrl label: {redacted}"
        );
        assert!(!redacted.contains("postgres://"), "raw scheme survived: {redacted}");
    }

    // --- CredentialKind::Custom and CredentialFinding::from_regex_match ---

    #[test]
    fn custom_kind_as_str_returns_custom() {
        assert_eq!(CredentialKind::Custom.as_str(), "Custom");
    }

    #[test]
    fn from_regex_match_creates_custom_finding() {
        let finding = CredentialFinding::from_regex_match(5, 20);
        assert_eq!(finding.kind, CredentialKind::Custom);
        assert_eq!(finding.offset, 5);
        assert_eq!(finding.matched, "[REDACTED:Custom]");
    }

    // --- False-positive corpus ---

    #[test]
    fn false_positive_corpus_has_no_hard_credential_hits() {
        let scanner = CredentialScanner::new();
        let corpus = [
            "The quick brown fox jumps over the lazy dog.",
            "fn main() { println!(\"Hello, world!\"); }",
            "SELECT * FROM users WHERE id = 42;",
            "cargo build --release --features std",
            "version = \"1.0.0\" edition = \"2021\"",
            "2026-04-27T15:34:15.377+0800",
            "error[E0382]: borrow of moved value: `x`",
        ];
        for text in &corpus {
            let result = scanner.scan(text);
            let hard: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.kind != CredentialKind::GenericHighEntropy)
                .collect();
            assert!(hard.is_empty(), "false positive in: {:?} → {:?}", text, hard);
        }
    }

    // --- ScannerConfig ---

    #[test]
    fn disabled_scanner_returns_empty_result() {
        let config = ScannerConfig {
            disabled: true,
            ..Default::default()
        };
        let scanner = CredentialScanner::with_config(config);
        let result = scanner.scan("sk-proj-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX ghp_XXXXXXXXX");
        assert!(result.is_clean(), "disabled scanner must return no findings");
    }

    #[test]
    fn custom_pattern_detected_as_custom_kind() {
        let config = ScannerConfig {
            custom_patterns: vec!["INTERNAL_SECRET_".into()],
            ..Default::default()
        };
        let scanner = CredentialScanner::with_config(config);
        let result = scanner.scan("token=INTERNAL_SECRET_hello");
        let custom: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.kind == CredentialKind::Custom)
            .collect();
        assert!(!custom.is_empty(), "custom pattern must produce a Custom finding");
        assert!(custom[0].matched.contains("[REDACTED:Custom]"));
    }

    #[test]
    fn custom_pattern_coexists_with_builtin() {
        let config = ScannerConfig {
            custom_patterns: vec!["MY_TOKEN_".into()],
            ..Default::default()
        };
        let scanner = CredentialScanner::with_config(config);
        let text = "a=ghp_XXXXXXXXX b=MY_TOKEN_secret123";
        let result = scanner.scan(text);
        let kinds: Vec<_> = result.findings.iter().map(|f| &f.kind).collect();
        assert!(kinds.contains(&&CredentialKind::GitHubPat));
        assert!(kinds.contains(&&CredentialKind::Custom));
    }

    // --- AAASM-5344: the entropy gate measures ASCII runs, not raw bytes ---
    //
    // Every fixture below is synthetic: no real credential, order reference,
    // phone number or person appears in this section.

    /// Offsets are byte offsets into the slice handed in, since that is what the
    /// caller adds to the token's own offset to place a finding. Each Han
    /// character is 3 UTF-8 bytes, so character indices would be silently wrong.
    #[test]
    fn ascii_runs_segments_a_token_around_its_non_ascii_bytes() {
        let runs: Vec<(usize, &str)> = ascii_runs("日誌abc：xy").collect();
        assert_eq!(runs, vec![(6, "abc"), (12, "xy")]);
    }

    /// The behaviour-preservation claim of the whole change: for ASCII input the
    /// run *is* the token, so the entropy pass sees the same slice at the same
    /// offset it always did and every pre-existing finding is reproduced.
    #[test]
    fn ascii_runs_yields_the_whole_slice_for_ascii_only_input() {
        let token = "xK9mP2nQvR7sT4wY1aB6dF3hJ8lN0eC5";
        let runs: Vec<(usize, &str)> = ascii_runs(token).collect();
        assert_eq!(runs, vec![(0, token)]);
    }

    /// Synthetic mixed `zh-TW`/English agent traffic carrying no credential.
    const BENIGN_ZH_TW_BLOCK: &str = "使用者請求：請協助查詢訂單狀態，並將結果整理成報表。\
         系統回應：查詢完成，共 12 筆資料，處理時間 340 毫秒。\
         備註 (note): the retrieval step returned 12 rows from the orders table. \
         設定檔版本 version = \"1.0.0\"，環境 environment = production。\
         日誌：2026-04-27T12:00:00Z 資訊 處理中 request_id=abc123 狀態正常。\
         客戶反映系統登入失敗請協助處理謝謝，我們已於今日上午完成修復並通知使用者。\
         測試涵蓋率報告顯示核心模組的分支覆蓋率為百分之九十二，尚有兩個邊界案例待補。";

    /// The headline defect: 32 KB of this traffic produced 87 `GenericHighEntropy`
    /// findings while the byte-equivalent English produced none, so a `zh-TW`
    /// tenant on `credential_action: Block` was denied for speaking Chinese.
    #[test]
    fn benign_mixed_zh_tw_traffic_yields_no_findings() {
        let mut corpus = String::new();
        while corpus.len() < 32 * 1024 {
            corpus.push_str(BENIGN_ZH_TW_BLOCK);
        }

        let scanner = CredentialScanner::new();
        let result = scanner.scan(&corpus);

        assert!(
            result.findings.is_empty(),
            "{} bytes of benign zh-TW traffic must be clean, got {} findings: {:?}",
            corpus.len(),
            result.findings.len(),
            result.findings,
        );
        assert_eq!(result.redact(&corpus), corpus, "clean traffic must survive redact()");
    }

    /// The evasion this fix must not create. Skipping any whitespace token that
    /// holds a non-ASCII byte would have fixed the false positives and handed an
    /// attacker a one-glyph bypass: prepend a Han character and the secret rides
    /// through untouched. The fixture's punctuation keeps it out of the base64
    /// alphabet, so passes 2-4 cannot cover for pass 1 here — the whitespace-token
    /// pass is the only thing that can catch it, which is the point.
    ///
    /// Asserting the exact span also pins the offset arithmetic: the finding must
    /// start after the leading Han characters (3 bytes each) and stop before the
    /// trailing ones rather than swallowing the surrounding prose.
    #[test]
    fn a_cjk_prefix_cannot_hide_an_ascii_secret() {
        let scanner = CredentialScanner::new();
        let secret = "Xk9!mQ2*vB7#nR4$wT6%zP1&";
        let text = format!("日誌：{secret}，狀態正常");

        let result = scanner.scan(&text);
        let hit = result
            .findings
            .iter()
            .find(|f| f.kind == CredentialKind::GenericHighEntropy)
            .expect("an ASCII secret must stay visible behind a CJK prefix");

        assert_eq!(&text[hit.offset..hit.end], secret, "span must cover exactly the secret");
        assert!(
            !result.redact(&text).contains(secret),
            "secret must not survive redact()"
        );
    }

    /// Reported reproducer 1. This redacted to `[REDACTED:GenericHighEntropy]
    /// 的狀態`, destroying the sentence around a synthetic order reference that
    /// is not a secret at all.
    #[test]
    fn zh_tw_order_reference_survives_redact() {
        let scanner = CredentialScanner::new();
        let text = "請查詢訂單編號：ORD20260427001 的狀態";
        let result = scanner.scan(text);
        assert!(result.is_clean(), "unexpected findings: {:?}", result.findings);
        assert_eq!(result.redact(text), text);
    }

    /// Reported reproducer 2, redacted in its entirety. The digits are a
    /// synthetic Taiwanese mobile number: 10 digits, so neither the SSN shape
    /// nor the Luhn range applies and the PII passes are not what fired here.
    #[test]
    fn zh_tw_contact_line_survives_redact() {
        let scanner = CredentialScanner::new();
        let text = "聯絡電話：0912-345-678，請於上班時間撥打";
        let result = scanner.scan(text);
        assert!(result.is_clean(), "unexpected findings: {:?}", result.findings);
        assert_eq!(result.redact(text), text);
    }

    /// Reported reproducer 3. The URL is the interesting part: it is a 30-char
    /// ASCII run, squarely inside the 20-64 window, and it stays clean because
    /// its entropy is genuinely below the gate — the same verdict the identical
    /// URL gets in English text. That is the equivalence the fix restores.
    #[test]
    fn zh_tw_document_link_survives_redact() {
        let scanner = CredentialScanner::new();
        let text = "文件連結：https://example.com/docs/guide 請參考";
        let result = scanner.scan(text);
        assert!(result.is_clean(), "unexpected findings: {:?}", result.findings);
        assert_eq!(result.redact(text), text);
    }

    /// Reported reproducer 4, and the end-to-end one: on the enforcement path
    /// this whole sentence became `[REDACTED:GenericHighEntropy]`, so a support
    /// request written in Chinese reached the model as nothing at all.
    #[test]
    fn zh_tw_support_request_survives_redact() {
        let scanner = CredentialScanner::new();
        let text = "客戶反映系統登入失敗請協助處理謝謝";
        let result = scanner.scan(text);
        assert!(result.is_clean(), "unexpected findings: {:?}", result.findings);
        assert_eq!(result.redact(text), text);
    }

    /// Detection-strength guard: the plain ASCII high-entropy token is the case
    /// the whitespace-token pass exists for, and the case this change edits. It
    /// must be unaffected.
    #[test]
    fn ascii_high_entropy_token_is_still_detected() {
        let scanner = CredentialScanner::new();
        let secret = "xK9mP2nQvR7sT4wY1aB6dF3hJ8lN0eC5";
        let text = format!("token={secret}");
        let result = scanner.scan(&text);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::GenericHighEntropy),
            "ASCII high-entropy token must still be flagged: {:?}",
            result.findings
        );
        assert!(!result.redact(&text).contains(secret));
    }

    /// Detection-strength guard for the base64-run pass. Deliberately shaped as
    /// compact JSON with no whitespace and a run past 64 chars, so the
    /// whitespace-token pass cannot reach it — this asserts pass 3 specifically.
    #[test]
    fn ascii_base64_secret_is_still_detected() {
        let scanner = CredentialScanner::new();
        let secret = "aGVsbG9Xb3JsZFRoaXNJc0FWZXJ5TG9uZ0Jhc2U2NFNlY3JldFRva2VuQmV5b25kU2l4dHlGb3VyQ2hhcnM5OQ";
        let text = format!("{{\"api_token\":\"{secret}\"}}");
        let result = scanner.scan(&text);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::GenericHighEntropy),
            "ASCII base64 secret must still be flagged: {:?}",
            result.findings
        );
        assert!(!result.redact(&text).contains(secret));
    }

    /// Detection-strength guard for the hex-run pass. Hex tops out at 4.0
    /// bits/char, below the gate, so this can only ever be caught by the
    /// dedicated length rule — an entropy-side regression would be invisible
    /// here, which is exactly why it needs its own assertion.
    #[test]
    fn ascii_hex_secret_is_still_detected() {
        let scanner = CredentialScanner::new();
        let secret = "deadbeefcafebabe0123456789abcdef0123456789abcdeffedcba9876543210";
        let text = format!("key={secret}");
        let result = scanner.scan(&text);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == CredentialKind::GenericHighEntropy),
            "64-char ASCII hex secret must still be flagged: {:?}",
            result.findings
        );
        assert!(!result.redact(&text).contains(secret));
    }

    /// Detection-strength guard for the literal prefix pass, across the vendor
    /// families whose prefixes dilute run entropy below the gate — for these the
    /// AC scan is the only reliable path, so a regression here is a silent leak.
    #[test]
    fn ascii_api_key_prefixes_are_still_detected() {
        let scanner = CredentialScanner::new();
        for (text, expected) in [
            ("k=AKIAIOSFODNN7EXAMPLE", CredentialKind::AwsAccessKey),
            ("k=ghp_0000000000000000000000000000000000ab", CredentialKind::GitHubPat),
            ("k=sk-ant-api03-000000000000000000000000", CredentialKind::AnthropicKey),
            ("k=xoxb-000000000000-000000000000-abcdef", CredentialKind::SlackBotToken),
            (
                "url=postgres://user:notarealpassword@host:5432/db",
                CredentialKind::PostgresUrl,
            ),
        ] {
            let result = scanner.scan(text);
            assert!(
                result.findings.iter().any(|f| f.kind == expected),
                "{expected:?} must still be flagged: {:?}",
                result.findings
            );
        }
    }

    /// Detection-strength guard for PEM private keys, whose span is assembled
    /// from a literal header plus an entropy-caught body (ADR 0015 §2/§5.1) —
    /// the one detector that depends on the edited pass for part of its answer,
    /// so it needs asserting on both halves rather than on the header alone.
    #[test]
    fn ascii_private_key_block_is_still_detected() {
        let scanner = CredentialScanner::new();
        let body = "MIIEpAIBAAKCAQEAx7Vq2mNfP9sKdL3wQzR8tYuI0oP1aScDeFgHjKlMnBvCxZ";
        let text = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----");
        let result = scanner.scan(&text);
        assert!(
            result.findings.iter().any(|f| f.kind == CredentialKind::RsaPrivateKey),
            "PEM private key header must still be flagged: {:?}",
            result.findings
        );
        assert!(
            !result.redact(&text).contains(body),
            "key material must not survive redact()"
        );
    }

    // --- AAASM-5368: a secret cut in two by one separator must face the same
    //     bar its unsplit form faces. All fixtures are synthetic. ---

    /// A constructed 36-character base64 value, split into two 18-character
    /// halves by the tests below. Not observed key material: the characters are
    /// deliberately near-all-distinct so its entropy (5.11 bits/byte) sits
    /// clearly above the 4.5 gate rather than straddling it, which keeps these
    /// tests measuring the *split* rather than the gate's calibration at short
    /// lengths. Both halves are under `BASE64_RUN_MIN_LEN`, which is what makes
    /// it the evasion this pass closes.
    const SPLIT_SECRET_HEAD: &str = "aB3dEf7hJk9mNp2qRs";
    const SPLIT_SECRET_TAIL: &str = "5tUv8wXy4zC6gLhQ1V";

    /// The former residual, now closed (AAASM-5368). Every row here was asserted
    /// as **not detected** by `separator_split_secret_is_a_known_residual` until
    /// this pass existed: a separator dropped into the middle of a secret split
    /// it into two sub-20-character runs and neither was scored, for every
    /// separator class including a plain space.
    ///
    /// Rewritten rather than deleted, so the flip is visible in one place. The
    /// undivided row is the control — it was detected before and must stay
    /// detected, which is what tells a reader the pass added coverage rather than
    /// moving it.
    #[test]
    fn a_secret_split_by_one_separator_of_any_class_is_detected() {
        let scanner = CredentialScanner::new();
        let (head, tail) = (SPLIT_SECRET_HEAD, SPLIT_SECRET_TAIL);

        for splitter in ["中", "😀", "д", " ", "\t", "\n", ".", ","] {
            let text = format!("log {head}{splitter}{tail} end");
            let result = scanner.scan(&text);
            assert!(
                result
                    .findings
                    .iter()
                    .any(|f| f.kind == CredentialKind::GenericHighEntropy),
                "split secret not detected for splitter {splitter:?}: {:?}",
                result.findings,
            );
            let redacted = result.redact(&text);
            assert!(!redacted.contains(head), "head survived for {splitter:?}: {redacted}");
            assert!(!redacted.contains(tail), "tail survived for {splitter:?}: {redacted}");
        }

        let undivided = format!("log {head}{tail} end");
        assert!(
            !scanner.scan(&undivided).is_clean(),
            "control: the same secret undivided must still be detected"
        );
    }

    #[test]
    fn default_config_matches_new() {
        let default_scanner = CredentialScanner::new();
        let config_scanner = CredentialScanner::with_config(ScannerConfig::default());
        let text = "key=ghp_XXXXXXXXX url=postgres://u:p@host/db";
        let r1 = default_scanner.scan(text);
        let r2 = config_scanner.scan(text);
        assert_eq!(r1.findings.len(), r2.findings.len());
        for (a, b) in r1.findings.iter().zip(r2.findings.iter()) {
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.offset, b.offset);
        }
    }
}
