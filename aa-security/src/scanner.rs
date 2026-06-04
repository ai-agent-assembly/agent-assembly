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
    /// AWS access key ID (prefix `AKIA`).
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
    /// GitHub personal access token (prefix `ghp_`).
    GitHubPat,
    /// Slack bot token (prefix `xoxb-`).
    SlackBotToken,
    /// Slack OAuth token (prefix `xoxa-`).
    SlackOAuthToken,
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
    /// High-entropy token (Shannon entropy > 4.5 bits/char, length 20–64 bytes).
    GenericHighEntropy,
    // Policy-defined
    /// A pattern defined in the policy document's `data.sensitive_patterns` field.
    Custom,
}

impl CredentialKind {
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
            Self::GitHubPat => "GitHubPat",
            Self::MongodbUrl => "MongodbUrl",
            Self::MysqlUrl => "MysqlUrl",
            Self::OpenAiKey => "OpenAiKey",
            Self::OpensshPrivateKey => "OpensshPrivateKey",
            Self::PgpPrivateKey => "PgpPrivateKey",
            Self::PostgresUrl => "PostgresUrl",
            Self::PrivateKey => "PrivateKey",
            Self::RsaPrivateKey => "RsaPrivateKey",
            Self::SlackBotToken => "SlackBotToken",
            Self::SlackOAuthToken => "SlackOAuthToken",
            Self::SlackUserToken => "SlackUserToken",
            Self::SsnPattern => "SsnPattern",
            Self::Custom => "Custom",
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
    /// Replacements are applied in reverse offset order so earlier byte positions
    /// remain valid after each splice. The `end` field of each finding records the
    /// original match boundary and is used here without being exposed in the public API.
    pub fn redact(&self, text: &str) -> String {
        let mut sorted: Vec<&CredentialFinding> = self.findings.iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.offset));
        let mut result = text.to_string();
        for finding in sorted {
            if finding.end <= result.len() && finding.offset <= finding.end {
                result.replace_range(finding.offset..finding.end, &finding.matched);
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
    /// 1. Aho-Corasick literal prefix scan — O(n), 18 patterns covering API keys,
    ///    auth tokens, cloud credentials, database URLs, and PEM private key headers.
    /// 2. Credit card and SSN digit-sequence scan.
    /// 3. Email address scan.
    /// 4. High-entropy token scan (Shannon entropy > 4.5 bits/char, length 20–64).
    pub fn scan(&self, text: &str) -> ScanResult {
        if self.disabled {
            return ScanResult { findings: Vec::new() };
        }

        let mut findings = Vec::new();

        // Phase 1: AC literal prefix scan (API keys, auth tokens, cloud creds,
        //          database URLs, PEM private key headers — 18 patterns + custom)
        for mat in self.patterns.find_iter(text) {
            let kind = self.kinds[mat.pattern()].clone();
            let offset = mat.start();
            let end = token_end(text, mat.end());
            findings.push(CredentialFinding::new(kind, offset, end));
        }

        // Phase 2: PII — credit card numbers and SSN patterns
        scan_digit_sequences(text, &mut findings);

        // Phase 3: Email addresses
        scan_emails(text, &mut findings);

        // Phase 4: High-entropy tokens (Shannon entropy > 4.5 bits/char, length 20–64)
        scan_high_entropy(text, &mut findings);

        findings.sort_by_key(|f| f.offset);
        ScanResult { findings }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns the byte index of the first token-terminating character at or after
/// `from`. Token terminators are whitespace and common delimiters.
fn token_end(text: &str, from: usize) -> usize {
    text[from..]
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')' | ']' | '}'))
        .map(|i| from + i)
        .unwrap_or(text.len())
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

/// Scans `text` for credit card numbers (Luhn-validated) and SSN patterns (`DDD-DD-DDDD`).
fn scan_digit_sequences(text: &str, findings: &mut Vec<CredentialFinding>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }

        let start = i;
        let mut digits = String::new();
        let mut j = i;
        let limit = (start + 24).min(bytes.len());

        while j < limit {
            match bytes[j] {
                b if b.is_ascii_digit() => {
                    digits.push(b as char);
                    j += 1;
                }
                b' ' | b'-' if !digits.is_empty() => {
                    j += 1;
                }
                _ => break,
            }
        }

        let end = j;
        let segment = &text[start..end];

        if is_ssn(segment) {
            findings.push(CredentialFinding::new(CredentialKind::SsnPattern, start, end));
        } else if digits.len() >= 13 && digits.len() <= 19 && luhn_valid(&digits) {
            findings.push(CredentialFinding::new(CredentialKind::CreditCardLuhn, start, end));
        }
        i = end.max(i + 1);
    }
}

/// Computes the Shannon entropy of `s` in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Scans `text` for high-entropy whitespace-delimited tokens (> 4.5 bits/char,
/// length 20–64 bytes) and reports them as [`CredentialKind::GenericHighEntropy`].
fn scan_high_entropy(text: &str, findings: &mut Vec<CredentialFinding>) {
    let mut offset = 0usize;
    for token in text.split_whitespace() {
        let token_offset = text[offset..].find(token).map(|i| offset + i).unwrap_or(offset);
        let token_end_pos = token_offset + token.len();
        let len = token.len();
        if (20..=64).contains(&len) && shannon_entropy(token) > 4.5 {
            findings.push(CredentialFinding::new(
                CredentialKind::GenericHighEntropy,
                token_offset,
                token_end_pos,
            ));
        }
        offset = token_end_pos;
    }
}

/// Scans `text` for email addresses by locating `@` signs and expanding outward.
fn scan_emails(text: &str, findings: &mut Vec<CredentialFinding>) {
    let mut search = text;
    let mut base = 0usize;

    while let Some(at) = search.find('@') {
        let abs_at = base + at;

        let local_start = text[..abs_at]
            .rfind(|c: char| c.is_whitespace() || matches!(c, '<' | ',' | ';' | '"' | '\''))
            .map(|i| i + 1)
            .unwrap_or(0);

        let domain_end = token_end(text, abs_at + 1);
        let local = &text[local_start..abs_at];
        let domain = &text[abs_at + 1..domain_end];

        if !local.is_empty() && domain.contains('.') && domain.len() >= 3 {
            findings.push(CredentialFinding::new(
                CredentialKind::EmailAddress,
                local_start,
                domain_end,
            ));
        }

        let next = abs_at + 1;
        if next >= text.len() {
            break;
        }
        search = &text[next..];
        base = next;
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
    fn detects_email_address() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("contact: user@example.com for support");
        assert!(result.findings.iter().any(|f| f.kind == CredentialKind::EmailAddress));
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
