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
    /// High-entropy or long encoded token: a whitespace token of length 20–64
    /// with Shannon entropy > 4.5 bits/char, a contiguous hex run ≥ 64 chars, or
    /// a contiguous base64 run > 64 chars above the entropy gate.
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
            | Self::GitHubPat
            | Self::MongodbUrl
            | Self::MysqlUrl
            | Self::OpenAiKey
            | Self::OpensshPrivateKey
            | Self::PgpPrivateKey
            | Self::PostgresUrl
            | Self::PrivateKey
            | Self::RsaPrivateKey
            | Self::SlackBotToken
            | Self::SlackOAuthToken
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
    /// after each replacement. Spans whose boundaries do not fall on UTF-8
    /// character boundaries are skipped rather than spliced, making the former
    /// mid-codepoint panic structurally impossible.
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
    /// 1. Aho-Corasick literal prefix scan — O(n), 18 patterns covering API keys,
    ///    auth tokens, cloud credentials, database URLs, and PEM private key headers.
    /// 2. Credit card and SSN digit-sequence scan.
    /// 3. Email address scan.
    /// 4. Generic high-entropy / long-encoded-blob scan: a 20–64 whitespace token
    ///    above the entropy gate, a contiguous hex run ≥ 64 chars, or a base64
    ///    run > 64 chars above the gate (see [`scan_high_entropy`]).
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

        // Phase 4: High-entropy / long-hex tokens (encoding & length evasions, AAASM-3870)
        scan_high_entropy(text, &mut findings);

        // Phase 5: Azure `AccountKey=` values wherever they appear in a
        //          connection string (AAASM-3997).
        scan_azure_account_key(text, &mut findings);

        findings.sort_by_key(|f| f.offset);
        ScanResult { findings }
    }
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

/// Shannon-entropy gate, in bits per character.
///
/// Base64/base85 encodings of random bytes sit around 5-6 bits/char, while
/// English prose and `snake_case` / `kebab-case` identifiers stay below this.
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
/// The whitespace-token pass below already covers high-entropy tokens of length
/// 20–64; this strictly-greater bound (> 64) is the additive AAASM-3870 rule that
/// catches the long encoded blobs the 64-byte cap skipped, without re-flagging
/// anything the token pass already handles. Combined with the entropy gate it
/// stays clear of long-but-structured strings (e.g. connection strings) whose
/// per-run entropy is below the gate.
const BASE64_RUN_MIN_LEN: usize = 64;

/// Returns `true` if `b` is in the base64 / base64url alphabet
/// (alphanumerics plus `+ / - _`). `=` padding and all delimiters are excluded.
fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_')
}

/// Scans `text` for generic secret-like tokens, reporting them as
/// [`CredentialKind::GenericHighEntropy`]. Three additive passes run; each only
/// *adds* findings, so the literal/URL/PEM detectors are never displaced and the
/// conformance behaviour of the original whitespace pass is preserved exactly:
///
/// 1. **Whitespace-token entropy** (unchanged spec behaviour) — a whitespace
///    token of length 20–64 with Shannon entropy > [`ENTROPY_BITS_GATE`].
/// 2. **Long hex run** (AAASM-3870) — a contiguous hex run ≥ [`HEX_RUN_MIN_LEN`],
///    closing the hex-encoding evasion (hex entropy is capped at 4.0 bits/char,
///    below the gate, so pass 1 never catches it at any length).
/// 3. **Long base64 run** (AAASM-3870) — a contiguous base64/base64url run
///    longer than [`BASE64_RUN_MIN_LEN`] whose entropy exceeds the gate, closing
///    the > 64-char length evasion that the pass-1 upper bound skipped.
/// 4. **Separator-grouped hex run** (AAASM-4075) — a hex run broken into groups
///    by `:` / `-` separators (e.g. `de:ad:be:ef:…`) whose total hex-digit count
///    reaches [`HEX_RUN_MIN_LEN`]. Such reformatting splits the contiguous run
///    into 2-char groups that clear neither the pass-2 length bar nor (with `-`
///    kept inside the base64 alphabet) the pass-3 entropy gate, so it evades
///    passes 1-3 entirely; this pass closes that gap.
fn scan_high_entropy(text: &str, findings: &mut Vec<CredentialFinding>) {
    // Pass 1: whitespace-delimited high-entropy tokens, length 20–64.
    let mut offset = 0usize;
    for token in text.split_whitespace() {
        let token_offset = text[offset..].find(token).map(|i| offset + i).unwrap_or(offset);
        let whitespace_end = token_offset + token.len();
        let len = token.len();
        if (20..=64).contains(&len) && shannon_entropy(token) > ENTROPY_BITS_GATE {
            // The whitespace token can still carry trailing delimiters when a
            // secret is embedded in structured text (e.g. `...key"}]}` in compact
            // JSON). Clamp the finding's `end` at the first token-terminating
            // character so the span covers only the credential — matching how the
            // AC literal scan derives its `end`.
            let end = token_end(text, token_offset);
            findings.push(CredentialFinding::new(
                CredentialKind::GenericHighEntropy,
                token_offset,
                end,
            ));
        }
        offset = whitespace_end;
    }

    // Passes 2 & 3: contiguous encoded-blob runs that the token pass misses.
    scan_long_hex_runs(text, findings);
    scan_long_base64_runs(text, findings);
    // Pass 4: separator-grouped hex runs the contiguous passes miss (AAASM-4075).
    scan_separated_hex_runs(text, findings);
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

/// Pass 3 — flag every contiguous base64/base64url run longer than
/// [`BASE64_RUN_MIN_LEN`] whose Shannon entropy exceeds [`ENTROPY_BITS_GATE`].
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
        if run.len() > BASE64_RUN_MIN_LEN && shannon_entropy(run) > ENTROPY_BITS_GATE {
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
fn scan_separated_hex_runs(text: &str, findings: &mut Vec<CredentialFinding>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() && !is_hex_group_separator(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
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
        if has_separator && hex_count >= HEX_RUN_MIN_LEN {
            if let Some(span_start) = first_hex {
                findings.push(CredentialFinding::new(
                    CredentialKind::GenericHighEntropy,
                    span_start,
                    last_hex + 1,
                ));
            }
        }
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
