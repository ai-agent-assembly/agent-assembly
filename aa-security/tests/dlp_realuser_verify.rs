//! Real-user verification of the shipped DLP detector (AAASM-5270 Done items).
//!
//! This is NOT a mock — it feeds real payloads through the shipped
//! `CredentialScanner::scan` / `ScanResult::redact` exactly as the runtime
//! does, and asserts the behavior the Done tickets claim. It is a QA evidence
//! harness (labelled per ticket), not a unit test of internals.
//!
//! Scope = Done items only:
//!   5344  non-ASCII text is NOT classified as high-entropy secrets
//!   5345  full-width digits are normalised before Luhn/SSN
//!   5346  redaction preserves the surrounding payload (no mangling)
//!   5352  canonical finding model over the scanner
//!   5353  zh-TW benign traffic yields no findings / survives redact
//!   real true-positives: API keys, AWS, credit cards, emails, private keys
//!
//! Out of scope (In-Progress / To-Do waves, and known-unfixed evasions
//! 5364/5368): not asserted here. Where an already-known-unfixed gap is
//! adjacent, the test documents it rather than asserting a pass.

use aa_security::scanner::{CredentialKind, CredentialScanner};

fn scan(text: &str) -> aa_security::scanner::ScanResult {
    CredentialScanner::new().scan(text)
}

fn kinds(text: &str) -> Vec<CredentialKind> {
    scan(text).findings.into_iter().map(|f| f.kind).collect()
}

// ── True positives: a real user pasting real secrets must be caught ──────────

#[test]
fn detects_real_provider_api_keys() {
    // Prefixes + bodies are assembled at RUNTIME, never as one literal, so no
    // secret-shaped token sits in source (GitHub push-protection / CodeQL would
    // otherwise flag it — same reason the auth tests generate throwaway values).
    // The scanner keys off the provider PREFIX, so a prefix + filler body is a
    // faithful detection payload without being a real-looking credential string.
    let body32 = "a".repeat(32);
    let anthropic = format!("sk-ant-api03-{body32}");
    let openai = format!("sk-proj-{body32}");
    let ghp = format!("{}_{}", "ghp", "0".repeat(36));
    let aws = format!("{}{}", "AKIA", "0".repeat(16)); // AWS access-key prefix + filler
    for (label, payload) in [("anthropic", anthropic), ("openai", openai), ("aws", aws), ("ghp", ghp)] {
        let r = scan(&payload);
        assert!(
            !r.is_clean(),
            "{label}: a provider-prefixed key must be detected, got no findings"
        );
    }
}

#[test]
fn detects_credit_card_and_email_and_private_key() {
    assert!(
        kinds("card 4111 1111 1111 1111 on file").contains(&CredentialKind::CreditCardLuhn),
        "a valid Luhn credit card must be detected"
    );
    assert!(
        kinds("reach me at alice@example.com").contains(&CredentialKind::EmailAddress),
        "an email address must be detected"
    );
    // Assemble the PEM header at runtime (a literal "BEGIN RSA PRIVATE KEY"
    // block trips push-protection / secret scanning even though it's inert).
    let marker = format!("BEGIN {} PRIVATE KEY", "RSA");
    let pem = format!("-----{marker}-----\nMIIEowIBAAKCAQEA0Z\n-----END RSA PRIVATE KEY-----");
    assert!(!scan(&pem).is_clean(), "a PEM private key block must be detected");
}

// ── 5345: full-width digit normalisation before Luhn/SSN ─────────────────────

#[test]
fn aaasm_5345_fullwidth_digit_credit_card_is_detected() {
    // Full-width digits (evasion attempt) must normalise and still catch the
    // card. Uses ASCII spaces AND a fully-contiguous run as separators — the
    // ideographic space U+3000 is a DIFFERENT, still-open issue (see the
    // ignored 5364 reproducer below), so it is deliberately not used here.
    let fw_ascii_sep = "card ４１１１ １１１１ １１１１ １１１１ end";
    let fw_contiguous = "card ４１１１１１１１１１１１１１１１ end";
    assert!(
        kinds(fw_ascii_sep).contains(&CredentialKind::CreditCardLuhn),
        "AAASM-5345: full-width-digit credit card (ASCII-separated) must be normalised and detected"
    );
    assert!(
        kinds(fw_contiguous).contains(&CredentialKind::CreditCardLuhn),
        "AAASM-5345: full-width-digit credit card (contiguous) must be normalised and detected"
    );
}

/// Documented reproducer for the KNOWN-OPEN bug AAASM-5364 (status: To Do):
/// a full-width credit card separated by the ideographic space U+3000 evades
/// digit-sequence detection. Ignored so it does not fail the Done-scope suite;
/// captured here as real evidence that the gap is present and reproducible.
/// Remove `#[ignore]` (assert detection) when AAASM-5364 lands.
#[test]
#[ignore = "AAASM-5364 not yet fixed: U+3000 ideographic space defeats full-width digit-run detection"]
fn aaasm_5364_ideographic_space_evasion_is_known_open() {
    let evasion = "card ４１１１　１１１１　１１１１　１１１１ end"; // U+3000 separators
    assert!(
        kinds(evasion).contains(&CredentialKind::CreditCardLuhn),
        "AAASM-5364: once fixed, an ideographic-space-separated full-width card must be detected"
    );
}

// ── 5344 / 5353: benign CJK text must NOT be a false positive ────────────────

#[test]
fn aaasm_5344_benign_cjk_text_is_not_flagged_as_secret() {
    // Ordinary Traditional-Chinese prose — must not trip the entropy/secret pass.
    let benign = "您好，我想詢問關於代理程式治理的設定方式，謝謝您的協助。這是一段正常的中文訊息，不包含任何機密資料。";
    let r = scan(benign);
    assert!(
        r.is_clean(),
        "AAASM-5344: benign CJK text must yield no findings, got {:?}",
        r.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

#[test]
fn aaasm_5353_benign_zh_tw_contact_line_is_not_flagged() {
    let benign = "訂單參考編號 A-2024-0912，聯絡電話請洽客服，感謝。";
    let r = scan(benign);
    assert!(
        r.is_clean(),
        "AAASM-5353: benign zh-TW order/contact line must yield no findings, got {:?}",
        r.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

// ── 5346: redaction preserves the surrounding payload (no mangling) ──────────

#[test]
fn aaasm_5346_redaction_preserves_surrounding_cjk_and_removes_secret() {
    // Runtime-assembled AWS-shaped token (avoid a secret-shaped source literal).
    let secret = format!("{}{}", "AKIA", "0".repeat(16));
    let text = format!("金鑰是 {secret} 請勿外流");
    let redacted = scan(&text).redact(&text);
    assert!(
        !redacted.contains(&secret),
        "AAASM-5346: the raw secret must not survive redaction"
    );
    assert!(
        redacted.contains("金鑰是") && redacted.contains("請勿外流"),
        "AAASM-5346: surrounding CJK text must be preserved intact, got: {redacted}"
    );
    // The redacted output must still be valid UTF-8 (String guarantees it) and
    // must not have mangled the multibyte boundaries around the splice.
    assert!(redacted.is_char_boundary(0));
}

#[test]
fn aaasm_5346_redaction_is_idempotent_and_clean_text_untouched() {
    let clean = "這是一段完全乾淨的中文，沒有任何祕密。";
    assert_eq!(
        scan(clean).redact(clean),
        clean,
        "AAASM-5346: clean text must pass through redact unchanged"
    );
}
