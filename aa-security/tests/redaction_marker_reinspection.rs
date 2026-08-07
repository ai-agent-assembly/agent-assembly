//! AAASM-5441 — a correctly scrubbed body must re-inspect clean.
//!
//! The scanner writes `[REDACTED:<kind>]` over every value it finds. Those
//! labels are its own output, not the payload's content, and scoring them as
//! payload inverted the meaning of the signal: a proxy that redacted properly
//! and then re-inspected the bytes it was about to forward reported that they
//! still carried a credential, so **the better it behaved the less protective it
//! looked**. It also did not converge — each re-scan spliced another label in,
//! so a payload crossing two inspection points accumulated markers instead of
//! reaching a fixed point.
//!
//! # What these tests must not become
//!
//! "Scanning a redaction label finds nothing" is true of the label on its own
//! even *without* the fix. The longest of them, `[REDACTED:GenericHighEntropy]`,
//! is 29 bytes at 4.3492 bits over 22 distinct values — below the 4.5-bit gate,
//! and below the 23 distinct values that gate arithmetically requires, so it
//! cannot clear it at any length. A test built on the label in isolation
//! therefore passes for the wrong reason and proves nothing. The defect needs
//! the label to be **pooled into a longer candidate**: in a compact JSON body
//! the whole payload is one whitespace token, and the label's brackets, colon
//! and mixed case carry that token to 4.7582 bits, over the gate.
//!
//! Every assertion here is therefore made over a realistic scrubbed body, and
//! each is preceded by a non-vacuity check that the body is non-empty, carries a
//! label, and reaches the entropy pass's 20-64 character window at all.

use aa_security::{CredentialKind, CredentialScanner, ScanResult};

/// Synthetic Anthropic-shaped key. Not a real credential.
const ANTHROPIC_SECRET: &str = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

/// Synthetic GitHub-PAT-shaped token. Not a real credential.
const GITHUB_SECRET: &str = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

/// A value carrying no branded prefix at all, so the assertions that use it are
/// about the **entropy** pass rather than the literal-prefix pass. Synthetic.
const ENTROPY_SECRET: &str = "8f4Ke2Lq9ZvR1sTuXwYb3Nc7";

/// Bodies in the shapes the enforcement layers actually hand the scanner.
fn representative_bodies() -> Vec<String> {
    vec![
        format!(r#"{{"model":"claude-3","api_key":"{ANTHROPIC_SECRET}"}}"#),
        format!(r#"{{"token":"{GITHUB_SECRET}"}}"#),
        format!(r#"{{"body":"{ENTROPY_SECRET}"}}"#),
        format!("Authorization: Bearer {ENTROPY_SECRET}\r\nHost: api.example.com"),
        format!("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\nanthropic = {ANTHROPIC_SECRET}"),
        format!("請將金鑰 {ENTROPY_SECRET} 設定於環境變數中，並勿寫入版本控制。"),
        "contact ops@agent-assembly.example about card 4111111111111111".to_string(),
    ]
}

/// Longest ASCII run inside a whitespace token — the exact slice the entropy
/// pass scores.
fn longest_scored_run(text: &str) -> usize {
    text.split_whitespace()
        .flat_map(|token| token.split(|c: char| !c.is_ascii()))
        .map(str::len)
        .max()
        .unwrap_or(0)
}

/// `scan` then `redact`, in one step.
fn scrub(text: &str) -> String {
    CredentialScanner::new().scan(text).redact(text)
}

fn scan(text: &str) -> ScanResult {
    CredentialScanner::new().scan(text)
}

/// **The reproduction.** A body scrubbed completely and correctly must re-scan
/// clean.
///
/// Before AAASM-5441 the second scan of
/// `{"model":"claude-3","api_key":"[REDACTED:AnthropicKey]"}` reported one
/// `GenericHighEntropy` finding — and its span was the opening `{`, *outside* the
/// label, because pass 1 scores the whole token and then clamps the span at the
/// first delimiter. That is why the fix excludes the label from what is scored
/// rather than filtering findings that land inside one.
#[test]
fn a_correctly_scrubbed_body_reinspects_clean() {
    let body = format!(r#"{{"model":"claude-3","api_key":"{ANTHROPIC_SECRET}"}}"#);

    let first = scan(&body);
    assert!(
        !first.findings.is_empty(),
        "the fixture must contain a detectable secret, else everything below is vacuous"
    );

    let scrubbed = first.redact(&body);

    // Non-vacuity, in the three ways this Epic has already been fooled.
    assert!(!scrubbed.is_empty(), "an empty body would re-scan clean trivially");
    assert!(
        !scrubbed.contains(ANTHROPIC_SECRET),
        "the scrub must be complete, else a second finding would be correct"
    );
    assert!(
        scrubbed.contains("[REDACTED:AnthropicKey]"),
        "the scrubbed body must actually carry a label: {scrubbed}"
    );
    let run = longest_scored_run(&scrubbed);
    assert!(
        (20..=64).contains(&run),
        "the scrubbed body's longest scored ASCII run is {run} characters, outside the \
         entropy pass's 20-64 window — this text never reaches the gate, so a clean \
         result would prove nothing about it"
    );

    let second = scan(&scrubbed);
    assert!(
        second.findings.is_empty(),
        "a correctly and completely scrubbed body re-inspected as still carrying a \
         secret: {:?} over {scrubbed}",
        second.findings
    );
}

/// **Idempotence.** `redact(redact(x)) == redact(x)`, and the scrubbed form
/// re-scans clean, for every representative body.
///
/// The failure this pins is not cosmetic: `{"token":"<PAT>"}` used to gain one
/// extra `]` on **every** re-scan and never reach a fixed point, so a payload
/// crossing two inspection points came out longer than it went in.
#[test]
fn redaction_reaches_a_fixed_point() {
    for body in representative_bodies() {
        let once = scrub(&body);
        assert_ne!(once, body, "fixture carries no detectable value: {body}");

        let twice = scrub(&once);
        assert_eq!(
            twice, once,
            "redaction is not idempotent for {body:?}: first pass gave {once:?}, second gave {twice:?}"
        );

        assert!(
            scan(&once).findings.is_empty(),
            "re-scanning the scrubbed form of {body:?} reported {:?}",
            scan(&once).findings
        );
    }
}

/// **Every** label shape, not only the long one (AC 4): the bare `[REDACTED]`
/// that the locale packs and the fail-closed branch emit, plus
/// `[REDACTED:<kind>]` for all of [`CredentialKind::ALL`] and for `Custom`.
///
/// Each is placed in the contexts that pooled it into a longer candidate — the
/// bare label alone is below the gate and would pass here even unfixed.
#[test]
fn no_label_shape_is_reported_as_a_secret() {
    let mut labels: Vec<String> = CredentialKind::ALL
        .iter()
        .chain(std::iter::once(&CredentialKind::Custom))
        .map(|kind| format!("[REDACTED:{}]", kind.as_str()))
        .collect();
    labels.push("[REDACTED]".to_string());

    for label in &labels {
        for body in [
            format!(r#"{{"api_key":"{label}"}}"#),
            format!(r#"{{"k":"{label}"}}"#),
            format!("key={label};"),
            format!("<{label}>"),
            format!(r#"{{"a":"{label}","b":"{label}"}}"#),
            label.clone(),
        ] {
            assert!(
                scan(&body).findings.is_empty(),
                "a body whose only high-entropy content is a redaction label was reported \
                 as carrying a secret: {body:?} -> {:?}",
                scan(&body).findings
            );
        }
    }
}

/// The **bare** `[REDACTED]` shape, which no `<kind>` name makes long or diverse.
///
/// It is what the locale packs emit — a finding with no [`CredentialKind`] has no
/// label to name, and inventing one would publish a pattern name — and what
/// `ScanResult::redact`'s fail-closed branch emits. At ten bytes over eight
/// distinct values it can never clear the gate alone, which is exactly why it
/// needs its own test: it tips a candidate only by *joining* one, and a suite
/// built on the label in isolation leaves this shape unproven. Each body below
/// was measured dirty without the exclusion.
///
/// The second assertion is what makes the first mean something: with the label
/// deleted the same body is clean, so the finding was the scanner reacting to its
/// own output rather than to the identifier beside it.
#[test]
fn a_bare_label_beside_an_opaque_identifier_is_clean() {
    for body in [
        r#"{"requestId":"Qk9tZ2x4NA","ssn":"[REDACTED]"}"#,
        r#"{"traceId":"7Kd3pVq0Lm","nationalId":"[REDACTED]"}"#,
        r#"{"x-corr-id":"Qk9tZ2x4NA","tw_id":"[REDACTED]"}"#,
        r#"{"invoiceNo":"Ab3xZ9Qm","buyerId":"[REDACTED]"}"#,
        "trace=7Kd3pVq0Lm&national_id=[REDACTED]",
        "customerRef=Ab3xZ9Qm&id=[REDACTED];",
    ] {
        let run = longest_scored_run(body);
        assert!(
            (20..=64).contains(&run),
            "{body:?} has no scored ASCII run in the 20-64 window ({run}); a clean result \
             would say nothing about the entropy pass"
        );
        assert!(
            scan(body).findings.is_empty(),
            "a body carrying a bare redaction label was reported as carrying a secret: \
             {body:?} -> {:?}",
            scan(body).findings
        );

        let without_label = body.replace("[REDACTED]", "");
        assert!(
            scan(&without_label).findings.is_empty(),
            "fixture is not about the label: {without_label:?} is reported even with the \
             label removed, so the assertion above would hold for another reason"
        );
    }
}

/// **The adversarial case, and the one that decides the design.**
///
/// The exclusion is by exact literal against a closed set, so an attacker who
/// writes labels around a secret excises no bytes of their own choosing and the
/// secret is still found. Both the literal-prefix detectors and the entropy pass
/// are exercised, because only the second is the one the exclusion touches.
#[test]
fn a_label_cannot_be_used_to_smuggle_a_secret() {
    for secret in [ANTHROPIC_SECRET, GITHUB_SECRET, ENTROPY_SECRET] {
        assert!(
            !scan(secret).findings.is_empty(),
            "{secret} is not detected even on its own — it cannot demonstrate anything \
             about smuggling"
        );

        for body in [
            format!("[REDACTED:GenericHighEntropy]{secret}[REDACTED:GenericHighEntropy]"),
            format!("[REDACTED]{secret}[REDACTED]"),
            format!("[REDACTED:GenericHighEntropy] {secret} [REDACTED:GenericHighEntropy]"),
            format!(r#"{{"k":"[REDACTED:AnthropicKey]{secret}"}}"#),
            format!("[REDACTED:AnthropicKey][REDACTED:GitHubPat][REDACTED]{secret}"),
            format!("{secret}[REDACTED]"),
            format!("[REDACTED]{secret}"),
        ] {
            let result = scan(&body);
            assert!(
                !result.findings.is_empty(),
                "wrapping a secret in redaction labels hid it: {body:?}"
            );
            assert!(
                !result.redact(&body).contains(secret),
                "the secret survived redaction of {body:?}: {}",
                result.redact(&body)
            );
        }
    }
}

/// The other half of the same argument: label-**shaped** text is not a label.
///
/// `[REDACTED:<anything>]` is excluded only when `<anything>` is one of the kind
/// names this crate emits. A secret in that slot is not a label, is not masked,
/// and is still found.
#[test]
fn label_shaped_text_is_not_a_label() {
    for secret in [ENTROPY_SECRET, "AKIAIOSFODNN7EXAMPLE", ANTHROPIC_SECRET] {
        for body in [
            format!("[REDACTED:{secret}]"),
            format!("[REDACTED{secret}]"),
            format!("[REDACTED:GenericHighEntropy{secret}]"),
            format!(r#"{{"k":"[REDACTED:{secret}]"}}"#),
        ] {
            let result = scan(&body);
            assert!(
                !result.findings.is_empty(),
                "text that merely looks like a redaction label hid a secret: {body:?}"
            );
            assert!(
                !result.redact(&body).contains(secret),
                "the secret survived redaction of {body:?}: {}",
                result.redact(&body)
            );
        }
    }
}
