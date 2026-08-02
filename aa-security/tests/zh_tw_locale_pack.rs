//! The zh-TW locale pack's public behaviour, and the two things it must not
//! break (AAASM-5353).
//!
//! Driven through the crate's public API only, so it also proves the pack is
//! reachable from outside `aa-security` — the SDK and WASM layers reach it the
//! same way.

use aa_security::canonical::redact_findings;
use aa_security::locale::zh_tw;
use aa_security::CredentialScanner;

/// Clean Traditional-Chinese technical prose, carrying the numeric content real
/// documents carry: dates, versions, ports, counts, monetary amounts and
/// timestamps.
///
/// The numbers are the point. A corpus of pure Han text would pass this test
/// even if every recognizer matched any digit run, so the assertion would prove
/// nothing — and this programme has already shipped clean-prose vectors whose
/// text could not reach the code they were meant to exercise. The assertions
/// below therefore check the corpus is numerically dense *before* checking it is
/// clean.
const CLEAN_ZH_TW_PROSE: &str = include_str!("fixtures/zh_tw_clean_prose.txt");

/// The byte-level Shannon entropy of an ASCII-or-not slice.
///
/// Deliberately scored over **bytes**, because that is the calculation that
/// produced this Epic's founding defect: the entropy gate is calibrated in bits
/// per character on English prose, and Han characters spread their UTF-8 bytes
/// widely enough to land at 4.6–4.9 bits/byte. Reproduced here so
/// `the_corpus_reaches_the_entropy_window_that_caused_the_defect` can prove the
/// corpus is capable of triggering it, rather than asserting cleanliness over
/// text that could never have failed.
fn byte_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Whitespace tokens of the corpus that sit inside the 20–64 byte window with
/// byte-entropy above the 4.5 bits gate — i.e. the exact shape that was reported
/// as a leaked secret before AAASM-5344.
fn tokens_in_the_pre_5344_danger_window(text: &str) -> usize {
    text.split_whitespace()
        .filter(|t| (20..=64).contains(&t.len()) && byte_entropy(t) > 4.5)
        .count()
}

/// Substrings of `text` that the zh-TW pack must look at and decline: a letter
/// followed by nine digits, a standalone run of exactly eight digits, and a run
/// of nine or ten digits beginning with a zero.
///
/// Counted with a hand-rolled scan rather than by asking the pack, because the
/// point is to establish — independently of the code under test — that the
/// corpus actually contains candidates. `zh_tw::scan` returning zero over a
/// corpus with no candidates in it proves nothing at all.
fn candidate_shape_counts(text: &str) -> (usize, usize, usize) {
    let b: Vec<char> = text.chars().collect();
    let digit = |i: usize| b.get(i).is_some_and(char::is_ascii_digit);
    let alnum = |i: usize| b.get(i).is_some_and(char::is_ascii_alphanumeric);
    let (mut letter9, mut eight, mut zero_led) = (0, 0, 0);

    for (i, c) in b.iter().enumerate() {
        let starts_token = i == 0 || !alnum(i - 1);
        // A letter followed by exactly nine digits, not glued to more.
        if c.is_ascii_uppercase() && starts_token && (1..=9).all(|k| digit(i + k)) && !alnum(i + 10) {
            letter9 += 1;
        }
        if c.is_ascii_digit() && starts_token {
            let mut n = 0;
            while digit(i + n) {
                n += 1;
            }
            if n == 8 && !alnum(i + 8) {
                eight += 1;
            }
            if (9..=10).contains(&n) && *c == '0' {
                zero_led += 1;
            }
        }
    }
    (letter9, eight, zero_led)
}

/// A high-entropy ASCII secret used to prove the locale pack did not weaken the
/// existing detectors. Not a real credential — a fixed alphanumeric run.
const ASCII_SECRET: &str = "ghp_0123456789abcdefABCDEF0123456789abcd";

/// Ordinary zh-TW prose must produce no findings — from either scanner.
///
/// This is the defect the whole Epic exists to fix: 32 KB of clean Traditional
/// Chinese previously produced 87 findings, because the entropy gate scored
/// UTF-8 bytes against a threshold calibrated on English characters. AAASM-5344
/// fixed that; this ticket must not undo it by adding recognizers loose enough
/// to reintroduce it from the other direction.
#[test]
fn clean_zh_tw_prose_produces_no_findings_from_either_scanner() {
    let digits = CLEAN_ZH_TW_PROSE.chars().filter(char::is_ascii_digit).count();
    assert!(
        CLEAN_ZH_TW_PROSE.len() > 8000,
        "corpus is too small to be evidence: {} bytes",
        CLEAN_ZH_TW_PROSE.len()
    );
    assert!(
        digits > 400,
        "corpus has too few digits to exercise the digit recognizers: {digits}"
    );

    let scanner_findings = CredentialScanner::new().scan(CLEAN_ZH_TW_PROSE).findings;
    assert!(
        scanner_findings.is_empty(),
        "clean zh-TW prose produced {} credential findings: {:?}",
        scanner_findings.len(),
        scanner_findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>()
    );

    let locale_findings = zh_tw::scan(CLEAN_ZH_TW_PROSE);
    assert!(
        locale_findings.is_empty(),
        "clean zh-TW prose produced {} locale findings: {:?}",
        locale_findings.len(),
        locale_findings
            .iter()
            .map(|f| {
                let s = f.span();
                (f.category().to_string(), &CLEAN_ZH_TW_PROSE[s.start()..s.end()])
            })
            .collect::<Vec<_>>()
    );

    // And redaction over an empty finding set returns the text, not a blank.
    assert_eq!(redact_findings(CLEAN_ZH_TW_PROSE, &locale_findings), CLEAN_ZH_TW_PROSE);
}

/// The corpus must be able to trigger the **entropy** defect, or its
/// cleanliness says nothing about the scanner.
///
/// Before AAASM-5344 the entropy pass scored a whole whitespace token's UTF-8
/// bytes against a gate calibrated in bits per *character* on English. Chinese
/// does not delimit words with spaces, so a clause is one token; land that token
/// in the 20–64 byte window and Han's byte distribution puts it over 4.5 bits,
/// and ordinary prose is reported as a leaked secret. That is where the 87
/// findings came from.
///
/// A corpus whose tokens are all *longer* than 64 bytes would sail past that
/// window and stay clean no matter how broken the gate was — which is exactly
/// the failure mode this programme has already shipped: clean-prose vectors
/// whose text overflowed the window, so a mutation failed zero of them. This
/// asserts the corpus lands inside the window many times over.
#[test]
fn the_corpus_reaches_the_entropy_window_that_caused_the_defect() {
    let in_window = tokens_in_the_pre_5344_danger_window(CLEAN_ZH_TW_PROSE);
    assert!(
        in_window >= 30,
        "only {in_window} tokens land in the 20–64 byte window above 4.5 bits/byte; \
         this corpus could not have failed before AAASM-5344, so its cleanliness \
         is not evidence that the fix holds"
    );
}

/// And the corpus must be able to trigger the **locale pack**, which is a
/// different question with a different answer.
///
/// The entropy check above exercises `CredentialScanner`. It says nothing about
/// whether the text ever reaches `zh_tw::scan`'s recognizers — a corpus with no
/// identifier-shaped token in it would yield zero locale findings however
/// permissive the checksums were. Counted independently of the pack, so the
/// evidence does not come from the code under test.
#[test]
fn the_corpus_contains_candidates_the_locale_pack_must_decline() {
    let (letter9, eight, zero_led) = candidate_shape_counts(CLEAN_ZH_TW_PROSE);
    assert!(
        letter9 >= 4,
        "only {letter9} letter+9-digit tokens: the identity recognizers are never exercised"
    );
    assert!(
        eight >= 6,
        "only {eight} standalone 8-digit runs: the 統一編號 recognizer is barely exercised"
    );
    assert!(
        zero_led >= 2,
        "only {zero_led} zero-led 9–10 digit runs: the phone recognizers are never exercised"
    );
}

/// The standing D-3 constraint: nothing in this ticket may weaken detection of
/// ASCII base64, hex or high-entropy secrets.
///
/// The locale pack is a separate entry point and does not touch
/// `CredentialScanner`, so this holds structurally — but "holds structurally"
/// is what every regression looked like beforehand. Asserted against the same
/// text the locale pack is scanning, so a future change that *did* wire the two
/// together cannot quietly trade one for the other.
#[test]
fn ascii_secret_detection_survives_beside_the_locale_pack() {
    let payload = format!("{CLEAN_ZH_TW_PROSE}\n授權標頭：{ASCII_SECRET}\n");

    let result = CredentialScanner::new().scan(&payload);
    // Raw-secret absence, not finding count: a 40-character `ghp_` token trips
    // both the literal detector and the base64-run backstop, and that overlap
    // is long-standing scanner behaviour rather than anything this ticket
    // changes. What must hold is that the secret is identified and removed.
    assert!(
        result.findings.iter().any(|f| f.kind.as_str() == "GitHubPat"),
        "the ASCII secret must still be identified as a GitHub PAT, got {:?}",
        result.findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>()
    );
    assert!(
        !result.redact(&payload).contains(ASCII_SECRET),
        "the ASCII secret survived redaction"
    );
    // And the surrounding prose still contributes nothing of its own.
    assert!(
        result.findings.iter().all(|f| f.offset >= CLEAN_ZH_TW_PROSE.len()),
        "a finding landed inside the clean prose"
    );
}

/// A payload carrying both an ASCII secret and a Taiwanese identifier must lose
/// both, each through its own scanner.
///
/// The two findings sets are disjoint in category and are produced by different
/// recognizers, so a caller has to run both and combine them. This is what that
/// looks like end to end, and it is the shape AAASM-5355's ingest path will use.
#[test]
fn a_mixed_payload_loses_both_the_ascii_secret_and_the_taiwanese_identifier() {
    // `A200000003`: letter A → area code 10, so n₁·1 + n₂·9 = 1; the body
    // `20000000` contributes 2 × 8 = 16; the check digit 3 brings the weighted
    // sum to 20, which is divisible by 10. Constructed, not observed.
    let identifier = "A200000003";
    // A space after the secret, because the scanner's literal detector extends
    // a finding to the end of its whitespace token — punctuation glued to the
    // token is swallowed into the span. That is existing, tested behaviour and
    // not this ticket's to change; the payload is written so the exact-string
    // assertion below is about the locale pack rather than about that.
    let payload = format!("身分證字號 {identifier}，授權標頭 {ASCII_SECRET} ，請儘速處理。");

    let scanner_redacted = CredentialScanner::new().scan(&payload).redact(&payload);
    assert!(!scanner_redacted.contains(ASCII_SECRET), "ASCII secret survived");

    let locale_findings = zh_tw::scan(&scanner_redacted);
    assert_eq!(locale_findings.len(), 1, "the identifier must be found");
    assert_eq!(
        locale_findings[0].category().to_string(),
        "NATIONAL_ID[zh-TW/national_id]"
    );

    let fully_redacted = redact_findings(&scanner_redacted, &locale_findings);
    assert!(!fully_redacted.contains(identifier), "identifier survived redaction");
    assert!(!fully_redacted.contains(ASCII_SECRET), "ASCII secret reappeared");
    assert_eq!(
        fully_redacted,
        "身分證字號 [REDACTED]，授權標頭 [REDACTED:GitHubPat] ，請儘速處理。"
    );
}
