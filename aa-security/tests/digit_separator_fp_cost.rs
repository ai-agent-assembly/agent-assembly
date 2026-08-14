//! AAASM-5450: what each candidate digit separator would cost, measured.
//!
//! [`aa_security::scanner`]'s `ascii_separator_of` decides the whole set of
//! characters a digit run is joined across before it reaches the Luhn checksum
//! and the SSN shape check. Widening that set is not free: every separator
//! admitted lengthens the joined run, and a longer run is a fresh chance to land
//! in the 13-19 digit window where Luhn — a mod-10 checksum — passes roughly one
//! arbitrary number in ten. On the enforcement path a coincidental pass redacts
//! or blocks a legitimate payload.
//!
//! AAASM-5450 named six candidates as plausible in real payloads: `.`, `_`, `/`,
//! `,`, tab and newline. This harness is how each one was **priced** instead of
//! argued about.
//!
//! # Why a second corpus exists at all
//!
//! `fp_ceiling_and_recall_floor.rs` already builds
//! `aaasm5456_mixed_en_zh_tw_prose_v1`, 20,971,526 bytes of mixed en/zh-TW prose,
//! and that is the corpus the repository's accepted false-positive rate is quoted
//! over. It stays the headline number here, unchanged and unedited.
//!
//! It cannot, however, price these six, and that was established by counting
//! rather than assumed. Over its 20,971,526 bytes it carries **56,104**
//! `digit.digit` junctions — from its `v{a}.{b}.0` version strings — and
//! **zero** digit-flanked occurrences of `_`, `/`, `,`, tab, newline, U+FF0E, or
//! even the space: it contains no tab and no newline at all. A measurement of
//! "0 false positives" over a corpus containing none of the characters under
//! test is absence, not restraint, and this programme has already shipped
//! fixtures that passed for exactly that reason.
//!
//! The one candidate it does carry it still cannot price: with the full stop
//! admitted, the **longest** joined digit run anywhere in that corpus is eight
//! digits (`v9999.999.0`), five short of the 13-digit floor `luhn_valid` gates
//! on. The checksum is never reached, so the corpus reports zero for the full
//! stop no matter what the full stop costs.
//!
//! `aaasm5450_machine_payload_v1` is therefore a *second* corpus, built to reach
//! the window: JSON log lines with float unix timestamps, TSV numeric columns,
//! CSV amounts with thousands separators, dotted versions and IPv4 addresses,
//! underscore-grouped numeric literals, slash-formatted dates, bare numeric
//! columns one per line, and full-width zh-TW decimals. Every shape in it is
//! ordinary machine output. It contains no card number and no SSN, so **every**
//! PII finding over it is a false positive by construction.
//!
//! It is deliberately dense in these shapes so that each candidate can be
//! priced at all, which makes its absolute rates an **upper bound** on what a
//! given character costs rather than a typical rate. The comparable, typical
//! number is the prose corpus's, and that one is unchanged at zero.
//!
//! # The measurement, and what it decided
//!
//! Each candidate was admitted to `ascii_separator_of` on its own, the crate
//! rebuilt, and this harness re-run — the real scanner, not a reimplementation
//! of its walk. Over `aaasm5450_machine_payload_v1` (4,194,360 bytes):
//!
//! | separator admitted | card FPs | SSN FPs | runs it pushed into the window | ratio |
//! |---|---|---|---|---|
//! | *(none — the set before this ticket)* | 0 | 0 | 0 | — |
//! | `.` U+002E | 1255 | 0 | 12,284 | 10.2% |
//! | `．` U+FF0E | 1193 | 0 | 11,963 | 10.0% |
//! | `_` U+005F | 1207 | 0 | 12,127 | 10.0% |
//! | `/` U+002F | 1253 | 0 | 12,176 | 10.3% |
//! | `,` U+002C | 1175 | 0 | 12,265 | 9.6% |
//! | tab U+0009 | 1218 | 0 | 12,265 | 9.9% |
//! | newline U+000A | 532 | 0 | 5,395 | 9.9% |
//!
//! The ratio column is the finding. Every candidate costs the same ~10% of
//! whatever runs it pushes into the 13-19 digit window, because that is simply
//! the rate at which a mod-10 checksum passes by chance. **No candidate is
//! intrinsically safer than another**, so the set cannot be chosen on cost — it
//! has to be chosen on coverage, which is what `ascii_separator_of` documents.
//!
//! The baseline row is a zero because nothing in this corpus reaches the window
//! under the pre-ticket separator set; `every_candidate_separator_is_priced_against_reachable_text`
//! asserts exactly that, so the table's information is in the deltas rather than
//! in the baseline.
//!
//! # Falsification
//!
//! * `every_candidate_separator_is_priced_against_reachable_text` — the
//!   load-bearing positive control, and each of its two halves was watched to
//!   fire separately. Restricting the generator to the TSV record shape drops the
//!   full stop's junction count to 0 and it fails with *"full stop (U+002E) never
//!   occurs between two digits"*. Shortening the JSON timestamp's fractional part
//!   from six digits to two leaves all 85,803 junctions intact and drops the full
//!   stop's window-reaching runs to 0 instead, and it fails with *"admitting full
//!   stop (U+002E) would put no run … into the 13-19 digit window"*. A corpus
//!   that could not have produced a finding is caught either way.
//! * `the_admitted_separators_cost_what_was_measured` — an equality, not a
//!   ceiling, and watched to fail in both directions: removing `.` from
//!   `ascii_separator_of` moves it from (2448, 0) to (1193, 0), and admitting
//!   `,` on top of the shipped set moves it to (3623, 0).
//! * `the_zh_tw_payload_class_named_by_the_acceptance_criteria_stays_clean` — a
//!   requirement gate rather than a control, and honestly it **cannot** be
//!   falsified by any separator decision: the longest digit run that payload
//!   class can produce, joined across the widest candidate set, is eight digits,
//!   five short of the floor `luhn_valid` gates on. Admitting `,` on top of the
//!   shipped set leaves it at zero, as measured. What it does catch is the class
//!   of regression that actually put it at 87 findings once — an entropy or token
//!   window that reaches CJK text — which is why it is a gate at all.
//!
//! Two mutations, one per admitted character, were run against the whole
//! `aa-security` suite. They kill **disjoint** named tests — removing `.` uniquely
//! kills `detects_a_card_grouped_by_the_full_stop`, removing `．` uniquely kills
//! `detects_a_card_grouped_by_the_fullwidth_full_stop` — so the two are separately
//! pinned. Four further tests (`detects_an_ssn_written_with_full_stops`,
//! `redacts_full_stop_separated_values_to_exact_bytes`,
//! `full_stop_separated_spans_are_char_boundaries_of_the_original_text`,
//! `the_trailing_separator_guard_holds_for_the_full_stop_forms`) die under *both*
//! mutations because each covers both widths in one loop; they are coverage, not
//! two independent proofs, and are not counted as such.
//!
//! # Fixture safety
//!
//! Every digit sequence below is generated from a fixed seed. No card number,
//! SSN, or other genuine PII appears in this file.

use aa_security::{CredentialKind, CredentialScanner};

/// The corpus's identity. Together with [`CORPUS_SEED`] and this file's
/// generator, it names exactly one byte sequence.
const CORPUS_NAME: &str = "aaasm5450_machine_payload_v1";

/// Fixed seed. Changing it changes the corpus and therefore every number quoted
/// above, which is why it is a named constant rather than a literal.
const CORPUS_SEED: u64 = 0x5450_D161_7053_9A17;

/// The corpus is generated until it is at least this large.
const CORPUS_MIN_BYTES: usize = 4 * 1024 * 1024;

/// Exact byte length this seed produces. Recorded rather than derived, because
/// the rates above are quoted per byte over this exact corpus.
const CORPUS_BYTES: usize = 4_194_360;

/// Content digest of the corpus this seed produces — the drift this file's
/// length check cannot catch: same size, different text, different measurement.
const CORPUS_CHECKSUM: u64 = 0xd821_2298_389a_7c35;

/// SplitMix64, the same generator `fp_ceiling_and_recall_floor.rs` uses, for the
/// same reason: a dozen lines, no dependency, and identical output on every
/// compiler and target. Reproducibility is the whole requirement.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }
}

/// Builds `aaasm5450_machine_payload_v1`.
///
/// Eight record shapes, one per draw, each carrying one candidate separator
/// between two digits. The shapes are chosen so the corpus reaches the 13-19
/// digit Luhn window through *several* different separators rather than one, so
/// that admitting any single candidate produces a number rather than a zero.
fn corpus() -> String {
    let mut rng = SplitMix64(CORPUS_SEED);
    let mut out = String::with_capacity(CORPUS_MIN_BYTES + 4096);

    while out.len() < CORPUS_MIN_BYTES {
        match rng.next() % 8 {
            // A structured log line with a float unix timestamp. Ten integer
            // digits plus six fractional ones is sixteen joined digits — dead
            // centre of the Luhn window — and it is what every Python or Go
            // service writes for `time.time()`.
            0 => out.push_str(&format!(
                "{{\"ts\": 17{}.{:06}, \"level\": \"info\", \"dur_ms\": {}.{}}}\n",
                rng.range(10_000_000, 99_999_999),
                rng.range(0, 999_999),
                rng.range(1, 9999),
                rng.range(10, 99),
            )),
            // A TSV row of numeric columns — a query result or a metrics export.
            1 => out.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                rng.range(1000, 9999),
                rng.range(1000, 9999),
                rng.range(1000, 9999),
                rng.range(1000, 9999),
            )),
            // A CSV amount written with thousands separators, large enough that
            // the joined run clears the 13-digit floor.
            2 => out.push_str(&format!(
                "Q{},{},{:03},{:03},{:03},{:03},TWD\n",
                rng.range(1, 4),
                rng.range(1, 999),
                rng.range(0, 999),
                rng.range(0, 999),
                rng.range(0, 999),
                rng.range(0, 999),
            )),
            // A dotted version beside an IPv4 address. Neither reaches the window
            // alone; both are what makes `.` common enough to matter.
            3 => out.push_str(&format!(
                "service {}.{}.{} at 192.168.{}.{}:{}\n",
                rng.range(0, 99),
                rng.range(0, 99),
                rng.range(0, 99),
                rng.range(0, 255),
                rng.range(0, 255),
                rng.range(1024, 65535),
            )),
            // Underscore-grouped numeric literals, as Rust and Python source
            // carry them, plus an underscore-joined identifier.
            4 => out.push_str(&format!(
                "const LIMIT_{}: u64 = {}_{:03}_{:03}_{:03}_{:03}; // run_{}_{}\n",
                rng.range(1, 99),
                rng.range(1, 999),
                rng.range(0, 999),
                rng.range(0, 999),
                rng.range(0, 999),
                rng.range(0, 999),
                rng.range(1, 9999),
                rng.range(1, 9999),
            )),
            // A slash-formatted date and time — the shape `/` occurs in.
            5 => out.push_str(&format!(
                "{:02}/{:02}/{} {:02}/{:02}/{:02} request accepted\n",
                rng.range(1, 12),
                rng.range(1, 28),
                rng.range(2020, 2030),
                rng.range(0, 23),
                rng.range(0, 59),
                rng.range(0, 59),
            )),
            // A bare numeric column, one value per line — what `newline` joins.
            6 => out.push_str(&format!(
                "{}\n{}\n{}\n{}\n",
                rng.range(1000, 9999),
                rng.range(1000, 9999),
                rng.range(1000, 9999),
                rng.range(1000, 9999),
            )),
            // Full-width prose with the full-width full stop as a decimal point,
            // which is the role U+FF0E plays in zh-TW machine output — the exact
            // observation the committed conformance vector
            // `biz_fullwidth_delimited_negative` records.
            _ => out.push_str(&format!(
                "值＝{}　{}．{}　狀態正常\n",
                fullwidth(rng.range(10_000_000, 99_999_999)),
                fullwidth(rng.range(1, 9)),
                fullwidth(rng.range(10_000_000, 99_999_999)),
            )),
        }
    }
    out
}

/// Renders `n` in full-width digits (U+FF10-U+FF19), which is what a CJK input
/// method in full-width mode produces.
fn fullwidth(n: u64) -> String {
    n.to_string()
        .chars()
        .map(|c| char::from_u32(c as u32 - u32::from(b'0') + 0xFF10).expect("ASCII digit"))
        .collect()
}

/// Counts the corpus's PII findings, split by kind.
///
/// The corpus contains no card number and no SSN, so both counts are false
/// positives outright.
fn pii_findings(text: &str) -> (usize, usize) {
    let scanner = CredentialScanner::new();
    let findings = scanner.scan(text).findings;
    let cards = findings
        .iter()
        .filter(|f| f.kind == CredentialKind::CreditCardLuhn)
        .count();
    let ssns = findings.iter().filter(|f| f.kind == CredentialKind::SsnPattern).count();
    (cards, ssns)
}

/// The corpus's identity is its name, seed, byte size and content together.
#[test]
fn the_machine_payload_corpus_identity_is_pinned() {
    let text = corpus();
    let checksum = text
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
    println!(
        "corpus {CORPUS_NAME} seed {CORPUS_SEED:#x} bytes {} checksum {checksum:#x}",
        text.len()
    );

    assert!(
        text.len() >= CORPUS_MIN_BYTES,
        "{CORPUS_NAME} is {} bytes, below the {CORPUS_MIN_BYTES} the rates are expressed over",
        text.len()
    );
    assert_eq!(
        text.len(),
        CORPUS_BYTES,
        "{CORPUS_NAME} is {} bytes, not the recorded {CORPUS_BYTES}. The per-separator rates are \
         quoted over this exact corpus, so a corpus that changed size is a different measurement.",
        text.len()
    );
    assert_eq!(
        checksum, CORPUS_CHECKSUM,
        "{CORPUS_NAME} content drifted: checksum {checksum:#x}, recorded {CORPUS_CHECKSUM:#x}. \
         Same length, different text, different measurement."
    );
}

/// **The positive control every row of the cost table rests on.**
///
/// A separator priced over text that never presents it between two digits comes
/// back at zero for free, and a corpus whose joined runs never reach thirteen
/// digits never consults the Luhn check at all — either way "0 false positives"
/// would be absence rather than restraint. Both are asserted here, per candidate:
/// the character occurs flanked by digits, **and** admitting it would put runs
/// into the 13-19 window the checksum is applied over.
///
/// This is a property of the corpus text, not of the scanner, so it is counted
/// here rather than inferred from a finding count — a finding count is exactly
/// what it exists to validate.
#[test]
fn every_candidate_separator_is_priced_against_reachable_text() {
    let text = corpus();
    let chars: Vec<char> = text.chars().collect();

    for (label, sep) in [
        ("full stop", '.'),
        ("full-width full stop", '\u{FF0E}'),
        ("underscore", '_'),
        ("solidus", '/'),
        ("comma", ','),
        ("tab", '\t'),
        ("newline", '\n'),
    ] {
        let junctions = chars
            .windows(3)
            .filter(|w| w[1] == sep && is_digit_either_width(w[0]) && is_digit_either_width(w[2]))
            .count();
        let in_window = window_reaching_runs(&chars, sep);

        assert!(
            junctions > 0,
            "{label} (U+{:04X}) never occurs between two digits in {CORPUS_NAME}; the cost \
             quoted for it would be measuring absence",
            sep as u32,
        );
        assert!(
            in_window > 0,
            "admitting {label} (U+{:04X}) would put no run of {CORPUS_NAME} into the 13-19 \
             digit window, so the Luhn check is never reached and its measured cost of zero \
             says nothing about the character",
            sep as u32,
        );
        println!(
            "{label:<22} U+{:04X}  junctions: {junctions:>7}  runs reaching the Luhn window: {in_window:>7}",
            sep as u32
        );
    }

    // The other half of the control, and the reason the *baseline* row of the
    // cost table is a zero: under the separator set as it stood before
    // AAASM-5450, nothing in this corpus reaches the Luhn window at all. That
    // zero is unreachability, not restraint — which is precisely why the table's
    // information is in the per-candidate deltas and not in the baseline.
    let unreachable_today = window_reaching_runs(&chars, '\u{0}');
    assert_eq!(
        unreachable_today, 0,
        "{CORPUS_NAME} already reaches the Luhn window without admitting any candidate, so a \
         per-candidate delta measured against it is confounded by runs neither character \
         created"
    );
}

/// Number of digit runs that land in the 13-19 digit Luhn window when `extra` is
/// joined across in addition to the separators the scanner already admits.
///
/// Mirrors [`aa_security::scanner`]'s walk closely enough to answer "could this
/// character ever reach the checksum here" — the 24-character segment budget and
/// the AAASM-4820 rule that a separator is consumed only between two digits. It
/// is deliberately *not* the measurement: the measurement is the real scanner's
/// finding count, and this only certifies that the count had something to find.
fn window_reaching_runs(chars: &[char], extra: char) -> usize {
    let joins = |c: char| c == extra || matches!(c, ' ' | '\u{3000}' | '-' | '\u{FF0D}');

    let mut found = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if !is_digit_either_width(chars[i]) {
            i += 1;
            continue;
        }
        let mut digits = 0usize;
        let mut consumed = 0usize;
        let mut j = i;
        while consumed < 24 && j < chars.len() {
            if is_digit_either_width(chars[j]) {
                digits += 1;
                consumed += 1;
                j += 1;
            } else if joins(chars[j])
                && digits > 0
                && consumed + 1 < 24
                && chars.get(j + 1).copied().is_some_and(is_digit_either_width)
            {
                consumed += 1;
                j += 1;
            } else {
                break;
            }
        }
        if (13..=19).contains(&digits) {
            found += 1;
        }
        i = j.max(i + 1);
    }
    found
}

/// `true` for an ASCII digit or its full-width twin — the two widths
/// `ascii_digit_of` normalises.
fn is_digit_either_width(c: char) -> bool {
    c.is_ascii_digit() || ('\u{FF10}'..='\u{FF19}').contains(&c)
}

/// **The cost of the shipped separator set, pinned as an equality.**
///
/// Not a ceiling: a ceiling would absorb a widening silently as long as it
/// stayed under budget, and the entire point of AAASM-5450 is that widening the
/// set has a price that must stay visible. Admitting one more character to
/// `ascii_separator_of` moves this number and fails this test, which is the
/// intended way to notice.
#[test]
fn the_admitted_separators_cost_what_was_measured() {
    let text = corpus();
    let (cards, ssns) = pii_findings(&text);

    println!(
        "{CORPUS_NAME}: {cards} card false positives, {ssns} SSN false positives over {} bytes",
        text.len()
    );

    assert_eq!(
        (cards, ssns),
        (SHIPPED_CARD_FPS, SHIPPED_SSN_FPS),
        "the separator set's measured cost over {CORPUS_NAME} moved from \
         ({SHIPPED_CARD_FPS}, {SHIPPED_SSN_FPS}) to ({cards}, {ssns}). If a separator was \
         admitted or declined deliberately, re-record these constants with the measurement on \
         the ticket — do not adjust them to make the build green."
    );
}

/// Card false positives the shipped separator set costs over [`CORPUS_NAME`].
const SHIPPED_CARD_FPS: usize = 2448;

/// SSN false positives the shipped separator set costs over [`CORPUS_NAME`].
const SHIPPED_SSN_FPS: usize = 0;

/// The zh-TW filler `spike_5269_payload_classes`'s `mixed_zh_tw_32kb_clean`
/// payload class is built from, copied verbatim.
///
/// Duplicated rather than imported because the benches are a separate crate
/// target with no shared module, and the bench asserts nothing — it is a
/// research harness. AAASM-5450's acceptance criteria name this payload class
/// explicitly, so its finding count needs a gate rather than a benchmark, and
/// that gate is [`the_zh_tw_payload_class_named_by_the_acceptance_criteria_stays_clean`].
const BENIGN_BLOCK_ZH_TW: &str = "使用者請求：請協助查詢訂單狀態，並將結果整理成報表。\
     系統回應：查詢完成，共 12 筆資料，處理時間 340 毫秒。\
     備註 (note): the retrieval step returned 12 rows from the orders table. \
     設定檔版本 version = \"1.0.0\"，環境 environment = production。\
     日誌：2026-04-27T12:00:00Z 資訊 處理中 request_id=abc123 狀態正常。";

/// **`mixed_zh_tw_32kb_clean` must stay at zero findings.**
///
/// The payload class AAASM-5450's acceptance criteria name by name: full-width
/// and half-width punctuation around short digit runs, a dotted version string, a
/// timestamp, and no secret anywhere. Nothing in the repository gated it before —
/// the bench that defines it measures latency and asserts nothing, and its own
/// comment still claims 87 findings from before AAASM-5344 fixed the entropy
/// pass. Measured here it is zero, and this keeps it there.
///
/// What this test is **not**: evidence that the widened separator set is
/// restrained on CJK text. Joined across the widest candidate set — all seven
/// AAASM-5450 named, plus the four already admitted — this payload's longest
/// digit run is eight digits, five short of the 13-digit floor `luhn_valid`
/// gates on. It stays clean because the checksum is unreachable here, not
/// because the set is narrow, and no separator decision can move it. The
/// separator set's cost is measured over [`CORPUS_NAME`], which can reach the
/// window; this is a requirement gate against the other failure mode — an
/// entropy or token window that reaches CJK text, which is what put this exact
/// payload at 87 findings once.
#[test]
fn the_zh_tw_payload_class_named_by_the_acceptance_criteria_stays_clean() {
    let mut payload = String::with_capacity(33 * 1024);
    while payload.len() < 32 * 1024 {
        payload.push_str(BENIGN_BLOCK_ZH_TW);
    }

    let scanner = CredentialScanner::new();
    let findings = scanner.scan(&payload).findings;

    assert!(
        findings.is_empty(),
        "mixed_zh_tw_32kb_clean produced {:?} over {} bytes; the acceptance criteria require it \
         to stay at zero",
        findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>(),
        payload.len(),
    );
    println!("mixed_zh_tw_32kb_clean: 0 findings over {} bytes", payload.len());
}
