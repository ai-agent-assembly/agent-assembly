//! The Taiwan (zh-TW) deterministic recognizer pack (AAASM-5353).
//!
//! # Word boundaries do not exist here
//!
//! `\b` is useless against this input and the mistake is not theoretical: Han
//! characters are alphabetic, therefore word characters, so `\b\d{8}\b` does not
//! match `統編12345675` — which is exactly how the identifier is written in
//! practice, with no separator between the label and the number. Every boundary
//! test in this module is therefore explicit (`is_fragment_neighbour`), and it
//! treats a Han character as a boundary and an ASCII alphanumeric as not one.
//!
//! # Residual false-positive rates, stated rather than hidden
//!
//! A checksum over a short numeric domain admits a fixed fraction of random
//! strings. Recall matters asymmetrically for a security control — a miss is a
//! leak — so these recognizers are tuned to catch the identifier and the cost is
//! paid in precision. What that costs:
//!
//! | Recognizer | Structural constraint | Residual |
//! |---|---|---|
//! | 國民身分證 / 2021 居留證 | letter + 9 digits, weighted mod-10, `d₁ ∈ {1,2,8,9}` | ~4% of random letter+9-digit strings |
//! | Legacy 居留證 | 2 letters (2nd ∈ A–D) + 8 digits, weighted mod-10 | ~10% of random strings of that shape |
//! | 統一編號 | 8 whole digits, weighted digit-sum mod 5 | **~20% of random 8-digit strings** |
//! | 行動電話 | `09` + exactly 8 more digits | no checksum exists |
//! | 市內電話 | area-code gazetteer + separator + that area's local length | no checksum exists; **unseparated landlines are not detected** |
//!
//! The 統一編號 row is the one that matters. Roughly one 8-digit numeric literal
//! in five passes, so a bare `YYYYMMDD` date, a build number or an order
//! reference will sometimes be reported —
//! `a_bare_eight_digit_date_is_a_known_business_id_residual` pins that rather
//! than leaving a reviewer to discover it. It is reported at
//! `ConfidenceBand::Low` without a context keyword for exactly this reason, and
//! `Severity::Low`, so it sorts below findings that carry real harm. Narrowing
//! it further would mean *requiring* a context keyword, which the identifier
//! does not always carry and which the acceptance criteria rule out.
//!
//! # What this pack does not recognise
//!
//! Chinese personal names, addresses and 健保卡號 are probabilistic or have no
//! stable published algorithm. They are out of scope and are not claimed
//! anywhere. Nothing here should be read as complete coverage of Taiwanese
//! personal data.
//!
//! # Fixtures
//!
//! Every identifier in this module's tests is synthetic and constructed by
//! computing the check digit over a visibly patterned body (`A2` + seven zeros,
//! `A8` + seven zeros, and so on) with the same arithmetic the validator uses,
//! shown in the test module's `check_digit_for_id`. No value was taken from a real
//! document. A checksum-valid identifier is by construction indistinguishable
//! from an issued one, which is why the bodies are chosen to be obviously
//! generated rather than plausible.

use crate::canonical::{
    ByteSpan, CanonicalCategory, CanonicalFinding, CategoryBase as Base, ConfidenceBand, DetectionMethod,
    FindingStatus, Provenance, Recognizer, Severity,
};
use crate::scanner::ascii_digit_of;

/// The recognizer identity and version stamped on every finding this pack
/// produces.
///
/// Versioned with the crate for the same reason
/// [`SCANNER_PROVENANCE`](crate::canonical::SCANNER_PROVENANCE) is: the letter
/// tables, the 統一編號 checksum rule and the area-code gazetteer are all
/// versioned with the release, and a re-scan under a later one may legitimately
/// differ.
pub const ZH_TW_PROVENANCE: Provenance = Provenance::new(Recognizer::ZhTwLocalePack, env!("CARGO_PKG_VERSION"));

/// 國民身分證統一編號 — the national identity-card number.
const NATIONAL_ID: CanonicalCategory = CanonicalCategory::with_locale(Base::NationalId, "zh-TW", "national_id");
/// 統一證號 in the 2021 form — one letter and nine digits, like the national ID.
const ARC_NEW: CanonicalCategory = CanonicalCategory::with_locale(Base::NationalId, "zh-TW", "arc_new");
/// 統一證號 in the pre-2021 form — two letters and eight digits.
const ARC_LEGACY: CanonicalCategory = CanonicalCategory::with_locale(Base::NationalId, "zh-TW", "arc_legacy");
/// 統一編號 — the business registration / tax number.
const BUSINESS_ID: CanonicalCategory = CanonicalCategory::with_locale(Base::TaxIdentifier, "zh-TW", "business_id");

// ---------------------------------------------------------------------------
// Boundary handling
// ---------------------------------------------------------------------------

/// Whether `c` sitting immediately beside a candidate means the candidate is a
/// *fragment* of something longer rather than a whole identifier.
///
/// ASCII alphanumerics and digit characters of either width qualify, for the
/// obvious reason. `.` and `,` do too, and that is the non-obvious half: they
/// are the decimal point and the thousands separator, so the eight digits after
/// the point in `3.14159265` are a fragment of one number and not a 統一編號 —
/// and with a checksum that admits one string in five, that class of match would
/// dominate the output on any payload carrying floating-point data.
///
/// `+` is here so the digits of `+886…` cannot be re-read as a bare identifier
/// once the phone recognizer has declined them — the country code is part of
/// one number, not a prefix in front of another.
///
/// A Han character is deliberately **not** a fragment neighbour. That is the
/// whole point: `統編12345675` is how the identifier is written, and treating
/// Han as a word character — which every `\b`-based implementation does — makes
/// this recognizer miss the common case.
fn is_fragment_neighbour(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || ascii_digit_of(c).is_some()
        || ascii_uppercase_of(c).is_some()
        || matches!(c, '.' | ',' | '+')
}

/// The ASCII uppercase equivalent of `c` — `c` itself for `'A'..='Z'`, and the
/// corresponding ASCII letter for the full-width forms `'Ａ'..='Ｚ'`
/// (U+FF21–U+FF3A). `None` for anything else.
///
/// The companion to `ascii_digit_of`, and needed for the same reason. A
/// Taiwanese identity number is one letter and nine digits; on a CJK input
/// method the whole value is typed in one mode, so the letter arrives full-width
/// exactly as often as the digits do. Normalising only the digits would leave a
/// one-character evasion of every identity recognizer here — press one key
/// differently and `Ａ200000003` is invisible.
///
/// As with digits, this is for **matching only**: a full-width letter is three
/// UTF-8 bytes against ASCII's one, so callers advance offsets by the original
/// character's width.
fn ascii_uppercase_of(c: char) -> Option<char> {
    match c {
        'A'..='Z' => Some(c),
        '\u{FF21}'..='\u{FF3A}' => char::from_u32(c as u32 - 0xFF21 + u32::from(b'A')),
        _ => None,
    }
}

/// Whether the character immediately before byte offset `start` permits a
/// candidate to begin there.
fn left_boundary_ok(text: &str, start: usize) -> bool {
    // `Option::is_none_or` would read better but is stable only from 1.82,
    // above this workspace's floor (see `aa-core::integration::version`).
    match text[..start].chars().next_back() {
        Some(c) => !is_fragment_neighbour(c),
        None => true,
    }
}

/// Whether the character at byte offset `end` permits a candidate to end there.
fn right_boundary_ok(text: &str, end: usize) -> bool {
    match text[end..].chars().next() {
        Some(c) => !is_fragment_neighbour(c),
        None => true,
    }
}

/// Reads exactly `count` digit characters starting at byte offset `start`,
/// returning the byte offset just past them and their ASCII-normalised value.
///
/// Full-width digits normalise through `ascii_digit_of`, so an identifier
/// typed on a CJK input method is recognised as the same value as its ASCII
/// form — but the returned offset advances by the *original* character width,
/// so it stays a valid index into `text`. A full-width digit is three UTF-8
/// bytes against ASCII's one; an offset computed from the normalised string
/// would index the wrong bytes and make redaction fail closed over the whole
/// payload.
///
/// `None` if fewer than `count` digits are available.
fn read_digits(text: &str, start: usize, count: usize) -> Option<(usize, String)> {
    let mut digits = String::with_capacity(count);
    let mut end = start;
    for _ in 0..count {
        let c = text[end..].chars().next()?;
        digits.push(ascii_digit_of(c)?);
        end += c.len_utf8();
    }
    Some((end, digits))
}

// ---------------------------------------------------------------------------
// 國民身分證統一編號 and 統一證號 (居留證)
// ---------------------------------------------------------------------------

/// The two-digit area code of an identity-card letter, or `None` if `c` is not
/// one of the 26 letters the scheme assigns.
///
/// The table is the published one and is not derivable from the alphabet: `I`,
/// `O`, `W`, `X`, `Y` and `Z` are out of sequence because the letters were
/// assigned to administrative divisions in an order that later changed.
const fn letter_code(c: char) -> Option<u32> {
    Some(match c {
        'A' => 10,
        'B' => 11,
        'C' => 12,
        'D' => 13,
        'E' => 14,
        'F' => 15,
        'G' => 16,
        'H' => 17,
        'I' => 34,
        'J' => 18,
        'K' => 19,
        'L' => 20,
        'M' => 21,
        'N' => 22,
        'O' => 35,
        'P' => 23,
        'Q' => 24,
        'R' => 25,
        'S' => 26,
        'T' => 27,
        'U' => 28,
        'V' => 29,
        'W' => 32,
        'X' => 30,
        'Y' => 31,
        'Z' => 33,
        _ => return None,
    })
}

/// Whether `letter` + `digits` (nine ASCII digits) satisfies the identity-card
/// checksum.
///
/// The letter contributes its two-digit code as `n₁·1 + n₂·9`; the first eight
/// digits carry descending weights 8…1; the ninth is the check digit and is
/// added unweighted. The whole sum must be divisible by 10.
///
/// The **2021 residence certificate uses this identical algorithm**, differing
/// only in the leading digit. A validator that filtered on `d₁ ∈ {1,2}` — the
/// national-ID gender codes — would therefore reject every foreign resident's
/// number while looking entirely correct, which is why the digit class is
/// resolved by `id_category` *after* the checksum rather than folded into it.
fn national_id_checksum_ok(letter: char, digits: &str) -> bool {
    let Some(code) = letter_code(letter) else {
        return false;
    };
    if digits.len() != 9 {
        return false;
    }
    let mut sum = code / 10 + (code % 10) * 9;
    for (i, c) in digits.chars().enumerate() {
        let Some(d) = c.to_digit(10) else { return false };
        // Weights 8..=1 over the first eight digits, then the check digit at
        // weight 1.
        let weight = if i < 8 { 8 - i as u32 } else { 1 };
        sum += d * weight;
    }
    sum % 10 == 0
}

/// Which document a checksum-valid letter+9-digit number is, from its leading
/// digit — or `None` if the leading digit belongs to no issued form.
///
/// `1`/`2` are the national ID's gender codes and `8`/`9` the 2021 residence
/// certificate's. Nothing else is issued, so rejecting the rest is a real
/// structural constraint: it cuts the residual from the checksum's ~10% of
/// random strings of this shape to roughly 4%.
const fn id_category(first_digit: u8) -> Option<CanonicalCategory> {
    match first_digit {
        b'1' | b'2' => Some(NATIONAL_ID),
        b'8' | b'9' => Some(ARC_NEW),
        _ => None,
    }
}

/// Whether the legacy residence certificate's two letters and eight digits
/// satisfy its checksum.
///
/// Same weighting as the national ID, with the second letter standing in for
/// the national ID's first digit: it contributes only the **units digit** of its
/// area code, so `A`→0, `B`→1, `C`→2, `D`→3. Only those four are issued (A/C
/// male, B/D female), which is enforced here rather than accepting any letter.
fn arc_legacy_checksum_ok(first: char, second: char, digits: &str) -> bool {
    let (Some(code), Some(second_code)) = (letter_code(first), letter_code(second)) else {
        return false;
    };
    if !matches!(second, 'A' | 'B' | 'C' | 'D') || digits.len() != 8 {
        return false;
    }
    let mut sum = code / 10 + (code % 10) * 9 + (second_code % 10) * 8;
    for (i, c) in digits.chars().enumerate() {
        let Some(d) = c.to_digit(10) else { return false };
        // Weights 7..=1 over the first seven digits, then the check digit.
        let weight = if i < 7 { 7 - i as u32 } else { 1 };
        sum += d * weight;
    }
    sum % 10 == 0
}

/// Try to read an identity-card or residence-certificate number at `start`.
///
/// Returns the category and the byte offset just past the number. The legacy
/// two-letter form and the one-letter forms cannot be confused: the character
/// after the first letter is either a letter or a digit, and that decides which
/// grammar applies.
fn scan_identity_number(text: &str, start: usize) -> Option<(CanonicalCategory, usize)> {
    let mut chars = text[start..].chars();
    // Normalised for matching; offsets still advance by the *original*
    // character's width, which is three bytes for a full-width letter.
    let first_raw = chars.next()?;
    let first = ascii_uppercase_of(first_raw)?;
    let after_first = start + first_raw.len_utf8();
    let second_raw = chars.next()?;

    if let Some(second) = ascii_uppercase_of(second_raw) {
        let (end, digits) = read_digits(text, after_first + second_raw.len_utf8(), 8)?;
        if !right_boundary_ok(text, end) || !arc_legacy_checksum_ok(first, second, &digits) {
            return None;
        }
        return Some((ARC_LEGACY, end));
    }

    let (end, digits) = read_digits(text, after_first, 9)?;
    if !right_boundary_ok(text, end) || !national_id_checksum_ok(first, &digits) {
        return None;
    }
    let category = id_category(digits.as_bytes()[0])?;
    Some((category, end))
}

// ---------------------------------------------------------------------------
// 統一編號 (business registration / tax number)
// ---------------------------------------------------------------------------

/// Positional weights of the 統一編號 checksum.
///
/// The seventh weight is 4, not 2 — the sequence is not the alternating 1/2 it
/// looks like, and treating it as one produces a validator that agrees with the
/// real rule on most inputs and disagrees on the rest.
const BUSINESS_ID_WEIGHTS: [u32; 8] = [1, 2, 1, 2, 1, 2, 4, 1];

/// Which era's rule a checksum-valid 統一編號 satisfies.
///
/// Modelled explicitly rather than collapsed to a boolean so the two rules are
/// individually testable. The distinction is invisible in the output — both
/// produce the same category — but not in the code, and it is the difference
/// between shipping a working detector and one that misses every business
/// registered since April 2023.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusinessIdEra {
    /// Satisfies the pre-2023-04-01 rule: the weighted digit-sum is divisible
    /// by 10.
    PreApril2023,
    /// Satisfies only the current rule: divisible by 5 but not by 10.
    ///
    /// This variant is the trap. The Ministry of Finance relaxed the divisor
    /// from 10 to 5 on 2023-04-01, and because every mod-10-valid number is also
    /// mod-5-valid, a legacy-only validator passes every test written against
    /// numbers issued before that date while silently missing everything issued
    /// after it.
    CurrentOnly,
}

/// The weighted digit-sum the 統一編號 rule is applied to.
///
/// Each digit is multiplied by its positional weight and the **digits of the
/// product** are summed, not the product — so `7 × 4 = 28` contributes 10, not
/// 28. Summing the products instead gives a validator that is right about
/// roughly half of all inputs.
fn business_id_sum(digits: &str) -> Option<u32> {
    if digits.len() != 8 {
        return None;
    }
    let mut sum = 0u32;
    for (i, c) in digits.chars().enumerate() {
        let product = c.to_digit(10)? * BUSINESS_ID_WEIGHTS[i];
        sum += product / 10 + product % 10;
    }
    Some(sum)
}

/// Which rule, if any, `digits` satisfies.
///
/// The historical seventh-digit exception applies under both eras: when the
/// seventh digit is 7, the sum is allowed to be one short of a multiple of the
/// divisor, because that digit's weight-4 product was originally carried
/// differently.
fn business_id_era(digits: &str) -> Option<BusinessIdEra> {
    let sum = business_id_sum(digits)?;
    let seventh_is_seven = digits.as_bytes()[6] == b'7';
    let satisfies = |divisor: u32| sum % divisor == 0 || (seventh_is_seven && (sum + 1) % divisor == 0);

    if satisfies(10) {
        Some(BusinessIdEra::PreApril2023)
    } else if satisfies(5) {
        Some(BusinessIdEra::CurrentOnly)
    } else {
        None
    }
}

/// Try to read a 統一編號 at `start`: exactly eight digits, whole.
///
/// "Whole" is doing real work. The checksum admits roughly one 8-digit string in
/// five, so without the boundary tests every eight-digit window of every longer
/// number would be a candidate and the output would be dominated by fragments.
fn scan_business_id(text: &str, start: usize) -> Option<(CanonicalCategory, usize)> {
    let (end, digits) = read_digits(text, start, 8)?;
    if !right_boundary_ok(text, end) {
        return None;
    }
    business_id_era(&digits).map(|_| (BUSINESS_ID, end))
}

// ---------------------------------------------------------------------------
// Telephone numbers
// ---------------------------------------------------------------------------

/// 行動電話 — a mobile number.
const MOBILE: CanonicalCategory = CanonicalCategory::with_locale(Base::PhoneNumber, "zh-TW", "mobile");
/// 市內電話 — a landline.
const LANDLINE: CanonicalCategory = CanonicalCategory::with_locale(Base::PhoneNumber, "zh-TW", "landline");

/// Landline area codes, written **without** the trunk `0`, paired with the
/// subscriber-number lengths that area uses.
///
/// A gazetteer rather than "any digit then seven or eight more", because a
/// phone number has no checksum: the closed set of area codes and the fixed
/// local length per area are the only structure available, and without them
/// this recognizer would flag most 9- and 10-digit numbers.
///
/// Longest match wins, which is what disambiguates `3` from `37` and `8` from
/// `82` / `826` / `89`. Taichung and Changhua share `4` with different lengths,
/// so an area code maps to a set.
const LANDLINE_AREA_CODES: &[(&str, &[usize])] = &[
    ("826", &[5]),
    ("836", &[5]),
    ("37", &[6]),
    ("49", &[7]),
    ("82", &[6]),
    ("89", &[6]),
    ("2", &[8]),
    ("3", &[7]),
    ("4", &[7, 8]),
    ("5", &[7]),
    ("6", &[7]),
    ("7", &[7]),
    ("8", &[7]),
];

/// The longest national significant number Taiwan issues: a mobile is nine
/// digits after the trunk `0`, and no landline is longer.
///
/// Also the read budget, which is what stops a longer digit run being truncated
/// into a match: the reader stops at nine, the tenth digit then fails the right
/// boundary test, and the candidate is rejected rather than reported as a
/// prefix of something else.
const MAX_NATIONAL_SIGNIFICANT_DIGITS: usize = 9;

/// Reads digits from `start`, allowing a single `-`, space or `)` **between**
/// digits, and stopping at `max_digits`.
///
/// Returns the byte offset just past the last digit, the ASCII-normalised
/// digits, and how many separators were consumed. A trailing separator is never
/// swallowed — the span must end on the number, or redaction would rewrite a
/// character that is not part of it.
fn read_grouped_digits(text: &str, start: usize, max_digits: usize) -> (usize, String, usize) {
    let mut digits = String::new();
    let mut separators = 0usize;
    let mut end = start;

    while let Some(c) = text[end..].chars().next() {
        if let Some(d) = ascii_digit_of(c) {
            if digits.len() == max_digits {
                break;
            }
            digits.push(d);
            end += c.len_utf8();
            continue;
        }

        let is_separator = matches!(c, '-' | ' ' | ')');
        let followed_by_digit = text[end + c.len_utf8()..]
            .chars()
            .next()
            .and_then(ascii_digit_of)
            .is_some();
        if is_separator && !digits.is_empty() && followed_by_digit && digits.len() < max_digits {
            separators += 1;
            end += c.len_utf8();
            continue;
        }

        break;
    }

    (end, digits, separators)
}

/// Classify a national significant number — the digits after the trunk `0` or
/// after `+886`.
fn classify_national_number(digits: &str, separated: bool) -> Option<CanonicalCategory> {
    // Mobile: `9` plus eight more, which is `09` plus eight in national form.
    if digits.len() == MAX_NATIONAL_SIGNIFICANT_DIGITS && digits.starts_with('9') {
        return Some(MOBILE);
    }

    // A landline must be written with a separator, `(0x)` parentheses or the
    // `+886` prefix. Unseparated landlines are a **known miss**, and a
    // deliberate one: `0212345678` is indistinguishable in shape from a
    // ten-digit account or reference number beginning with a zero, and with no
    // checksum to appeal to, accepting it would report a large class of
    // ordinary numbers as personal data.
    if !separated {
        return None;
    }
    LANDLINE_AREA_CODES
        .iter()
        .find(|(area, lengths)| digits.starts_with(*area) && lengths.contains(&(digits.len() - area.len())))
        .map(|_| LANDLINE)
}

/// Try to read a Taiwanese telephone number at `start`.
///
/// Three written forms, all reduced to the same national significant number
/// before classification: `0…` with the trunk prefix, `(0x)…` with the area
/// code parenthesised, and `+886…` with the trunk `0` dropped — the leading-zero
/// drop being the part an implementation tends to get wrong, since the
/// international form of `0912345678` is `+886912345678` and not
/// `+8860912345678`.
fn scan_phone_number(text: &str, start: usize) -> Option<(CanonicalCategory, usize)> {
    let rest = &text[start..];
    let (mut pos, international) = match rest.strip_prefix("+886") {
        Some(_) => (start + "+886".len(), true),
        None => (start, false),
    };

    if international {
        // An optional separator, then an optional trunk `0` some writers keep
        // even though the international form drops it.
        if matches!(text[pos..].chars().next(), Some('-' | ' ')) {
            pos += 1;
        }
        if text[pos..].starts_with('0') {
            pos += 1;
        }
    } else {
        // `(0x)` — consume the opening paren; the closing one is read as a
        // separator by `read_grouped_digits`.
        let parenthesised = text[pos..].starts_with('(');
        if parenthesised {
            pos += 1;
        }
        // The trunk prefix. Normalised, so a full-width `０` counts.
        let trunk = text[pos..].chars().next().and_then(ascii_digit_of)?;
        if trunk != '0' {
            return None;
        }
        pos += text[pos..].chars().next()?.len_utf8();
    }

    let (end, digits, separators) = read_grouped_digits(text, pos, MAX_NATIONAL_SIGNIFICANT_DIGITS);
    if !right_boundary_ok(text, end) {
        return None;
    }
    let category = classify_national_number(&digits, separators > 0 || international)?;
    Some((category, end))
}

// ---------------------------------------------------------------------------
// Context keywords
// ---------------------------------------------------------------------------

/// Labels that, immediately before a candidate, make it far likelier to be the
/// identifier its shape suggests.
///
/// Both spellings of 身分證/身份證 are present: the second is a common
/// misspelling that appears constantly in real form data, and omitting it would
/// silently drop the confidence signal on a large share of genuine hits.
const CONTEXT_KEYWORDS: &[&str] = &[
    "身分證",
    "身份證",
    "居留證",
    "統一證號",
    "統一編號",
    "統編",
    "營業人",
    "電話",
    "手機",
    "行動電話",
    "市話",
    "傳真",
];

/// How many bytes before a candidate are searched for a context keyword.
///
/// Deliberately short. A keyword is evidence only if it labels *this* value, and
/// a wide window turns any document that mentions 身分證 once into one where
/// every 8-digit number is confidently an identifier. 32 bytes is about ten Han
/// characters — enough for `身分證字號：` plus punctuation, not enough to reach
/// the previous sentence.
const CONTEXT_WINDOW_BYTES: usize = 32;

/// Whether a context keyword labels the candidate starting at `start`.
///
/// Confidence only — never a precondition. A checksum-valid identifier is
/// reported whether or not it is labelled, because the label is a convention and
/// the checksum is the evidence.
fn has_context_keyword(text: &str, start: usize) -> bool {
    let window_start = text[..start]
        .char_indices()
        .rev()
        .take_while(|(i, _)| start - i <= CONTEXT_WINDOW_BYTES)
        .map(|(i, _)| i)
        .last()
        .unwrap_or(start);
    let window = &text[window_start..start];
    CONTEXT_KEYWORDS.iter().any(|k| window.contains(k))
}

// ---------------------------------------------------------------------------
// Finding assembly
// ---------------------------------------------------------------------------

/// The severity and unlabelled confidence this pack assigns to a category.
///
/// Severity answers "how damaging is exposure", not "how sure are we" — the two
/// are separate axes on purpose. The identity documents are `Critical`,
/// alongside the SSN the scanner already classifies that way. Phone numbers are
/// `Medium`: personal data whose exposure is harmful but grants no access, the
/// same band as an email address. 統一編號 is `Low`, and that is a deliberate
/// judgement rather than an oversight — it is published in the government's
/// business registry and printed on every invoice, so its exposure is not itself
/// harmful; it is reported because a payload carrying one identifies a
/// counterparty, and because its checksum is weak enough that ranking it above
/// an email address would bury real findings under it.
fn bands(category: CanonicalCategory) -> (Severity, ConfidenceBand) {
    match category {
        NATIONAL_ID | ARC_NEW | ARC_LEGACY => (Severity::Critical, ConfidenceBand::Medium),
        // A mobile's `09` prefix plus its exact length is real structure; a
        // landline rests on an area-code gazetteer alone, which is weaker.
        MOBILE => (Severity::Medium, ConfidenceBand::Medium),
        LANDLINE => (Severity::Medium, ConfidenceBand::Low),
        // 統一編號, and anything a later locale adds without its own row.
        _ => (Severity::Low, ConfidenceBand::Low),
    }
}

/// Raise a band one step because a context keyword labels the value.
///
/// One step, not straight to `High`. A label is corroboration, not proof: a
/// 統編 next to the word 統編 is much more likely to be one, but the checksum
/// underneath still admits a fifth of all 8-digit strings, and a document that
/// discusses the identifier while quoting an unrelated number is ordinary.
const fn corroborated(band: ConfidenceBand) -> ConfidenceBand {
    match band {
        ConfidenceBand::Low => ConfidenceBand::Medium,
        _ => ConfidenceBand::High,
    }
}

/// Build the finding for a recognised span.
///
/// Returns `None` only for a malformed span, which
/// [`CanonicalFinding::new`] rejects — unreachable for spans produced here,
/// since every recognizer consumes at least one character, and kept fallible
/// rather than unwrapped so a future recognizer with an off-by-one cannot panic
/// on a caller's payload.
fn finding(text: &str, category: CanonicalCategory, start: usize, end: usize) -> Option<CanonicalFinding> {
    let (severity, base_band) = bands(category);
    let confidence = if has_context_keyword(text, start) {
        corroborated(base_band)
    } else {
        base_band
    };
    CanonicalFinding::new(
        category,
        severity,
        confidence,
        ByteSpan::new(start, end),
        // Every recognizer in this pack is a checksum or a fixed structure, so
        // the match is exact about what it matched even where it cannot be
        // certain the value is real — the same reading of this axis the scanner
        // applies to `SsnPattern`, which also has no checksum.
        DetectionMethod::Deterministic,
        ZH_TW_PROVENANCE,
        match confidence {
            ConfidenceBand::High => FindingStatus::Confirmed,
            _ => FindingStatus::Suspected,
        },
    )
    .ok()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Scan `text` for Taiwanese identifiers, returning findings in offset order.
///
/// Additive and independent: this never calls, and is never called by,
/// [`CredentialScanner::scan`](crate::scanner::CredentialScanner::scan), whose
/// output is unchanged by this module. A caller that wants both runs both.
///
/// Spans are byte offsets into `text` and always fall on character boundaries,
/// so [`redact_findings`](crate::canonical::redact_findings) can splice them.
///
/// Detection is best-effort within the constraints documented on this module:
/// the checksums admit a stated fraction of random strings, phone numbers have
/// no checksum, and unseparated landline numbers are not recognised at all.
pub fn scan(text: &str) -> Vec<CanonicalFinding> {
    let mut findings = Vec::new();
    let mut i = 0usize;

    while i < text.len() {
        let Some(c) = text[i..].chars().next() else { break };
        let width = c.len_utf8();

        if !left_boundary_ok(text, i) {
            i += width;
            continue;
        }

        // Order matters among the digit-initial forms: a phone number is tried
        // before a 統一編號 so a nine-digit national number is never truncated
        // into an eight-digit tax number by whichever ran first. Letter-initial
        // forms cannot collide with either.
        let hit = scan_identity_number(text, i)
            .or_else(|| scan_phone_number(text, i))
            .or_else(|| scan_business_id(text, i));

        match hit {
            Some((category, end)) => {
                if let Some(f) = finding(text, category, i, end) {
                    findings.push(f);
                }
                i = end;
            }
            None => i += width,
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check digit that makes `letter` + `body` (eight digits) a
    /// checksum-valid identity-card or 2021 residence-certificate number.
    ///
    /// This is the fixture generator, and it is written out rather than hidden
    /// behind the validator so a reviewer can confirm every identifier in this
    /// file was *constructed* — not harvested from a real document. It runs the
    /// same weighted sum `national_id_checksum_ok` checks and returns the digit
    /// that zeroes it mod 10.
    fn check_digit_for_id(letter: char, body: &str) -> char {
        assert_eq!(body.len(), 8, "the body is the eight digits before the check digit");
        let code = letter_code(letter).expect("fixture letters are in the table");
        let mut sum = code / 10 + (code % 10) * 9;
        for (i, c) in body.chars().enumerate() {
            sum += c.to_digit(10).expect("fixture bodies are digits") * (8 - i as u32);
        }
        char::from_digit((10 - sum % 10) % 10, 10).expect("a mod-10 residue is a digit")
    }

    /// Assemble a synthetic identifier from a letter and a visibly patterned
    /// eight-digit body.
    fn synthetic_id(letter: char, body: &str) -> String {
        format!("{letter}{body}{}", check_digit_for_id(letter, body))
    }

    /// The same, for the legacy two-letter form's seven-digit body.
    fn synthetic_legacy_arc(first: char, second: char, body: &str) -> String {
        assert_eq!(body.len(), 7);
        let code = letter_code(first).expect("in table");
        let second_code = letter_code(second).expect("in table");
        let mut sum = code / 10 + (code % 10) * 9 + (second_code % 10) * 8;
        for (i, c) in body.chars().enumerate() {
            sum += c.to_digit(10).expect("digits") * (7 - i as u32);
        }
        let check = char::from_digit((10 - sum % 10) % 10, 10).expect("digit");
        format!("{first}{second}{body}{check}")
    }

    fn categories(text: &str) -> Vec<String> {
        scan(text).iter().map(|f| f.category().to_string()).collect()
    }

    /// The generator and the validator must agree, or every positive fixture
    /// below proves only that two copies of the same bug agree with each other.
    ///
    /// Checked across the whole letter table and several bodies rather than on
    /// one value, so a table entry transposed in either place shows up here.
    #[test]
    fn the_fixture_generator_produces_values_the_validator_accepts() {
        let mut built = 0usize;
        for letter in 'A'..='Z' {
            for body in ["20000000", "10000000", "80000000", "90000000", "27182818"] {
                let id = synthetic_id(letter, body);
                let digits = &id[1..];
                assert!(
                    national_id_checksum_ok(letter, digits),
                    "generated {id} but the validator rejects it"
                );
                // And the generator is not vacuous: changing one digit breaks it.
                let mutated: String = format!("{}{}", &digits[..8], (digits.as_bytes()[8] - b'0' + 1) % 10);
                assert!(
                    !national_id_checksum_ok(letter, &mutated),
                    "{id} still validates with a different check digit"
                );
                built += 1;
            }
        }
        assert_eq!(built, 26 * 5);
    }

    /// A national ID is detected, and detected as the national ID rather than as
    /// a residence certificate.
    #[test]
    fn a_synthetic_national_id_is_detected() {
        for body in ["20000000", "10000000"] {
            let id = synthetic_id('A', body);
            let text = format!("身分證字號 {id} 已建檔");
            assert_eq!(categories(&text), ["NATIONAL_ID[zh-TW/national_id]"], "{id}");
        }
    }

    /// **The trap this ticket exists to avoid.** The 2021 residence certificate
    /// uses the identical checksum and differs only in the leading digit, so a
    /// validator written against the national ID's `d₁ ∈ {1,2}` looks correct,
    /// passes every national-ID test, and misses every foreign resident.
    #[test]
    fn a_synthetic_2021_residence_certificate_is_detected() {
        for body in ["80000000", "90000000"] {
            let id = synthetic_id('A', body);
            let text = format!("居留證號碼 {id}");
            assert_eq!(categories(&text), ["NATIONAL_ID[zh-TW/arc_new]"], "{id}");
        }
    }

    /// The legacy two-letter certificate is a separate grammar and a separate
    /// checksum, and must not be reachable through the one-letter path.
    #[test]
    fn a_synthetic_legacy_residence_certificate_is_detected() {
        for second in ['A', 'B', 'C', 'D'] {
            let id = synthetic_legacy_arc('A', second, "0000000");
            let text = format!("舊式居留證 {id}");
            assert_eq!(categories(&text), ["NATIONAL_ID[zh-TW/arc_legacy]"], "{id}");
        }
    }

    /// The legacy generator and validator must agree, and the check digit must
    /// **matter**.
    ///
    /// This test exists because its absence was a real hole, found by review
    /// after the first version of this PR: defeating `arc_legacy_checksum_ok`'s
    /// arithmetic outright — while leaving the A–D letter-class check intact —
    /// passed the entire suite. The legacy near-miss was credited to
    /// `a_legacy_certificate_with_an_unissued_second_letter_is_rejected`, but
    /// that test varies the *letter*, never the digits, so the
    /// `(second_code % 10) * 8` term and the 7..=1 weighting were completely
    /// unprotected. An arithmetic error there means **missed** residence
    /// certificates, which is the asymmetric direction: a miss is a leak.
    ///
    /// The national-ID path had this from the start
    /// (`the_fixture_generator_produces_values_the_validator_accepts`); the
    /// legacy path did not, and the two are separate weightings.
    #[test]
    fn the_legacy_fixture_generator_produces_values_the_validator_accepts() {
        let mut built = 0usize;
        for first in 'A'..='Z' {
            for second in ['A', 'B', 'C', 'D'] {
                for body in ["0000000", "1234567", "9876543"] {
                    let id = synthetic_legacy_arc(first, second, body);
                    assert!(
                        arc_legacy_checksum_ok(first, second, &id[2..]),
                        "generated {id} but the validator rejects it"
                    );
                    // Not vacuous: every *other* check digit must be refused, so
                    // a validator that ignores the arithmetic cannot pass.
                    let correct = id.as_bytes()[9] - b'0';
                    for delta in 1..10u8 {
                        let wrong = format!("{}{}", &id[..9], (correct + delta) % 10);
                        assert!(
                            !arc_legacy_checksum_ok(first, second, &wrong[2..]),
                            "{wrong} validates, but only {id} should"
                        );
                    }
                    built += 1;
                }
            }
        }
        assert_eq!(built, 26 * 4 * 3);
    }

    /// The same, end to end through `scan`: a legacy certificate whose check
    /// digit is wrong is not reported.
    #[test]
    fn a_legacy_certificate_with_a_wrong_check_digit_is_rejected() {
        for second in ['A', 'B', 'C', 'D'] {
            let id = synthetic_legacy_arc('A', second, "1234567");
            let correct = id.as_bytes()[9] - b'0';
            for delta in 1..10u8 {
                let wrong = format!("{}{}", &id[..9], (correct + delta) % 10);
                assert_eq!(
                    categories(&format!("舊式居留證 {wrong}")),
                    Vec::<String>::new(),
                    "{wrong} was reported but only {id} is checksum-valid"
                );
            }
            // The correct one is still found, so the loop above is not passing
            // because the recognizer stopped working.
            assert_eq!(
                categories(&format!("舊式居留證 {id}")),
                ["NATIONAL_ID[zh-TW/arc_legacy]"],
                "{id}"
            );
        }
    }

    /// A second letter outside A–D is not issued, so the shape alone must not be
    /// enough — otherwise every `XY` + 8 digits string gets a 10% pass rate.
    ///
    /// This is a **letter-class** test, not a checksum test. Defeating the
    /// checksum arithmetic leaves it passing; that is what
    /// `the_legacy_fixture_generator_produces_values_the_validator_accepts` and
    /// `a_legacy_certificate_with_a_wrong_check_digit_is_rejected` are for.
    #[test]
    fn a_legacy_certificate_with_an_unissued_second_letter_is_rejected() {
        // Generated with `E`'s own units digit, so the weighted sum balances and
        // the *only* thing that can reject it is the letter-class constraint.
        // If that constraint is dropped, this string sails through.
        for second in ['E', 'F', 'Z'] {
            let id = synthetic_legacy_arc('A', second, "0000000");
            assert_eq!(categories(&format!("編號 {id}")), Vec::<String>::new(), "{id}");
        }
        // The same generator with an issued letter does produce a finding, so
        // the assertion above is not passing because the generator is broken.
        let issued = synthetic_legacy_arc('A', 'D', "0000000");
        assert_eq!(categories(&format!("編號 {issued}")), ["NATIONAL_ID[zh-TW/arc_legacy]"]);
    }

    /// Every near-miss must be rejected: one wrong check digit, and a leading
    /// digit that no issued document uses.
    #[test]
    fn checksum_and_structural_near_misses_are_rejected() {
        let valid = synthetic_id('A', "20000000");
        // Flip the check digit.
        let bytes = valid.as_bytes();
        let wrong_check = format!("{}{}", &valid[..9], (bytes[9] - b'0' + 5) % 10);
        assert_ne!(wrong_check, valid);
        assert_eq!(categories(&format!("身分證 {wrong_check}")), Vec::<String>::new());

        // Checksum-valid but `d₁ = 3`, which is not an issued class.
        let unissued = synthetic_id('A', "30000000");
        assert!(national_id_checksum_ok('A', &unissued[1..]), "fixture must be valid");
        assert_eq!(categories(&format!("編號 {unissued}")), Vec::<String>::new());
    }

    /// Han on both sides with no separator — the case `\b` cannot express.
    #[test]
    fn an_identifier_written_flush_against_han_is_detected() {
        let id = synthetic_id('A', "20000000");
        let text = format!("身分證{id}已登記");
        let found = scan(&text);
        assert_eq!(found.len(), 1);
        assert_eq!(&text[found[0].span().start()..found[0].span().end()], id);
    }

    /// An identifier glued to ASCII letters or digits is a fragment of something
    /// else, and must not be reported.
    #[test]
    fn an_identifier_inside_a_longer_token_is_not_reported() {
        let id = synthetic_id('A', "20000000");
        for text in [
            format!("REF{id}"),
            format!("{id}9"),
            format!("7{id}"),
            format!("x{id}x"),
        ] {
            assert_eq!(categories(&text), Vec::<String>::new(), "{text}");
        }
    }

    /// Widen every character of `s` that has a full-width form.
    fn widen(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                '0'..='9' => char::from_u32(c as u32 - u32::from(b'0') + 0xFF10).unwrap_or(c),
                'A'..='Z' => char::from_u32(c as u32 - u32::from(b'A') + 0xFF21).unwrap_or(c),
                _ => c,
            })
            .collect()
    }

    /// Full-width forms must normalise, and the span must still index the
    /// original bytes — three per character, not one.
    ///
    /// Both the digits **and the letter** are widened. Widening only the digits
    /// is what a first implementation does, and it leaves a one-keystroke
    /// evasion: on a CJK input method the whole value is typed in one mode, so
    /// the letter arrives full-width exactly as often as the digits do, and a
    /// recognizer insisting on an ASCII letter never sees the identifier at all.
    /// The mixed rows are here because a real payload is often half and half.
    #[test]
    fn a_full_width_identifier_is_detected_and_spans_the_original_bytes() {
        let id = synthetic_id('A', "20000000");
        let legacy = synthetic_legacy_arc('A', 'B', "0000000");
        let cases = [
            (widen(&id), "NATIONAL_ID[zh-TW/national_id]"),
            // Full-width letter, ASCII digits.
            (format!("Ａ{}", &id[1..]), "NATIONAL_ID[zh-TW/national_id]"),
            // ASCII letter, full-width digits.
            (format!("A{}", widen(&id[1..])), "NATIONAL_ID[zh-TW/national_id]"),
            (widen(&legacy), "NATIONAL_ID[zh-TW/arc_legacy]"),
        ];
        for (wide, expected) in cases {
            let text = format!("身分證 {wide} 已建檔");
            let found = scan(&text);
            assert_eq!(found.len(), 1, "{wide} was missed");
            assert_eq!(found[0].category().to_string(), expected, "{wide}");
            let span = found[0].span();
            assert_eq!(&text[span.start()..span.end()], wide);
            assert!(text.is_char_boundary(span.start()) && text.is_char_boundary(span.end()));
        }
    }

    /// A context keyword raises confidence; its absence must not suppress the
    /// finding.
    #[test]
    fn context_raises_confidence_but_is_not_required() {
        let id = synthetic_id('A', "20000000");

        let unlabelled = scan(&format!("（{id}）"));
        assert_eq!(unlabelled.len(), 1, "a checksum-valid ID needs no label");
        assert_eq!(unlabelled[0].confidence(), ConfidenceBand::Medium);
        assert_eq!(unlabelled[0].status(), FindingStatus::Suspected);

        let labelled = scan(&format!("身分證字號：{id}"));
        assert_eq!(labelled.len(), 1);
        assert_eq!(labelled[0].confidence(), ConfidenceBand::High);
        assert_eq!(labelled[0].status(), FindingStatus::Confirmed);
    }

    /// A keyword further back than the window must not corroborate — otherwise
    /// one mention of 身分證 promotes every number in the document.
    #[test]
    fn a_distant_keyword_does_not_corroborate() {
        let id = synthetic_id('A', "20000000");
        let text = format!("身分證的欄位在申請書的第三頁最下方的表格中填寫，另外參考編號 {id}");
        let found = scan(&text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].confidence(), ConfidenceBand::Medium, "window is too wide");
    }

    /// Provenance names this pack, not the scanner that never ran.
    #[test]
    fn findings_are_attributed_to_the_locale_pack() {
        let id = synthetic_id('A', "20000000");
        let found = scan(&format!("身分證 {id}"));
        assert_eq!(found[0].provenance().recognizer, Recognizer::ZhTwLocalePack);
        assert_eq!(found[0].provenance().recognizer.as_str(), "aa-security::locale::zh_tw");
        assert_eq!(found[0].method(), DetectionMethod::Deterministic);
    }

    /// The 統一編號 fixtures, with their arithmetic written out so a reviewer can
    /// confirm each is constructed rather than harvested.
    ///
    /// Body `1000000` puts a single 1 at weight 1, so the weighted digit-sum is
    /// `1 + check`. Body `1000007` adds `7 × 4 = 28`, whose digits sum to 10, so
    /// the total is `11 + check` and the seventh digit is a 7 — which is what
    /// arms the historical exception.
    ///
    /// | Value | Sum | Era |
    /// |---|---|---|
    /// | `10000009` | 10 | divisible by 10 — valid before and after 2023 |
    /// | `10000004` | 5 | divisible by 5 only — **valid only under the current rule** |
    /// | `10000078` | 19 | 19+1 = 20, seventh digit is 7 — valid via the exception |
    /// | `10000007` | 8 | divisible by neither, exception not armed — invalid |
    const LEGACY_ERA_ID: &str = "10000009";
    const CURRENT_ERA_ONLY_ID: &str = "10000004";
    const SEVENTH_DIGIT_EXCEPTION_ID: &str = "10000078";
    const INVALID_ID: &str = "10000007";

    /// The fixture table's arithmetic must be what the implementation computes,
    /// or the era tests below prove nothing about which rule is in force.
    #[test]
    fn the_business_id_fixtures_have_the_sums_the_table_claims() {
        for (value, sum) in [
            (LEGACY_ERA_ID, 10),
            (CURRENT_ERA_ONLY_ID, 5),
            (SEVENTH_DIGIT_EXCEPTION_ID, 19),
            (INVALID_ID, 8),
        ] {
            assert_eq!(business_id_sum(value), Some(sum), "{value}");
        }
    }

    /// **The second trap this ticket exists to avoid.** The divisor changed from
    /// 10 to 5 on 2023-04-01, and every mod-10-valid number is also mod-5-valid
    /// — so a legacy-only validator passes every test written against older
    /// numbers while missing every business registered since. `CURRENT_ERA_ONLY_ID`
    /// is the discriminating case: it fails mod-10 and passes mod-5.
    #[test]
    fn both_the_pre_and_post_2023_business_id_rules_are_honoured() {
        assert_eq!(business_id_era(LEGACY_ERA_ID), Some(BusinessIdEra::PreApril2023));
        assert_eq!(business_id_era(CURRENT_ERA_ONLY_ID), Some(BusinessIdEra::CurrentOnly));
        assert_eq!(
            business_id_era(SEVENTH_DIGIT_EXCEPTION_ID),
            Some(BusinessIdEra::PreApril2023),
        );
        assert_eq!(business_id_era(INVALID_ID), None);

        // And both eras reach the scanner, not just the validator.
        for value in [LEGACY_ERA_ID, CURRENT_ERA_ONLY_ID, SEVENTH_DIGIT_EXCEPTION_ID] {
            assert_eq!(
                categories(&format!("統一編號 {value}")),
                ["TAX_IDENTIFIER[zh-TW/business_id]"],
                "{value}"
            );
        }
        assert_eq!(categories(&format!("統一編號 {INVALID_ID}")), Vec::<String>::new());
    }

    /// The acceptance criteria's own example: no separator, flush against Han on
    /// the left. This is the case `\b\d{8}\b` cannot match.
    #[test]
    fn the_cjk_adjacent_business_id_from_the_acceptance_criteria_is_detected() {
        let text = "統編12345675";
        let found = scan(text);
        assert_eq!(found.len(), 1, "統編12345675 must be detected");
        assert_eq!(found[0].category().to_string(), "TAX_IDENTIFIER[zh-TW/business_id]");
        assert_eq!(&text[found[0].span().start()..found[0].span().end()], "12345675");
        // The label is adjacent, so the finding is corroborated.
        assert_eq!(found[0].confidence(), ConfidenceBand::Medium);
    }

    /// Eight digits inside a longer number are a fragment, not an identifier.
    ///
    /// With a checksum that admits one string in five this is not a nicety: an
    /// unbounded match would report a hit inside most long numeric literals.
    #[test]
    fn eight_digits_inside_a_longer_number_are_not_a_business_id() {
        for text in [
            format!("{LEGACY_ERA_ID}5"),
            format!("5{LEGACY_ERA_ID}"),
            // The decimal-point case: the fractional digits are part of one
            // number, which is why `.` is a fragment neighbour.
            format!("3.{LEGACY_ERA_ID}"),
            format!("{LEGACY_ERA_ID}.5"),
        ] {
            assert_eq!(categories(&text), Vec::<String>::new(), "{text}");
        }
    }

    /// A documented, deliberate residual — recorded rather than hidden.
    ///
    /// The checksum admits roughly one 8-digit string in five, and a compact
    /// `YYYYMMDD` date is an 8-digit string. `20260801` has weighted digit-sum
    /// 15, so it is reported. Nothing here is broken; the acceptance criteria
    /// require the checksum-valid match without a context keyword, and this is
    /// the price. The test exists so the behaviour is visible in the suite and
    /// so a future change to the trade-off has to touch it deliberately.
    #[test]
    fn a_bare_eight_digit_date_is_a_known_business_id_residual() {
        assert_eq!(business_id_sum("20260801"), Some(15));
        let found = scan("批次 20260801 已完成");
        assert_eq!(found.len(), 1, "the residual is real and this test documents it");
        assert_eq!(found[0].category().to_string(), "TAX_IDENTIFIER[zh-TW/business_id]");
        // Reported at the lowest bands precisely because of this, so it sorts
        // below anything that carries real harm.
        assert_eq!(found[0].confidence(), ConfidenceBand::Low);
        assert_eq!(found[0].severity(), Severity::Low);
        assert_eq!(found[0].status(), FindingStatus::Suspected);

        // A date written with separators is *not* an 8-digit run, so the common
        // written form does not trip it.
        assert_eq!(categories("批次 2026-08-01 已完成"), Vec::<String>::new());
    }

    /// Every written form of the same mobile number must be detected.
    ///
    /// All of these are the same synthetic number — an ascending digit run, so
    /// it is visibly constructed rather than observed — written the several ways
    /// a person writes it. A phone number has no checksum, so unlike the
    /// identity fixtures there is nothing to generate it from; the defence
    /// against writing down a real one is that the digits are sequential.
    ///
    /// The `+886` row is the one worth the test: the international form
    /// **drops the trunk zero**, so it is
    /// `+886912345678` and not `+8860912345678`, and an implementation that
    /// strips `+886` and expects a leading `0` misses every internationally
    /// written number.
    #[test]
    fn every_written_form_of_a_mobile_number_is_detected() {
        for text in [
            "手機 0912345678",
            "手機 0912-345-678",
            "手機 0912 345 678",
            "手機 +886912345678",
            "手機 +886-912-345-678",
        ] {
            assert_eq!(categories(text), ["PHONE_NUMBER[zh-TW/mobile]"], "{text}");
        }
    }

    /// A landline is recognised from the area-code gazetteer and that area's
    /// local-number length, in each written form.
    #[test]
    fn landline_forms_across_the_area_code_gazetteer_are_detected() {
        for text in [
            "電話 02-23456789",  // Taipei: area 2, 8 local digits
            "電話 (02)23456789", // parenthesised area code
            "電話 03-4567890",   // Taoyuan: area 3, 7 local digits
            "電話 037-456789",   // Miaoli: area 37, 6 local digits — longest match wins
            "電話 049-4567890",  // Nantou: area 49, 7 local digits
            "電話 089-456789",   // Taitung: area 89, 6 local digits
            "電話 0826-45678",   // Wuqiu: area 826, 5 local digits
            "電話 +886-2-23456789",
        ] {
            assert_eq!(categories(text), ["PHONE_NUMBER[zh-TW/landline]"], "{text}");
        }
    }

    /// The gazetteer is the whole constraint, so it has to reject: an area code
    /// that is not issued, and a local number of the wrong length for an area
    /// code that is.
    #[test]
    fn a_wrong_area_code_or_local_length_is_not_a_landline() {
        for text in [
            "電話 01-23456789", // `1` is not an area code
            "電話 09-2345678",  // `9` is mobile-only, not a landline area
            "電話 02-2345678",  // area 2 takes 8 local digits, not 7
            "電話 03-45678901", // area 3 takes 7, not 8
            "電話 037-4567890", // area 37 takes 6, not 7
        ] {
            assert_eq!(categories(text), Vec::<String>::new(), "{text}");
        }
    }

    /// An unseparated landline is a documented miss, not an accident.
    ///
    /// `0212345678` has the shape of a Taipei number and equally the shape of a
    /// ten-digit account or reference number. With no checksum to appeal to,
    /// accepting it would report a large class of ordinary numbers as personal
    /// data. Recorded so a future change to that trade-off is deliberate.
    #[test]
    fn an_unseparated_landline_is_a_known_miss() {
        assert_eq!(categories("電話 0223456789"), Vec::<String>::new());
        // The same digits with a separator are detected, so this is the
        // separator rule and not a broken area-code table.
        assert_eq!(categories("電話 02-23456789"), ["PHONE_NUMBER[zh-TW/landline]"]);
    }

    /// A phone number must be tried before the 統一編號, or the tax recognizer
    /// truncates a nine-digit national number into an eight-digit match.
    #[test]
    fn a_phone_number_is_not_reported_as_a_business_id() {
        let found = scan("手機 0912345678");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].category().to_string(), "PHONE_NUMBER[zh-TW/mobile]");
        assert_eq!(
            &"手機 0912345678"[found[0].span().start()..found[0].span().end()],
            "0912345678"
        );
    }

    /// A number glued to more digits is a fragment, in either direction.
    #[test]
    fn a_phone_number_inside_a_longer_digit_run_is_not_reported() {
        for text in ["手機 09123456789", "手機 10912345678", "手機 0912-345-6789"] {
            assert_eq!(categories(text), Vec::<String>::new(), "{text}");
        }
    }

    /// Phone confidence bands, and that a keyword raises them.
    #[test]
    fn phone_confidence_reflects_how_much_structure_there_is() {
        // A mobile's `09` prefix plus exact length is real structure.
        assert_eq!(scan("（0912345678）")[0].confidence(), ConfidenceBand::Medium);
        assert_eq!(scan("手機：0912345678")[0].confidence(), ConfidenceBand::High);
        // A landline rests on a gazetteer alone, which is weaker.
        assert_eq!(scan("（02-23456789）")[0].confidence(), ConfidenceBand::Low);
        assert_eq!(scan("電話：02-23456789")[0].confidence(), ConfidenceBand::Medium);
    }

    /// Every category this pack emits must parse back in the same build.
    ///
    /// The failure it guards is silent: a category missing from
    /// `CanonicalCategory::ALL` renders correctly, is emitted by this live
    /// recognizer, and only fails at the reader. Checked here against real
    /// scanner output rather than against the constant list, so a recognizer
    /// wired to a category nobody registered is caught.
    #[test]
    fn every_emitted_category_round_trips() {
        let corpus = [
            format!("身分證 {}", synthetic_id('A', "20000000")),
            format!("居留證 {}", synthetic_id('A', "80000000")),
            format!("居留證 {}", synthetic_legacy_arc('A', 'B', "0000000")),
            format!("統一編號 {LEGACY_ERA_ID}"),
            "手機 0912345678".to_string(),
            "電話 02-23456789".to_string(),
        ];
        let mut seen = 0usize;
        for text in &corpus {
            for f in scan(text) {
                let rendered = f.category().to_string();
                assert_eq!(
                    rendered.parse::<CanonicalCategory>(),
                    Ok(f.category()),
                    "{rendered} is emitted but does not parse in this build"
                );
                seen += 1;
            }
        }
        assert_eq!(seen, corpus.len(), "corpus produced too few findings to prove anything");
    }
}
