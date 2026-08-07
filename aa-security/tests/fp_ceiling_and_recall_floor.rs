//! The two thresholds AAASM-5368 was accepted on, made mechanical.
//!
//! AAASM-5368 recovered a band in which 99.8% of 23+17 character splits were
//! missed, at a cost of roughly one false positive per 25 MB of prose. The owner
//! accepted that trade **on the condition that the limit was locked by tests**.
//! It was not: the acceptance criteria stated a ceiling of 1 per 20 MB and a
//! recall floor of 99%, and nothing in the repository measured either. A stated
//! bound that nothing enforces is worse than no bound, because a green build
//! reads as evidence the bound holds.
//!
//! AAASM-5456 is that enforcement. Two assertions, each falsifiable:
//!
//! * the entropy pass produces **no findings** over this corpus of clean prose;
//! * it detects **at least 99%** of secrets split 23+17 across a separator.
//!
//! # The ceiling is tighter than the one AAASM-5368 was accepted on
//!
//! AAASM-5368 was accepted at roughly one false positive per 25 MB, and
//! AAASM-5456 locked a limit of one per 20 MB above it. AAASM-5502 then changed
//! the entropy bar and the measured rate went to **zero on this corpus**, at
//! which point the 1-per-20 MB limit permitted two findings that the pass was
//! not producing — enforcement lagging the measurement it exists to protect.
//!
//! AAASM-5451 closed that gap by pinning the ceiling to the measurement. The
//! consequence is deliberate and is the point: one new false positive here now
//! fails the build, so a precision-for-recall trade has to be argued rather
//! than absorbed.
//!
//! # Why the corpus is generated rather than committed
//!
//! Twenty megabytes of prose in git is a permanent repository cost for a number
//! a generator reproduces exactly. The corpus is therefore synthesised from a
//! fixed seed by a fixed algorithm: its identity is `CORPUS_NAME` plus the seed,
//! its size is asserted rather than assumed, and any drift in either shows up as
//! a failing test rather than as a silently different measurement.
//!
//! # Why the corpus is checked before it is trusted
//!
//! A corpus of plain Han text or short English words would satisfy the ceiling
//! even if the entropy pass were deleted outright — it would contain nothing the
//! pass could look at, so "zero findings" would prove nothing about the pass.
//! This is the failure mode the zh-TW pack documents at length, and this
//! programme has already shipped clean-prose fixtures whose text could not reach
//! the code they were meant to exercise.
//!
//! `the_corpus_reaches_the_entropy_window` therefore runs **first** in spirit:
//! it asserts the corpus carries a large population of ASCII runs long enough to
//! be scored, so that the ceiling assertion is measuring restraint rather than
//! absence.

use aa_security::CredentialScanner;

/// The corpus's identity. Together with [`CORPUS_SEED`] and this file's
/// generator, it names exactly one byte sequence.
const CORPUS_NAME: &str = "aaasm5456_mixed_en_zh_tw_prose_v1";

/// Fixed seed. Changing it changes the corpus, and therefore the measurement —
/// which is why it is a named constant rather than a literal buried in a call.
const CORPUS_SEED: u64 = 0x5456_0BE1_5EED_1234;

/// The corpus is generated until it is at least this large, so the ceiling is
/// expressed over a full 20 MB rather than extrapolated from a sample.
const CORPUS_MIN_BYTES: usize = 20 * 1024 * 1024;

/// Exact byte length of the corpus this seed produces.
///
/// Recorded, not derived at run time: the accepted false-positive rate is quoted
/// per byte over this corpus, so its size is part of the measurement's identity.
const CORPUS_BYTES: usize = 20_971_526;

/// Content digest of the corpus this seed produces.
///
/// Recorded for the same reason as [`CORPUS_BYTES`], and covering the case that
/// one cannot: text that changed without changing length.
const CORPUS_CHECKSUM: u64 = 0x6d5a_4588_7502_e932;

/// The accepted false-positive ceiling: **zero findings** over this corpus.
///
/// # Why this is a count and not a rate (AAASM-5451)
///
/// It used to be `1 per 20 * 1024 * 1024` bytes, which over [`CORPUS_BYTES`]
/// permitted **two** findings while the pass produced **none**. A rate is only
/// worth expressing when the denominator can vary; this one cannot — the corpus
/// is pinned by name, seed, length and checksum, so a rate over it is a count
/// wearing a disguise, and the disguise cost two findings of unenforced slack.
/// A regression could have introduced two false positives and left the build
/// green, which is precisely the "stated bound that nothing enforces" this file
/// exists to eliminate.
///
/// # Why zero rather than some smaller cushion
///
/// AAASM-5368 was accepted at roughly one false positive per 25 MB, and this
/// constant was set to 1-per-20 MB as headroom above that. AAASM-5502 then
/// changed the entropy bar and the measurement went to **zero on this corpus**.
/// Headroom above a measurement of zero is not headroom, it is unenforced slack:
/// any nonzero value here permits a regression nobody chose.
///
/// So this is a real tightening of the bar, deliberately: a single new false
/// positive on this corpus now fails the build. That is the intended cost. A
/// change that trades precision for recall is a product decision, and this
/// constant is where it has to be argued rather than absorbed. Raising it back
/// requires the same kind of owner decision that AAASM-5368 itself needed —
/// recorded on AAASM-5451.
///
/// Note the number this replaces was **not** measured on this corpus:
/// `aaasm5456_mixed_en_zh_tw_prose_v1` was created by AAASM-5456, after
/// AAASM-5368. There is no comparable prior figure over these bytes, and quoting
/// one would be the error this file warns about elsewhere — a rate without its
/// corpus is not a measurement.
const FP_CEILING_FINDINGS: usize = 0;

/// The accepted recall floor for the 23+17 split band, in percent.
const RECALL_FLOOR_PERCENT: u32 = 99;

/// Number of synthetic split secrets the recall measurement draws.
const RECALL_SAMPLE: usize = 1_000;

/// A deterministic 64-bit generator, so the corpus does not depend on the
/// standard library's hasher, the platform, or the crate graph.
///
/// SplitMix64 — chosen because it is a dozen lines, has no dependency, and is
/// stable across compilers and targets. Cryptographic quality is irrelevant
/// here; reproducibility is the entire requirement.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next() % items.len() as u64) as usize]
    }

    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }
}

/// English sentence fragments carrying the shapes real technical prose carries.
const EN_FRAGMENTS: &[&str] = &[
    "The gateway evaluated the request against the active policy document and recorded the decision.",
    "Operators can inspect the audit trail from the dashboard without elevated privileges.",
    "Each interception layer reports independently, so a gap in one does not silence the others.",
    "The budget tracker aggregates spend per team and refuses an action that would exceed the cap.",
    "Retries are bounded, and a request that exhausts them is refused rather than retried forever.",
];

/// Traditional-Chinese fragments, so the corpus is genuinely mixed-script and
/// the ASCII-run segmentation is exercised against multi-byte neighbours.
const ZH_TW_FRAGMENTS: &[&str] = &[
    "閘道器已依照目前生效的政策文件評估該請求，並將決策結果寫入稽核紀錄。",
    "維運人員可以直接從儀表板檢視稽核軌跡，不需要額外的特權帳號。",
    "三個攔截層各自獨立回報，因此其中一層失效並不會讓其他層一併靜默。",
    "預算追蹤器會依團隊彙總花費，並在動作將超出上限時直接拒絕。",
    "重試次數有上限，耗盡之後該請求會被拒絕，而不是無限期重試下去。",
];

/// Long ASCII runs that clean technical prose genuinely contains.
///
/// These are what make the corpus able to *reach* the entropy pass. Without
/// them the ceiling assertion would hold trivially — there would be no run long
/// enough to score, so zero findings would say nothing about the pass's
/// restraint. None of these is a credential.
const LONG_ASCII_RUNS: &[&str] = &[
    "/var/log/agent-assembly/gateway/policy-evaluation.log",
    "https://docs.agent-assembly.example/reference/policy-schema#matched-rule-ids",
    "getUserAccountPreferencesForTenantScope",
    "aa_gateway::storage::sensitive_data::projection_writer",
    "urn:agent-assembly:policy:document:billing-egress-restrictions",
    "application/vnd.agent-assembly.decision-event+json;version=3",
    "CREATE INDEX idx_sd_events_scope_ts ON sensitive_data_events",
];

/// Builds the corpus deterministically from [`CORPUS_SEED`].
///
/// Returns at least [`CORPUS_MIN_BYTES`]; the exact length is whatever the last
/// fragment pushed it to, and is asserted by the tests rather than assumed.
fn corpus() -> String {
    let mut rng = SplitMix64(CORPUS_SEED);
    let mut out = String::with_capacity(CORPUS_MIN_BYTES + 4096);

    while out.len() < CORPUS_MIN_BYTES {
        match rng.next() % 10 {
            0..=3 => out.push_str(rng.pick(EN_FRAGMENTS)),
            4..=6 => out.push_str(rng.pick(ZH_TW_FRAGMENTS)),
            7 => out.push_str(rng.pick(LONG_ASCII_RUNS)),
            8 => {
                // Numeric density: dates, versions, ports, amounts. Real prose
                // is full of these, and a corpus without them cannot exercise
                // the digit-adjacent paths at all.
                let a = rng.range(1, 9999);
                let b = rng.range(1, 999);
                out.push_str(&format!(
                    " 2026-0{}-1{} v{a}.{b}.0 port {} ",
                    rng.range(1, 9),
                    rng.range(1, 9),
                    rng.range(1024, 65535)
                ));
            }
            _ => out.push(' '),
        }
        out.push(' ');
    }
    out
}

/// The corpus must be able to reach the entropy pass at all.
///
/// A clean result over text the pass cannot look at is not restraint, it is
/// absence — and it would hold identically if the pass were deleted. This
/// asserts the corpus carries a large population of ASCII runs at or above the
/// 23-character floor the entropy pass scores, so
/// [`the_false_positive_rate_stays_under_the_accepted_ceiling`] is measuring
/// something.
#[test]
fn the_corpus_reaches_the_entropy_window() {
    let text = corpus();

    let long_runs = text
        .split(|c: char| !c.is_ascii_graphic())
        .filter(|run| run.len() >= 23)
        .count();

    assert!(
        long_runs >= 10_000,
        "{CORPUS_NAME} carries only {long_runs} ASCII runs of 23+ characters; a corpus \
         the entropy pass cannot look at would satisfy the ceiling even with the pass \
         deleted, so the ceiling assertion would prove nothing"
    );
}

/// The corpus's identity is its name, seed and byte size together.
///
/// Pinned so a change to the generator is a visible failure rather than a
/// silently different measurement reported under the same name.
#[test]
fn the_corpus_identity_is_pinned() {
    let text = corpus();

    assert!(
        text.len() >= CORPUS_MIN_BYTES,
        "{CORPUS_NAME} is {} bytes, below the {CORPUS_MIN_BYTES} the ceiling is expressed over",
        text.len()
    );

    // A corpus that drifted in content but not in length would still change the
    // measurement, so pin the content too — as an equality against a recorded
    // value, not merely as a non-degeneracy check. An earlier form of this test
    // computed the checksum and then asserted only `!= 0`, which every possible
    // corpus satisfies: it read like a content pin and enforced nothing. Editing
    // one word of one fragment left it green (AAASM-5502).
    let checksum = text
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
    println!(
        "corpus {CORPUS_NAME} seed {CORPUS_SEED:#x} bytes {} checksum {checksum:#x}",
        text.len()
    );

    assert_eq!(
        text.len(),
        CORPUS_BYTES,
        "{CORPUS_NAME} is {} bytes, not the recorded {CORPUS_BYTES}. The false-positive rate is \
         quoted per byte over this exact corpus, so a corpus that changed size is a different \
         measurement. Re-record both constants deliberately, or revert the fragment change.",
        text.len()
    );
    assert_eq!(
        checksum, CORPUS_CHECKSUM,
        "{CORPUS_NAME} content drifted: checksum {checksum:#x}, recorded {CORPUS_CHECKSUM:#x}. \
         Same length, different text, different measurement."
    );
}

/// **The accepted ceiling, enforced.**
///
/// Zero findings over this corpus. Breaching this fails the build.
#[test]
fn the_false_positive_rate_stays_under_the_accepted_ceiling() {
    let text = corpus();
    let scanner = CredentialScanner::new();
    let findings = scanner.scan(&text).findings.len();

    // `<=` and not `==`: the relation this test enforces is "at most the accepted
    // ceiling", and `FP_CEILING_FINDINGS` is a product constant that a future owner
    // decision may raise. Clippy sees only today's value of 0 and reads the
    // comparison as absurd; writing `==` instead would silently invert the test's
    // meaning the moment the ceiling moved, failing a build that produced *fewer*
    // false positives than allowed.
    #[allow(clippy::absurd_extreme_comparisons)]
    let within_ceiling = findings <= FP_CEILING_FINDINGS;

    assert!(
        within_ceiling,
        "{CORPUS_NAME}: {findings} false positives over {} bytes exceeds the accepted \
         ceiling of {FP_CEILING_FINDINGS}. The ceiling is a product decision recorded on \
         AAASM-5368 and tightened on AAASM-5451 — raising this constant to make the test \
         pass would silently move an accepted threshold. If a detection change genuinely \
         needs to spend a false positive here, that is a trade to argue on the ticket, \
         with the recall it buys measured.",
        text.len()
    );

    println!(
        "false positives: {findings} over {} bytes (ceiling {FP_CEILING_FINDINGS})",
        text.len()
    );
}

/// **The accepted recall floor, enforced.**
///
/// At least 99% of secrets split 23+17 across a separator must be detected —
/// the band AAASM-5368 recovered, in which 99.8% were previously missed.
#[test]
fn the_split_band_recall_stays_above_the_accepted_floor() {
    let scanner = CredentialScanner::new();
    let mut rng = SplitMix64(CORPUS_SEED ^ 0x2317_2317_2317_2317);
    let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .chars()
        .collect();

    let mut detected = 0usize;
    for _ in 0..RECALL_SAMPLE {
        let secret: String = (0..40).map(|_| *rng.pick(&alphabet)).collect();
        // 23 + 17, the band the ticket names, and **nothing else**. See
        // `wrapper_prose_can_raise_a_candidate_over_the_gate` for why no
        // surrounding words appear here.
        let payload = format!("{} {}", &secret[..23], &secret[23..]);
        if !scanner.scan(&payload).findings.is_empty() {
            detected += 1;
        }
    }

    let percent = (detected * 100 / RECALL_SAMPLE) as u32;
    assert!(
        percent >= RECALL_FLOOR_PERCENT,
        "23+17 split-band recall is {percent}% ({detected}/{RECALL_SAMPLE}), below the \
         accepted floor of {RECALL_FLOOR_PERCENT}%. This band is what AAASM-5368 bought \
         in exchange for the accepted false-positive rate; losing it while keeping the \
         rate is the worst of both."
    );

    println!("split-band recall: {percent}% ({detected}/{RECALL_SAMPLE})");
}

/// Why the recall measurement wraps its candidates in nothing at all.
///
/// AAASM-5502: the first version of the recall fixture presented each secret as
/// `config value: {secret} end`. Those two ordinary English words changed the
/// result. `scan_separated_base64_runs` joins a base64 run to a neighbour across
/// a single separator, and the *pair* clears [`ENTROPY_BITS_GATE`] even when the
/// secret alone does not — so a value genuinely below the gate was counted as
/// detected, and the measured recall was a property of the wrapper text rather
/// than of the detector.
///
/// This test pins that behaviour so the distortion cannot return unnoticed. It
/// asserts the difference is real: the same value is undetected alone and
/// detected beside prose.
///
/// It is deliberately **not** an assertion that the joining is wrong. Joining
/// across one separator is exactly what AAASM-5368 built, and a secret really can
/// sit next to a word. What is wrong is *measuring recall* through a fixture that
/// supplies the neighbour, which is why the recall test now supplies none.
#[test]
fn wrapper_prose_can_raise_a_candidate_over_the_gate() {
    let scanner = CredentialScanner::new();

    // A 40-character value whose own Shannon entropy sits just under the 4.5-bit
    // gate — the population AAASM-5502 is about. Repetition is what holds it
    // down; it is synthetic and is not a credential.
    let below_gate = "aAbBcCdDeEfFgGhHiIjJkKaAbBcCdDeEfFgGhHiI";

    assert!(
        scanner.scan(below_gate).findings.is_empty(),
        "fixture no longer sits below the gate; pick a value that does, or this          test proves nothing about contamination"
    );

    let wrapped = format!("config value: {below_gate} end");
    assert!(
        !scanner.scan(&wrapped).findings.is_empty(),
        "wrapper prose no longer lifts a below-gate candidate over the gate. If          that is an intended change to pass 5, update this test deliberately —          but the recall fixture must still present candidates in isolation,          because a fixture that supplies a neighbour measures the fixture."
    );
}
