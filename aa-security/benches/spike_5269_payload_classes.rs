//! AAASM-5269 research benchmark: per-payload-class cost of the deterministic
//! fast path.
//!
//! The Spike needs a defensible answer to "what latency budget does the built-in
//! Rust scanner already consume?" before any provider architecture can claim a
//! deep-inspection budget. The pre-existing `scanner_bench` measures a single
//! ~1 MB blob, which is the *worst* case and says nothing about the payload
//! shapes that dominate real traffic (small tool calls) or about the shapes the
//! redesign must newly handle (mixed `zh-TW`/English).
//!
//! This bench is **research-only** and asserts nothing. It exists so the numbers
//! in `docs/src/research/AAASM-5269-*.md` are reproducible on any machine. It
//! deliberately covers, per the Spike's Section F:
//!
//! - the six representative payload classes (small / medium / large / mixed
//!   `zh-TW` / high-finding-density / no-finding),
//! - `scan` alone versus `scan` + `redact`, since only the redaction path pays
//!   the allocation and splice cost,
//! - a repeat scan of an identical payload, which bounds what a content-addressed
//!   scan cache could ever save.
//!
//! # Fixture safety
//!
//! Every credential-shaped string below is **synthetic**. AWS-documented example
//! identifiers are used where a realistic prefix is required; no value here is or
//! has ever been a live credential, and no personal data of any real person
//! appears. The `zh-TW` fixture is ordinary prose and deliberately contains no
//! Taiwan identifier of any kind — its purpose is to measure the cost of CJK
//! text, not to exercise a recognizer that does not exist yet.

use aa_security::CredentialScanner;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

/// Benign filler that resembles agent traffic (prose, code, SQL, logs, URLs)
/// without tripping any detector.
const BENIGN_BLOCK: &str = "The quick brown fox jumps over the lazy dog. \
     fn process(input: &str) -> Result<(), Error> { Ok(()) } \
     SELECT id, name FROM users WHERE active = true; \
     version = \"1.0.0\" edition = \"2021\" \
     cargo build --release --features std alloc serde \
     2026-04-27T12:00:00Z info=processing request_id=abc123 \
     https://docs.rust-lang.org/std/string/struct.String.html \
     error[E0382]: borrow of moved value type mismatch expected found ";

/// Traditional-Chinese filler with the half-/full-width punctuation mix and the
/// English tokens that real `zh-TW` agent traffic carries.
///
/// Each CJK codepoint is 3 bytes in UTF-8, and Chinese has no spaces, so this
/// block exercises the entropy pass's byte-length token window against input it
/// was never calibrated for — which is how the false-positive rate reported in
/// the Spike (§4.1) was found. Expect a non-zero finding count here even though
/// the block contains no secret.
const BENIGN_BLOCK_ZH_TW: &str = "使用者請求：請協助查詢訂單狀態，並將結果整理成報表。\
     系統回應：查詢完成，共 12 筆資料，處理時間 340 毫秒。\
     備註 (note): the retrieval step returned 12 rows from the orders table. \
     設定檔版本 version = \"1.0.0\"，環境 environment = production。\
     日誌：2026-04-27T12:00:00Z 資訊 處理中 request_id=abc123 狀態正常。";

/// Synthetic credential-shaped strings. None is a live secret.
const SYNTHETIC_SECRETS: &[&str] = &[
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "GITHUB_TOKEN=ghp_0000000000000000000000000000000000ab",
    "DATABASE_URL=postgres://user:notarealpassword@host:5432/mydb",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    "contact: nobody@example.invalid",
];

/// Builds a payload of roughly `target_bytes` from `filler`, then appends
/// `secret_count` synthetic credentials (cycling the fixture list).
fn build_payload(filler: &str, target_bytes: usize, secret_count: usize) -> String {
    let mut payload = String::with_capacity(target_bytes + secret_count * 80);
    while payload.len() < target_bytes {
        payload.push_str(filler);
    }
    for i in 0..secret_count {
        payload.push('\n');
        payload.push_str(SYNTHETIC_SECRETS[i % SYNTHETIC_SECRETS.len()]);
    }
    payload
}

/// The six representative payload classes from the Spike's Section F, as
/// `(label, payload)` pairs.
fn payload_classes() -> Vec<(&'static str, String)> {
    vec![
        // A single tool call carrying one credential — the dominant shape on the
        // synchronous pre-action enforcement path.
        ("small_tool_call_1_finding", build_payload(BENIGN_BLOCK, 256, 1)),
        // Same size, nothing to find: the case that must stay cheapest, because
        // it is the overwhelming majority of inspected actions.
        ("small_tool_call_clean", build_payload(BENIGN_BLOCK, 256, 0)),
        // A prompt plus conversation history.
        ("medium_prompt_history_32kb", build_payload(BENIGN_BLOCK, 32 * 1024, 3)),
        (
            "medium_prompt_history_32kb_clean",
            build_payload(BENIGN_BLOCK, 32 * 1024, 0),
        ),
        // A retrieved document — the RAG worst case.
        ("large_document_1mb", build_payload(BENIGN_BLOCK, 1024 * 1024, 5)),
        ("large_document_1mb_clean", build_payload(BENIGN_BLOCK, 1024 * 1024, 0)),
        // Mixed zh-TW / English: multi-byte codepoints throughout.
        ("mixed_zh_tw_32kb", build_payload(BENIGN_BLOCK_ZH_TW, 32 * 1024, 3)),
        (
            "mixed_zh_tw_32kb_clean",
            build_payload(BENIGN_BLOCK_ZH_TW, 32 * 1024, 0),
        ),
        // High finding density: 500 credentials appended to ~32 KB of filler,
        // giving a ~59 KB payload. Bounds the cost of the sort +
        // overlap-coalescing tail of `scan`, which grows with finding count on
        // top of the byte-linear base cost.
        ("high_density_500_findings", build_payload(BENIGN_BLOCK, 32 * 1024, 500)),
    ]
}

/// Cost of detection alone, per payload class.
fn bench_scan_by_payload_class(c: &mut Criterion) {
    let scanner = CredentialScanner::new();
    let mut group = c.benchmark_group("spike5269_scan");

    for (label, payload) in payload_classes() {
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &payload, |b, p| {
            b.iter(|| black_box(scanner.scan(black_box(p)).findings.len()));
        });
    }

    group.finish();
}

/// Cost of detection *plus* redaction — the path an enforcement point actually
/// pays whenever a finding exists, since `redact` re-allocates the payload and
/// splices every coalesced span.
fn bench_scan_and_redact(c: &mut Criterion) {
    let scanner = CredentialScanner::new();
    let mut group = c.benchmark_group("spike5269_scan_redact");

    let scanner_for_probe = CredentialScanner::new();
    for (label, payload) in payload_classes() {
        // Skip only payloads that genuinely produce no findings, since redaction
        // is a no-op there. Filtering on the `_clean` label instead would drop
        // `mixed_zh_tw_32kb_clean`, which is named "clean" because it contains no
        // planted secret yet still yields 87 findings (§4.1) — precisely the case
        // this benchmark exists to measure.
        if scanner_for_probe.scan(&payload).findings.is_empty() {
            continue;
        }
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &payload, |b, p| {
            b.iter(|| {
                let result = scanner.scan(black_box(p));
                black_box(result.redact(black_box(p)).len())
            });
        });
    }

    group.finish();
}

/// Upper bound on what a content-addressed scan cache could save: the same
/// payload scanned twice. The scanner holds no cache today, so both scans cost
/// the same — the delta a cache could recover is the whole second scan.
fn bench_repeat_scan(c: &mut Criterion) {
    let scanner = CredentialScanner::new();
    let payload = build_payload(BENIGN_BLOCK, 32 * 1024, 3);

    let mut group = c.benchmark_group("spike5269_repeat_scan");
    group.throughput(Throughput::Bytes(payload.len() as u64));

    group.bench_function("scan_twice_no_cache", |b| {
        b.iter(|| {
            let first = scanner.scan(black_box(&payload));
            let second = scanner.scan(black_box(&payload));
            black_box(first.findings.len() + second.findings.len())
        });
    });

    group.finish();
}

/// Scanner construction cost. Every enforcement layer builds one Aho-Corasick
/// automaton at startup; this is the per-process fixed cost a provider
/// architecture must not multiply.
fn bench_scanner_construction(c: &mut Criterion) {
    c.bench_function("spike5269_scanner_new", |b| {
        b.iter(|| black_box(CredentialScanner::new()));
    });
}

criterion_group!(
    benches,
    bench_scan_by_payload_class,
    bench_scan_and_redact,
    bench_repeat_scan,
    bench_scanner_construction
);
criterion_main!(benches);
