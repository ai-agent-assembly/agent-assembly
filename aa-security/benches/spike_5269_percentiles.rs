//! AAASM-5269 research harness: true per-call latency percentiles for the
//! deterministic fast path.
//!
//! Criterion reports a mean and a median with confidence intervals, which is the
//! right tool for detecting a regression but the wrong one for answering the
//! question this Spike must answer: *what latency budget does a synchronous
//! pre-action enforcement point actually spend at the tail?* A p99 cannot be
//! read off a criterion report, and a provider budget derived from a mean would
//! understate the cost of the requests that matter.
//!
//! So this harness times each `scan` call individually and reports real order
//! statistics. It is a `harness = false` bench target purely to reuse the bench
//! profile's optimisation settings; it asserts nothing and gates nothing.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p aa-security --bench spike_5269_percentiles
//! ```
//!
//! Sample count is overridable via `AA_SPIKE_SAMPLES` (default 2000).
//!
//! # Fixture safety
//!
//! All credential-shaped strings are synthetic; see the note in
//! `spike_5269_payload_classes.rs`. No live secret and no real person's data
//! appears in this file.

use aa_security::CredentialScanner;
use std::hint::black_box;
use std::time::Instant;

const BENIGN_BLOCK: &str = "The quick brown fox jumps over the lazy dog. \
     fn process(input: &str) -> Result<(), Error> { Ok(()) } \
     SELECT id, name FROM users WHERE active = true; \
     version = \"1.0.0\" edition = \"2021\" \
     cargo build --release --features std alloc serde \
     2026-04-27T12:00:00Z info=processing request_id=abc123 \
     https://docs.rust-lang.org/std/string/struct.String.html \
     error[E0382]: borrow of moved value type mismatch expected found ";

const BENIGN_BLOCK_ZH_TW: &str = "使用者請求：請協助查詢訂單狀態，並將結果整理成報表。\
     系統回應：查詢完成，共 12 筆資料，處理時間 340 毫秒。\
     備註 (note): the retrieval step returned 12 rows from the orders table. \
     設定檔版本 version = \"1.0.0\"，環境 environment = production。\
     日誌：2026-04-27T12:00:00Z 資訊 處理中 request_id=abc123 狀態正常。";

const SYNTHETIC_SECRETS: &[&str] = &[
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "GITHUB_TOKEN=ghp_0000000000000000000000000000000000ab",
    "DATABASE_URL=postgres://user:notarealpassword@host:5432/mydb",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    "contact: nobody@example.invalid",
];

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

/// Nearest-rank percentile over an already-sorted slice.
///
/// Nearest-rank (rather than an interpolating definition) is deliberate: for a
/// latency budget we want an observed sample, not a synthesised value between
/// two samples.
fn percentile(sorted_nanos: &[u128], p: f64) -> u128 {
    if sorted_nanos.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted_nanos.len() as f64).ceil() as usize;
    sorted_nanos[rank.saturating_sub(1).min(sorted_nanos.len() - 1)]
}

struct Row {
    label: &'static str,
    bytes: usize,
    findings: usize,
    p50: u128,
    p95: u128,
    p99: u128,
    max: u128,
    mean: f64,
}

/// Times `op` `samples` times and returns the order statistics.
fn measure<F: FnMut()>(label: &'static str, bytes: usize, findings: usize, samples: usize, mut op: F) -> Row {
    // Warm caches and let the branch predictor settle before recording.
    for _ in 0..(samples / 10).max(50) {
        op();
    }

    let mut nanos = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        op();
        nanos.push(start.elapsed().as_nanos());
    }
    nanos.sort_unstable();

    let mean = nanos.iter().sum::<u128>() as f64 / nanos.len() as f64;
    Row {
        label,
        bytes,
        findings,
        p50: percentile(&nanos, 50.0),
        p95: percentile(&nanos, 95.0),
        p99: percentile(&nanos, 99.0),
        max: *nanos.last().unwrap(),
        mean,
    }
}

fn fmt_ns(n: u128) -> String {
    if n >= 1_000_000 {
        format!("{:.3} ms", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.3} µs", n as f64 / 1_000.0)
    } else {
        format!("{n} ns")
    }
}

fn main() {
    let samples: usize = std::env::var("AA_SPIKE_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);

    let scanner = CredentialScanner::new();

    let payloads: Vec<(&'static str, String)> = vec![
        ("small_tool_call_1_finding", build_payload(BENIGN_BLOCK, 256, 1)),
        ("small_tool_call_clean", build_payload(BENIGN_BLOCK, 256, 0)),
        ("medium_prompt_history_32kb", build_payload(BENIGN_BLOCK, 32 * 1024, 3)),
        (
            "medium_prompt_history_32kb_clean",
            build_payload(BENIGN_BLOCK, 32 * 1024, 0),
        ),
        ("large_document_1mb", build_payload(BENIGN_BLOCK, 1024 * 1024, 5)),
        ("large_document_1mb_clean", build_payload(BENIGN_BLOCK, 1024 * 1024, 0)),
        ("mixed_zh_tw_32kb", build_payload(BENIGN_BLOCK_ZH_TW, 32 * 1024, 3)),
        (
            "mixed_zh_tw_32kb_clean",
            build_payload(BENIGN_BLOCK_ZH_TW, 32 * 1024, 0),
        ),
        ("high_density_500_findings", build_payload(BENIGN_BLOCK, 32 * 1024, 500)),
    ];

    println!("# AAASM-5269 fast-path latency percentiles");
    println!("# samples per case: {samples}");
    println!("# rustc: {}", option_env!("RUSTC_VERSION").unwrap_or("see report"));
    println!();

    let mut scan_rows = Vec::new();
    for (label, payload) in &payloads {
        let findings = scanner.scan(payload).findings.len();
        scan_rows.push(measure(label, payload.len(), findings, samples, || {
            black_box(scanner.scan(black_box(payload)).findings.len());
        }));
    }

    let mut redact_rows = Vec::new();
    for (label, payload) in &payloads {
        let result = scanner.scan(payload);
        if result.findings.is_empty() {
            continue;
        }
        let findings = result.findings.len();
        redact_rows.push(measure(label, payload.len(), findings, samples, || {
            let r = scanner.scan(black_box(payload));
            black_box(r.redact(black_box(payload)).len());
        }));
    }

    let print_table = |title: &str, rows: &[Row]| {
        println!("## {title}\n");
        println!("| case | bytes | findings | p50 | p95 | p99 | max | mean |");
        println!("|---|---:|---:|---:|---:|---:|---:|---:|");
        for r in rows {
            println!(
                "| `{}` | {} | {} | {} | {} | {} | {} | {} |",
                r.label,
                r.bytes,
                r.findings,
                fmt_ns(r.p50),
                fmt_ns(r.p95),
                fmt_ns(r.p99),
                fmt_ns(r.max),
                fmt_ns(r.mean as u128),
            );
        }
        println!();
    };

    print_table("scan only", &scan_rows);
    print_table("scan + redact", &redact_rows);

    // Scanner construction is a per-process fixed cost, not a per-request one;
    // report it separately so it is never folded into a per-request budget.
    let ctor = measure("CredentialScanner::new", 0, 0, samples.min(500), || {
        black_box(CredentialScanner::new());
    });
    println!("## scanner construction (per process, not per request)\n");
    println!("| case | p50 | p95 | p99 | max |");
    println!("|---|---:|---:|---:|---:|");
    println!(
        "| `{}` | {} | {} | {} | {} |",
        ctor.label,
        fmt_ns(ctor.p50),
        fmt_ns(ctor.p95),
        fmt_ns(ctor.p99),
        fmt_ns(ctor.max)
    );
}
