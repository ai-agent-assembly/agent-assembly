use aa_security::CredentialScanner;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

/// Generates a ~1 MB synthetic payload that contains realistic benign text
/// interspersed with a small number of credential patterns.
fn make_payload() -> String {
    // ~1000-byte repeating block of benign text
    let block = "The quick brown fox jumps over the lazy dog. \
                 fn process(input: &str) -> Result<(), Error> { Ok(()) } \
                 SELECT id, name FROM users WHERE active = true; \
                 version = \"1.0.0\" edition = \"2021\" \
                 cargo build --release --features std alloc serde \
                 2026-04-27T12:00:00Z info=processing request_id=abc123 \
                 https://docs.rust-lang.org/std/string/struct.String.html \
                 error[E0382]: borrow of moved value type mismatch expected found \
                 ";

    // Fill to ~950 KB of benign text
    let mut payload = String::with_capacity(1024 * 1024);
    while payload.len() < 950_000 {
        payload.push_str(block);
    }

    // Sprinkle a handful of real credential patterns into the payload
    payload.push_str("\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    payload.push_str("GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n");
    payload.push_str("DATABASE_URL=postgres://user:secret@host:5432/mydb\n");
    payload.push_str("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n");
    payload.push_str("card: 4532015112830366\n");

    payload
}

fn bench_scan_1mb(c: &mut Criterion) {
    let scanner = CredentialScanner::new();
    let payload = make_payload();

    let mut group = c.benchmark_group("scanner");
    group.throughput(Throughput::Bytes(payload.len() as u64));

    group.bench_function("scan_1mb_payload", |b| {
        b.iter(|| {
            let result = scanner.scan(&payload);
            // Prevent the compiler from optimising away the scan
            black_box(result.findings.len())
        });
    });

    group.finish();
}

criterion_group!(benches, bench_scan_1mb);
criterion_main!(benches);
