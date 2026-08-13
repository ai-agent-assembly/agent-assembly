//! AAASM-5269 research harness: the irreducible cost of moving a payload to an
//! out-of-process sensitive-data provider and back.
//!
//! This measures the **transport floor only**. The stand-in "provider" here does
//! no detection at all — it parses the request and replies with an empty finding
//! list. Any real provider's own compute adds to every number below. The point
//! is to establish what an out-of-process design costs *before* the provider does
//! any work, so the architecture comparison in the Spike report (§3.3) is not
//! confounded by provider quality.
//!
//! Measured separately:
//!
//! 1. JSON encode + decode of the payload (the serialisation tax),
//! 2. a length-prefixed round-trip over loopback TCP (syscall + copy tax),
//! 3. the same over a Unix domain socket — the cheaper local transport, and the
//!    one ADR 0032 §6 prescribes, since loopback TCP is reachable by every local
//!    user with no kernel-supplied peer identity,
//! 4. persistent connection versus a fresh connection per request.
//!
//! It is a `harness = false` bench target purely to reuse the bench profile's
//! optimisation settings; it asserts nothing and gates nothing.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p aa-security --bench spike_5269_transport_floor
//! ```
//!
//! Loopback on one host is the **best** case. A same-Pod sidecar adds a
//! network-namespace hop and a cluster-local shared service adds a real network
//! round-trip; neither can be stood in for by a measurement on a single machine.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Instant;

const SAMPLES: usize = 1000;

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn fmt_ns(n: u128) -> String {
    if n >= 1_000_000 {
        format!("{:.3} ms", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2} µs", n as f64 / 1_000.0)
    } else {
        format!("{n} ns")
    }
}

struct Stats {
    p50: u128,
    p95: u128,
    p99: u128,
}

fn stats(mut nanos: Vec<u128>) -> Stats {
    nanos.sort_unstable();
    Stats {
        p50: percentile(&nanos, 50.0),
        p95: percentile(&nanos, 95.0),
        p99: percentile(&nanos, 99.0),
    }
}

/// A framed request: 4-byte big-endian length, then the JSON body.
fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// The stand-in provider: parse the request JSON, reply with an empty finding
/// list. Deliberately does no detection.
fn serve_one<S: Read + Write>(mut sock: S) {
    while let Ok(body) = read_frame(&mut sock) {
        // Parse, so the deserialisation cost of the request is paid on the
        // provider side exactly as a real adapter would pay it.
        let _parsed: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => break,
        };
        let resp = br#"{"findings":[]}"#;
        if write_frame(&mut sock, resp).is_err() {
            break;
        }
    }
}

fn build_payload(target_bytes: usize) -> String {
    let block = "The quick brown fox jumps over the lazy dog. \
                 SELECT id, name FROM users WHERE active = true; \
                 2026-04-27T12:00:00Z info=processing request_id=abc123 ";
    let mut s = String::with_capacity(target_bytes + block.len());
    while s.len() < target_bytes {
        s.push_str(block);
    }
    s
}

fn main() {
    let sizes: Vec<(&str, usize)> = vec![
        ("small_tool_call_~450B", 450),
        ("medium_prompt_32KB", 32 * 1024),
        ("large_document_1MB", 1024 * 1024),
    ];

    println!("# AAASM-5269 — out-of-process provider transport floor");
    println!("# The 'provider' performs NO detection. These are lower bounds.");
    println!("# samples per case: {SAMPLES}\n");

    // ---- 1. Serialisation tax only (no I/O at all) ----
    println!("## 1. JSON encode + decode only (no syscall, no copy)\n");
    println!("| payload | p50 | p95 | p99 |");
    println!("|---|---:|---:|---:|");
    for (label, size) in &sizes {
        let payload = build_payload(*size);
        let mut nanos = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let t = Instant::now();
            let req = serde_json::json!({ "text": &payload, "locale": "zh-TW" });
            let bytes = serde_json::to_vec(&req).unwrap();
            let back: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            std::hint::black_box(back);
            nanos.push(t.elapsed().as_nanos());
        }
        let s = stats(nanos);
        println!(
            "| `{label}` | {} | {} | {} |",
            fmt_ns(s.p50),
            fmt_ns(s.p95),
            fmt_ns(s.p99)
        );
    }

    // ---- 2. Loopback TCP, persistent connection ----
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    s.set_nodelay(true).ok();
                    thread::spawn(move || serve_one(s));
                }
                Err(_) => break,
            }
        }
    });

    println!("\n## 2. Loopback TCP round-trip, persistent connection (incl. JSON)\n");
    println!("| payload | p50 | p95 | p99 |");
    println!("|---|---:|---:|---:|");
    for (label, size) in &sizes {
        let payload = build_payload(*size);
        let mut sock = TcpStream::connect(addr).unwrap();
        sock.set_nodelay(true).unwrap();

        // warm
        for _ in 0..50 {
            let req = serde_json::json!({ "text": &payload, "locale": "zh-TW" });
            write_frame(&mut sock, &serde_json::to_vec(&req).unwrap()).unwrap();
            read_frame(&mut sock).unwrap();
        }

        let mut nanos = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let t = Instant::now();
            let req = serde_json::json!({ "text": &payload, "locale": "zh-TW" });
            write_frame(&mut sock, &serde_json::to_vec(&req).unwrap()).unwrap();
            let resp = read_frame(&mut sock).unwrap();
            let _: serde_json::Value = serde_json::from_slice(&resp).unwrap();
            nanos.push(t.elapsed().as_nanos());
        }
        let s = stats(nanos);
        println!(
            "| `{label}` | {} | {} | {} |",
            fmt_ns(s.p50),
            fmt_ns(s.p95),
            fmt_ns(s.p99)
        );
    }

    // ---- 3. Loopback TCP, fresh connection per request ----
    println!("\n## 3. Loopback TCP round-trip, NEW connection per request\n");
    println!("| payload | p50 | p95 | p99 |");
    println!("|---|---:|---:|---:|");
    for (label, size) in &sizes {
        let payload = build_payload(*size);
        let mut nanos = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let t = Instant::now();
            let mut sock = TcpStream::connect(addr).unwrap();
            sock.set_nodelay(true).unwrap();
            let req = serde_json::json!({ "text": &payload, "locale": "zh-TW" });
            write_frame(&mut sock, &serde_json::to_vec(&req).unwrap()).unwrap();
            let resp = read_frame(&mut sock).unwrap();
            let _: serde_json::Value = serde_json::from_slice(&resp).unwrap();
            nanos.push(t.elapsed().as_nanos());
        }
        let s = stats(nanos);
        println!(
            "| `{label}` | {} | {} | {} |",
            fmt_ns(s.p50),
            fmt_ns(s.p95),
            fmt_ns(s.p99)
        );
    }

    // ---- 4. Unix domain socket, persistent connection ----
    let sock_path = std::env::temp_dir().join(format!("aaasm5269-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);
    let ul = UnixListener::bind(&sock_path).unwrap();
    thread::spawn(move || {
        for stream in ul.incoming() {
            match stream {
                Ok(s) => {
                    thread::spawn(move || serve_one(s));
                }
                Err(_) => break,
            }
        }
    });

    println!("\n## 4. Unix domain socket round-trip, persistent connection (incl. JSON)\n");
    println!("| payload | p50 | p95 | p99 |");
    println!("|---|---:|---:|---:|");
    for (label, size) in &sizes {
        let payload = build_payload(*size);
        let mut sock = UnixStream::connect(&sock_path).unwrap();
        for _ in 0..50 {
            let req = serde_json::json!({ "text": &payload, "locale": "zh-TW" });
            write_frame(&mut sock, &serde_json::to_vec(&req).unwrap()).unwrap();
            read_frame(&mut sock).unwrap();
        }
        let mut nanos = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let t = Instant::now();
            let req = serde_json::json!({ "text": &payload, "locale": "zh-TW" });
            write_frame(&mut sock, &serde_json::to_vec(&req).unwrap()).unwrap();
            let resp = read_frame(&mut sock).unwrap();
            let _: serde_json::Value = serde_json::from_slice(&resp).unwrap();
            nanos.push(t.elapsed().as_nanos());
        }
        let s = stats(nanos);
        println!(
            "| `{label}` | {} | {} | {} |",
            fmt_ns(s.p50),
            fmt_ns(s.p95),
            fmt_ns(s.p99)
        );
    }
    let _ = std::fs::remove_file(&sock_path);

    println!("\n_Note: loopback on one host is the BEST case. A same-Pod sidecar adds a");
    println!("network-namespace hop; a cluster-local shared service adds a real network");
    println!("round-trip (typically hundreds of µs to low ms), which no measurement on a");
    println!("single laptop can stand in for._");
}
