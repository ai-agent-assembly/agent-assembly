//! AAASM-1577 / AAASM-1718 — Story-level TLS happy-path verification.
//!
//! Generates a fresh self-signed cert via rcgen, writes it to a tempdir,
//! boots `start_remote_with_handle` against a `RemoteModeConfig` whose
//! `tls` field points at the generated PEM, then probes `/healthz` over
//! HTTPS with a rustls-backed reqwest client.
//!
//! This covers the AAASM-1577 AC bullet *"TLS: valid cert/key → HTTPS"*
//! end-to-end (existence + PEM parse + handshake + body), in contrast to
//! ST-2's `remote_mode::tls::validate` unit tests which only cover the
//! pre-flight side of the contract.

use std::time::Duration;

use aa_core::config::{RemoteModeConfig, TlsConfig};
use axum_server::Handle;
use rcgen::{CertificateParams, KeyPair};
use tempfile::TempDir;
use time::{Duration as TimeDuration, OffsetDateTime};

/// Generate a self-signed cert valid for 365 days, write `cert.pem` and
/// `key.pem` into `dir`, and return a `TlsConfig` pointing at them.
fn fresh_self_signed_pair(dir: &TempDir) -> TlsConfig {
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.not_before = now - TimeDuration::days(1);
    params.not_after = now + TimeDuration::days(365);

    let key_pair = KeyPair::generate().expect("key_pair");
    let cert = params.self_signed(&key_pair).expect("self-signed");

    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");

    TlsConfig {
        cert_file: cert_path,
        key_file: key_path,
    }
}

#[tokio::test]
async fn https_handshake_serves_healthz_with_remote_mode_body() {
    // rustls 0.23 requires a process-wide CryptoProvider. With both
    // `aws-lc-rs` and `ring` present (the workspace pulls in both via
    // reqwest and axum-server), there is no automatic default, so the
    // first TLS API call panics unless one is installed explicitly.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let dir = TempDir::new().expect("tempdir");
    let tls = fresh_self_signed_pair(&dir);

    let cfg = RemoteModeConfig {
        listen_addr: "127.0.0.1:0".parse().expect("listen_addr"),
        tls: Some(tls),
        ..Default::default()
    };

    let handle = Handle::new();
    let probe_handle = handle.clone();
    let shutdown_handle = handle.clone();

    let server = tokio::spawn(async move { aa_gateway::remote_mode::start_remote_with_handle(&cfg, handle).await });

    let addr = probe_handle.listening().await.expect("server bound");

    // The rcgen-generated cert is self-signed and not in any trust
    // store, so the rustls-backed reqwest client must explicitly accept
    // an unverified chain for the handshake to land.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("reqwest builder");

    let body: serde_json::Value = client
        .get(format!("https://{addr}/healthz"))
        .send()
        .await
        .expect("https GET /healthz")
        .json()
        .await
        .expect("parse JSON body");

    assert_eq!(body["mode"], "remote", "mode label");
    assert_eq!(body["storage"], "memory", "storage label");

    shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    server.await.expect("server task").expect("server result");
}
