//! AAASM-6262 (J84) -- a governed-agent stand-in for the credential-broker
//! end-to-end test (`cli_run_credential_broker_e2e.rs`).
//!
//! It is NOT a coding agent and no result of running it is evidence about one.
//! It is a plain, unsigned Rust process (so a same-uid debugger can attach to it,
//! which a SIP-protected `/bin/sh` or `/usr/bin/curl` would refuse) that does the
//! one thing the journey needs from an agent: call a credential-requiring HTTPS
//! API through the governed proxy **without holding the credential**, twice,
//! with the test revoking the credential in between.
//!
//! Protocol, all through files in `$1` (a directory the test owns):
//!
//! 1. write `self.txt` (its own pid, argv and environment, for the test to scan),
//! 2. call the API, write `call1.status` / `call1.body`, then write `ready`,
//! 3. stay alive (holding whatever it holds in memory) until `go` appears,
//! 4. call the API again, write `call2.status` / `call2.body`, exit 0.
//!
//! The agent's own request carries a deliberately wrong credential header. A
//! brokered launch must replace it, so a 200 can only mean the proxy injected the
//! real one, and a revoked credential must be refused rather than forwarded.
//!
//! `$2` is the CA certificate (public) the launch trusts; the proxy to use comes
//! from `HTTPS_PROXY`, exactly as for any governed tool.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const TARGET_HOST: &str = "api.anthropic.com";

fn write(dir: &Path, name: &str, contents: &str) -> anyhow::Result<()> {
    // Write-then-rename so the test never reads a half-written file.
    let tmp = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, dir.join(name))?;
    Ok(())
}

async fn call(proxy: &str, config: Arc<ClientConfig>) -> Result<(String, String), String> {
    let mut tcp = TcpStream::connect(proxy.trim_start_matches("http://").trim_end_matches('/'))
        .await
        .map_err(|e| format!("proxy connect: {e}"))?;
    let target = format!("{TARGET_HOST}:443");
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .map_err(|e| format!("CONNECT write: {e}"))?;
    let mut reader = BufReader::new(tcp);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .map_err(|e| format!("CONNECT read: {e}"))?;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).await.unwrap_or(0) == 0 || h.trim().is_empty() {
            break;
        }
    }
    if !status_line.contains("200") {
        return Err(format!("tunnel refused: {}", status_line.trim()));
    }
    let name = ServerName::try_from(TARGET_HOST.to_owned()).map_err(|e| e.to_string())?;
    let mut tls = TlsConnector::from(config)
        .connect(name, reader.into_inner())
        .await
        .map_err(|e| format!("tls: {e}"))?;
    let body = r#"{"model":"probe","messages":[]}"#;
    let req = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {TARGET_HOST}\r\nx-api-key: agent-holds-no-credential\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("request write: {e}"))?;
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut raw)).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("none")
        .to_owned();
    let response_body = text.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned();
    Ok((status, response_body))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version") {
        println!("j84-probe-agent 0.0.0");
        return Ok(());
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = PathBuf::from(args.get(1).ok_or_else(|| anyhow::anyhow!("usage: <dir> <cacert>"))?);
    let cacert = args.get(2).ok_or_else(|| anyhow::anyhow!("usage: <dir> <cacert>"))?;

    let mut own = format!("pid={}\n===ARGV===\n", std::process::id());
    for a in &args {
        own.push_str(a);
        own.push('\n');
    }
    own.push_str("===ENV===\n");
    for (k, v) in std::env::vars() {
        own.push_str(&format!("{k}={v}\n"));
    }
    write(&dir, "self.txt", &own)?;

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(cacert)? {
        roots.add(cert?)?;
    }
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy = std::env::var("HTTPS_PROXY").map_err(|_| anyhow::anyhow!("HTTPS_PROXY is not set"))?;

    for (n, gate) in [(1, None), (2, Some("go"))] {
        if let Some(gate) = gate {
            write(&dir, "ready", "1")?;
            let deadline = Instant::now() + Duration::from_secs(120);
            while !dir.join(gate).exists() {
                anyhow::ensure!(Instant::now() < deadline, "never told to continue");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        match call(&proxy, config.clone()).await {
            Ok((status, body)) => {
                write(&dir, &format!("call{n}.body"), &body)?;
                write(&dir, &format!("call{n}.status"), &status)?;
            }
            Err(e) => {
                write(&dir, &format!("call{n}.body"), &e)?;
                write(&dir, &format!("call{n}.status"), "error")?;
            }
        }
    }
    Ok(())
}
