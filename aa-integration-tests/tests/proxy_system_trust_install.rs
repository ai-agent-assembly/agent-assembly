//! AAASM-5978, test categories A/C/D: `aa_proxy::run()`'s macOS System
//! Keychain step, driven through the **real spawned `aa-proxy` binary** (not
//! `ProxyServer` in-process — the keychain logic lives only in `run()`,
//! `aa-proxy/src/lib.rs`, so nothing short of the real binary can exercise
//! it). Category B (skipping system trust never means skipping validation)
//! is only constructible with an untrusting client and lives in
//! `aa-proxy/tests/system_trust_install_does_not_weaken_validation.rs`
//! instead, alongside `ProxyServer`.
//!
//! Mechanism: a PATH-shimmed `security` recorder. `aa-proxy/src/tls/keychain.rs`
//! is this proxy's **only** call site for the `security` CLI
//! (`Command::new("security")`, resolved through `PATH`) — a shim script
//! named `security`, prepended to `PATH`, is therefore a complete record of
//! every invocation the real binary makes, with nothing mocked and the real
//! System Keychain never touched.
//!
//! `#[cfg(target_os = "macos")]` for the whole file: the Keychain block this
//! ticket gates does not exist on other platforms (`aa-proxy/src/lib.rs`'s
//! `#[cfg(target_os = "macos")]`), so `AA_PROXY_SYSTEM_TRUST_INSTALL` being
//! unset there would make zero `security` calls regardless — these tests
//! would either be vacuous or fail to compile the claim they're making.
#![cfg(target_os = "macos")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ── binary resolution (mirrors aa-integration-tests/tests/cli_proxy.rs) ─────

fn cargo_target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("aa-integration-tests always has a workspace-root parent")
                .join("target")
        })
}

fn aa_proxy_bin() -> Option<PathBuf> {
    let target_dir = cargo_target_dir();
    let debug_bin = target_dir.join("debug").join("aa-proxy");
    if debug_bin.exists() {
        return Some(debug_bin);
    }
    let release_bin = target_dir.join("release").join("aa-proxy");
    if release_bin.exists() {
        return Some(release_bin);
    }
    None
}

fn ensure_aa_proxy_built() -> PathBuf {
    if let Some(bin) = aa_proxy_bin() {
        return bin;
    }
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "aa-proxy"])
        .env("CARGO_TARGET_DIR", cargo_target_dir())
        .status()
        .expect("cargo build -p aa-proxy");
    assert!(status.success(), "cargo build -p aa-proxy failed");
    aa_proxy_bin().expect("aa-proxy binary missing after build")
}

// ── the `security` shim ──────────────────────────────────────────────────

/// Write a no-op `security` shim into `dir` that appends its args to `log`
/// and always exits 0. Real `aa-proxy/src/tls/keychain.rs` calls are the
/// only thing that can ever invoke it in this test — nothing else on the
/// spawned child's `PATH` is named `security` before the real one.
fn write_security_shim(dir: &Path, log: &Path) {
    let script = format!("#!/bin/sh\necho \"$@\" >> {log:?}\nexit 0\n");
    std::fs::write(dir.join("security"), script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("security"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn prefixed_path(dir: &Path) -> std::ffi::OsString {
    let existing = std::env::var_os("PATH").unwrap_or_default();
    let mut parts = vec![dir.to_path_buf()];
    parts.extend(std::env::split_paths(&existing));
    std::env::join_paths(parts).unwrap()
}

// ── spawn + readiness ────────────────────────────────────────────────────

struct SpawnedProxy {
    child: Child,
    addr: SocketAddr,
    ca_dir: PathBuf,
    shim_log: PathBuf,
}

impl Drop for SpawnedProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the real `aa-proxy` binary with the `security` shim on `PATH` and
/// `system_trust_install` (`None` = unset/default, `Some("auto"|"never")` =
/// explicit) — waits for the ready file, matching `wait_for_ready_file`'s
/// own format (`aa-cli/src/commands/proxy/readiness.rs`): `SocketAddr\nPID\n`.
fn spawn_real_proxy(system_trust_install: Option<&str>) -> SpawnedProxy {
    let bin = ensure_aa_proxy_built();
    let work = tempfile::tempdir().unwrap().keep();
    let shim_dir = work.join("shim-bin");
    std::fs::create_dir_all(&shim_dir).unwrap();
    let shim_log = work.join("security-calls.log");
    write_security_shim(&shim_dir, &shim_log);

    let ca_dir = work.join("ca");
    let ready_file = work.join("ready");

    let mut cmd = Command::new(&bin);
    cmd.env("AA_PROXY_ADDR", "127.0.0.1:0");
    cmd.env("AA_PROXY_READY_FILE", &ready_file);
    cmd.env("AA_CA_DIR", &ca_dir);
    cmd.env("PATH", prefixed_path(&shim_dir));
    if let Some(v) = system_trust_install {
        cmd.env("AA_PROXY_SYSTEM_TRUST_INSTALL", v);
    } else {
        cmd.env_remove("AA_PROXY_SYSTEM_TRUST_INSTALL");
    }
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    let child = cmd.spawn().expect("spawn real aa-proxy");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let addr = loop {
        if let Ok(contents) = std::fs::read_to_string(&ready_file) {
            if let Some(line) = contents.lines().next() {
                if let Ok(addr) = line.parse::<SocketAddr>() {
                    break addr;
                }
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "aa-proxy did not report readiness within 10s"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    SpawnedProxy {
        child,
        addr,
        ca_dir,
        shim_log,
    }
}

fn shim_log_calls(shim_log: &Path) -> Vec<String> {
    std::fs::read_to_string(shim_log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

// ── real client TLS handshake against the spawned binary ────────────────

fn trusting_client_config(ca_pem_path: &Path) -> ClientConfig {
    let pem_bytes = std::fs::read(ca_pem_path).unwrap();
    let pem = x509_parser::pem::Pem::iter_from_buffer(&pem_bytes)
        .next()
        .expect("a PEM block")
        .expect("a valid PEM block");
    let mut roots = RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(pem.contents))
        .unwrap();
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// CONNECT to a built-in LLM host and complete the client TLS handshake —
/// `aa-proxy` sends `200 Connection Established` and accepts the client's
/// TLS handshake before ever dialing upstream (`handle_llm_mitm` takes an
/// already client-TLS-terminated stream), so this proves real cert trust
/// without needing any upstream to actually be reachable.
async fn real_handshake_completes(proxy: SocketAddr, ca_pem_path: &Path) -> bool {
    let host = "api.anthropic.com";
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let connect = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    stream.write_all(connect.as_bytes()).await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("200"), "tunnel not established: {line}");
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await.unwrap();
        if header.trim().is_empty() {
            break;
        }
    }

    let connector = TlsConnector::from(Arc::new(trusting_client_config(ca_pem_path)));
    let server_name = rustls::pki_types::ServerName::try_from(host).unwrap();
    connector.connect(server_name, reader.into_inner()).await.is_ok()
}

// ── tests ─────────────────────────────────────────────────────────────────

/// Category A + D: `AA_PROXY_SYSTEM_TRUST_INSTALL=never` — zero `security`
/// calls (D: no GUI dialog is even possible, since its sole trigger,
/// `add-trusted-cert`, is one of the calls proven absent here) and a real
/// client handshake still succeeds against the same live proxy.
#[tokio::test]
async fn never_makes_zero_security_calls_and_mitm_still_works() {
    install_crypto();
    let proxy = spawn_real_proxy(Some("never"));

    assert!(
        real_handshake_completes(proxy.addr, &proxy.ca_dir.join("ca-cert.pem")).await,
        "MitM must work using only this launch's own trust, with no System Keychain involvement"
    );
    assert!(
        shim_log_calls(&proxy.shim_log).is_empty(),
        "AA_PROXY_SYSTEM_TRUST_INSTALL=never must make ZERO `security` CLI invocations, got: {:?}",
        shim_log_calls(&proxy.shim_log)
    );
}

/// Category C: the positive control that makes the test above non-vacuous,
/// and the standalone-path regression guard — unset (today's default
/// behaviour, unchanged) makes at least the `find-certificate` lookup.
#[tokio::test]
async fn unset_makes_a_real_security_call() {
    install_crypto();
    let proxy = spawn_real_proxy(None);
    // Give the startup path a moment to reach the keychain check before the
    // process would otherwise be considered ready-but-uninspected.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let calls = shim_log_calls(&proxy.shim_log);
    assert!(
        calls.iter().any(|c| c.contains("find-certificate")),
        "unset (Auto) must still perform the System Keychain lookup — today's unchanged \
         behaviour for standalone/manual proxy use — got: {calls:?}"
    );
}
