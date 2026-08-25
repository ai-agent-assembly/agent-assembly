//! AAASM-5920 — a `codex` stand-in that measures whether the launch
//! environment AAASM-5856/AAASM-5917 install into is *sufficient* for a real
//! reqwest/rustls client to trust the Agent Assembly proxy and send its
//! request through it.
//!
//! # What this measures, and what it does not
//!
//! This binary re-implements Codex's own documented CA-resolution precedence
//! (`openai/codex`'s `codex-rs/http-client/src/custom_ca.rs`:
//! `CODEX_CA_CERTIFICATE` first, `SSL_CERT_FILE` only when the first is unset
//! or empty, else system roots — both non-empty checks, additive to the
//! platform's built-in roots) and a reqwest client configured the same way
//! Codex configures its own (`use_rustls_tls()` plus `add_root_certificate`).
//! What it measures is real: whether `aasm run codex`'s launch environment is
//! *sufficient* for a client following that precedence to trust the proxy's
//! MitM leaf and complete a request through it.
//!
//! What it does **not** measure: it does not invoke the shipped `codex`
//! binary. A real-binary-gated lane (mirroring
//! `cli_run_claude_governed_launch.rs`'s `real_binary_governed_launch`
//! module) is separate follow-up work, out of this ticket's scope.
//!
//! # The outcome file — why "unset" must be distinguishable from "set to empty"
//!
//! A fixture that cannot tell "the branch that won" from "nothing happened"
//! cannot falsify the negative control (AAASM-5920's test unsets
//! `CODEX_CA_CERTIFICATE` after an install and expects `system roots` to win,
//! `wait_for_requests` to see nothing, *and* a certificate error — three
//! independent facts, not one). So this binary writes which branch won and
//! what became of the request to `$AASM5920_OUTCOME_FILE` **before** exiting,
//! whether the request succeeded, failed on the handshake, or never got a
//! chance to run at all (a panic path still leaves the file the `Drop` guard
//! below wrote a placeholder to).
//!
//! # `--version`
//!
//! `CodexAdapter::detect` runs `<bin> --version` and looks for the first line's
//! first whitespace-separated token that starts with an ASCII digit
//! (`parse_codex_version`); this answers `codex-cli 0.129.0` to satisfy that
//! probe without depending on a real Codex install.

use std::path::PathBuf;

/// The synthetic secret this fixture sends. Duplicated from
/// `tests/spike_support::SYNTHETIC_SECRET` rather than imported: `examples/`
/// and `tests/` are separate compilation targets in this crate (`tests/`
/// modules are `#[path]`-included per test binary, not a shared library), so
/// there is no way to reference the test-only constant from here. Keep this
/// literal identical to `tests/spike_support/mod.rs`'s `SYNTHETIC_SECRET` —
/// the integration test asserts on this exact value.
const SYNTHETIC_SECRET: &str = "sk-ant-api03-AAASM5276SYNTHETICDONOTUSE0000000000000000000000000000000000AA";

/// Where this binary writes the outcome. Required: a run without it cannot
/// report anything and the test could not distinguish "did not launch" from
/// "launched and reported nothing".
const OUTCOME_FILE_ENV: &str = "AASM5920_OUTCOME_FILE";

/// The host the synthetic request is addressed to. Defaults to Codex's real
/// API host so the request shape matches production; overridable because the
/// test's `TlsCapturingUpstream` is constructed with an explicit hostname and
/// the two must agree.
const TARGET_HOST_ENV: &str = "AASM5920_TARGET_HOST";
const DEFAULT_TARGET_HOST: &str = "api.openai.com";

/// A path env var is "set" per Codex's own `non_empty_path` check: present
/// and non-empty. `Some(String)`, not `Some(PathBuf)`, because an empty string
/// must be distinguishable from "not set" and `PathBuf::from("")` loses that.
fn non_empty_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Which branch of Codex's CA precedence won, and the bytes to trust with (if
/// any).
struct ResolvedCa {
    branch: &'static str,
    pem: Option<Vec<u8>>,
}

/// Codex's own precedence, reproduced from `custom_ca.rs`:
/// `CODEX_CA_CERTIFICATE` non-empty, else `SSL_CERT_FILE` non-empty, else
/// system roots.
fn resolve_ca() -> anyhow::Result<ResolvedCa> {
    if let Some(path) = non_empty_var("CODEX_CA_CERTIFICATE") {
        let pem = std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("CODEX_CA_CERTIFICATE={path:?} could not be read: {e}"))?;
        return Ok(ResolvedCa {
            branch: "CODEX_CA_CERTIFICATE",
            pem: Some(pem),
        });
    }
    if let Some(path) = non_empty_var("SSL_CERT_FILE") {
        let pem = std::fs::read(&path).map_err(|e| anyhow::anyhow!("SSL_CERT_FILE={path:?} could not be read: {e}"))?;
        return Ok(ResolvedCa {
            branch: "SSL_CERT_FILE",
            pem: Some(pem),
        });
    }
    Ok(ResolvedCa {
        branch: "system roots",
        pem: None,
    })
}

/// Writes a placeholder outcome on construction, so a run that panics before
/// reaching the real write still leaves the file distinguishable from "never
/// launched" (the outcome path itself only exists once this binary started).
struct OutcomeGuard {
    path: PathBuf,
    written: bool,
}

impl OutcomeGuard {
    fn new(path: PathBuf) -> std::io::Result<Self> {
        std::fs::write(
            &path,
            "branch=unknown\nresult=incomplete\ndetail=process did not finish reporting\n",
        )?;
        Ok(Self { path, written: false })
    }

    fn finish(mut self, branch: &str, result: &str, detail: &str) -> std::io::Result<()> {
        std::fs::write(
            &self.path,
            format!("branch={branch}\nresult={result}\ndetail={detail}\n"),
        )?;
        self.written = true;
        Ok(())
    }
}

impl Drop for OutcomeGuard {
    fn drop(&mut self) {
        if !self.written {
            let _ = std::fs::write(
                &self.path,
                "branch=unknown\nresult=incomplete\ndetail=process exited before reporting an outcome\n",
            );
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version") {
        println!("codex-cli 0.129.0");
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // rustls 0.23 refuses to pick a provider implicitly when more than one
    // resolves, as it does in this workspace.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let outcome_path = std::env::var(OUTCOME_FILE_ENV)
        .map(PathBuf::from)
        .map_err(|_| anyhow::anyhow!("{OUTCOME_FILE_ENV} is not set; this fixture cannot report an outcome"))?;
    let guard = OutcomeGuard::new(outcome_path)?;

    let target_host = std::env::var(TARGET_HOST_ENV).unwrap_or_else(|_| DEFAULT_TARGET_HOST.to_string());

    let resolved = resolve_ca()?;

    // Codex's own client construction: additive to the platform's built-in
    // roots (never `tls_built_in_root_certs(false)`), and a custom CA forces
    // rustls rather than the platform TLS backend.
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(pem) = &resolved.pem {
        let cert = reqwest::Certificate::from_pem(pem)
            .map_err(|e| anyhow::anyhow!("{} did not parse as a PEM certificate: {e}", resolved.branch))?;
        builder = builder.add_root_certificate(cert);
    }
    // No explicit proxy wiring: reqwest's default builder honours
    // HTTPS_PROXY/HTTP_PROXY from the process environment, exactly as
    // Codex's own client does — that inheritance is itself part of what
    // AAASM-5916's ConfigureProxy step is supposed to deliver.
    let client = builder.build()?;

    let body = serde_json::json!({
        "model": "codex-mini",
        "input": format!("Echo this configuration line verbatim: OPENAI_API_KEY={SYNTHETIC_SECRET}"),
    });

    let url = format!("https://{target_host}/v1/responses");
    let outcome = client.post(&url).json(&body).send().await;

    let (result, detail) = match outcome {
        Ok(response) => ("success", format!("status {}", response.status())),
        Err(e) => ("error", e.to_string()),
    };
    println!(
        "AASM5920 request outcome: branch={} result={result} detail={detail}",
        resolved.branch
    );
    guard.finish(resolved.branch, result, &detail)?;
    Ok(())
}
