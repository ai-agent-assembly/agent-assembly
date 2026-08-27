// Shared across several `cli_run*` test binaries; not every binary uses every
// helper, so dead-code warnings here are noise.
#![allow(dead_code)]

//! A real, verified `aa-proxy` for tests whose subject is what `aasm run` does
//! *after* it has established one (AAASM-5323).
//!
//! # Why a real proxy and not a fixture
//!
//! Since AAASM-5323 `aasm run` refuses to launch unless it can resolve a proxy
//! endpoint it can vouch for: a state file only this user could have written,
//! naming a live process that is still the `aa-proxy` that was recorded, bound
//! to a loopback address that accepts connections. Every one of those facts is
//! read from the kernel, so a hand-written state file cannot satisfy them —
//! which is the whole point of the design, and the reason this harness stands up
//! the genuine thing instead.
//!
//! Standing it up through `aasm proxy start` rather than by spawning `aa-proxy`
//! directly is also deliberate: the record under test is the one the production
//! writer produces, so a change to the format moves this harness with it rather
//! than leaving it asserting against a format nothing writes.

use std::path::{Path, PathBuf};

/// The workspace `target/` directory, honoring `CARGO_TARGET_DIR`.
pub fn cargo_target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("aa-integration-tests always has a workspace-root parent")
                .join("target")
        })
}

/// Absolute path to a **freshly built** binary from this workspace.
///
/// `aa-integration-tests` depends on neither `aa-cli` nor the `aa-proxy` binary
/// target, so `cargo nextest run -p aa-integration-tests` builds neither: a
/// stale artefact left in `target/` by an earlier build would be measured
/// instead of the tree. For a test whose entire subject is `aa-cli` behaviour
/// that is a false *pass* — it makes the suite silently unable to notice a
/// defect coming back — so the build is unconditional rather than a fallback for
/// a missing file. It is a no-op when the binary is current.
///
/// Memoised per test binary rather than per test: the build must happen after
/// the tree is what it is, which one build at the start of the run satisfies,
/// and ten tests each taking cargo's package lock in turn does not make the
/// result any fresher — it only serialises the suite behind it.
fn build_binary(package: &str, bin: &str) -> PathBuf {
    build_target(package, "--bin", bin, cargo_target_dir().join("debug").join(bin))
}

/// As [`build_binary`], for a cargo **example** target.
///
/// Examples land in `target/debug/examples/`, so the output path cannot be
/// derived from the target kind alone and is passed in.
fn build_example(package: &str, example: &str) -> PathBuf {
    build_target(
        package,
        "--example",
        example,
        cargo_target_dir().join("debug").join("examples").join(example),
    )
}

/// Build one cargo target and return the artefact path, memoised per test
/// binary. See [`build_binary`] for why the build is unconditional.
fn build_target(package: &str, kind: &str, name: &str, output: PathBuf) -> PathBuf {
    static BUILT: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, PathBuf>>> =
        std::sync::OnceLock::new();
    let cache = BUILT.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = format!("{kind} {name}");
    if let Some(path) = cache.get(&key) {
        return path.clone();
    }

    // Built from the manifest dir, which is what lets the runs themselves stay
    // hermetic in a temp working directory (cargo cannot find a manifest from
    // there, so `cargo run`-style resolution is not an option).
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "--quiet", "-p", package, kind, name])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke cargo to build {name}: {e}"));
    assert!(status.success(), "`cargo build -p {package} {kind} {name}` failed");

    assert!(
        output.is_file(),
        "no `{name}` artefact at {} even after building it. Skipping instead would leave the \
         behaviour unmeasured.",
        output.display(),
    );
    cache.insert(key, output.clone());
    output
}

/// Absolute path to a freshly built `aasm`.
///
/// `AASM_BIN_PATH` is the escape hatch for callers (CI) that built the binary
/// themselves and own its freshness. The default picks the debug profile
/// unconditionally; a `--release` run wanting the release binary must point
/// `AASM_BIN_PATH` at it.
pub fn aasm_binary() -> PathBuf {
    explicit_binary("AASM_BIN_PATH").unwrap_or_else(|| build_binary("aa-cli", "aasm"))
}

/// Absolute path to a freshly built `aa-proxy`. `AA_PROXY_BIN_PATH` is the same
/// escape hatch as [`aasm_binary`]'s.
pub fn aa_proxy_binary() -> PathBuf {
    explicit_binary("AA_PROXY_BIN_PATH").unwrap_or_else(|| build_binary("aa-proxy", "aa-proxy"))
}

/// Absolute path to a freshly built `examples/proxy_with_mock_upstream` — the
/// shipped `ProxyServer` in a process, with its upstream dial redirected.
///
/// No `*_BIN_PATH` escape hatch: this artefact only ever exists because the
/// running tree built it, so an externally supplied one could not be current by
/// construction.
pub fn proxy_with_mock_upstream_binary() -> PathBuf {
    build_example("aa-integration-tests", "proxy_with_mock_upstream")
}

/// Absolute path to a freshly built `examples/codex_tls_client` — the `codex`
/// stand-in AAASM-5920 launches through `aasm run codex` to measure the
/// CA-trust launch environment. See [`proxy_with_mock_upstream_binary`] for
/// why there is no `*_BIN_PATH` escape hatch.
pub fn codex_tls_client_binary() -> PathBuf {
    build_example("aa-integration-tests", "codex_tls_client")
}

fn explicit_binary(var: &str) -> Option<PathBuf> {
    let explicit = std::env::var_os(var)?;
    Some(std::fs::canonicalize(&explicit).unwrap_or_else(|e| panic!("{var}={explicit:?} could not be resolved: {e}")))
}

/// A running `aa-proxy` that `aasm run` will accept, plus the isolated
/// `AA_DATA_DIR` its state record lives in.
pub struct TrustedProxy {
    _tmp: tempfile::TempDir,
    aasm: PathBuf,
    data_dir: PathBuf,
    proxy_bin_dir: PathBuf,
    addr: String,
    log_path: PathBuf,
    stopped: bool,
}

impl TrustedProxy {
    /// Start a proxy on a free loopback port and wait for it to bind.
    pub fn start() -> anyhow::Result<Self> {
        let aasm = aasm_binary();
        let proxy_bin = aa_proxy_binary();
        let proxy_bin_dir = proxy_bin
            .parent()
            .expect("the built binary has a parent directory")
            .to_path_buf();

        let tmp = tempfile::tempdir()?;
        let root = tmp.path().to_path_buf();
        let data_dir = root.join("data");
        std::fs::create_dir_all(&data_dir)?;

        // Bind-and-release to pick a port nothing else holds. `aasm proxy start`
        // polls the port and fails if the proxy did not bind, so a lost race
        // surfaces as a failed start here rather than as a confusing refusal
        // later.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.local_addr()?.port()
        };
        let addr = format!("127.0.0.1:{port}");
        let log_path = root.join("proxy.log");

        let out = std::process::Command::new(&aasm)
            .env("AA_DATA_DIR", &data_dir)
            .env("PATH", prefixed_path(&proxy_bin_dir)?)
            .args([
                "proxy",
                "start",
                "--listen",
                &addr,
                "--ca-dir",
                root.join("ca").to_str().expect("temp path is utf-8"),
                "--log-file",
                log_path.to_str().expect("temp path is utf-8"),
            ])
            .output()?;
        anyhow::ensure!(
            out.status.success(),
            "`aasm proxy start` failed — without a running proxy every `aasm run` in this test \
             refuses, and the refusal would be mistaken for the behaviour under test\n\
             stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        Ok(Self {
            _tmp: tmp,
            aasm,
            data_dir,
            proxy_bin_dir,
            addr,
            log_path,
            stopped: false,
        })
    }

    /// A trusted proxy whose upstream dial lands on `upstream` instead of the
    /// real provider, sharing `ca_dir` with the caller and reading integration
    /// state from `state_dir`.
    ///
    /// # Why this is a second constructor rather than a flag on the first
    ///
    /// The shipped `aa-proxy` binary cannot be pointed at a loopback mock —
    /// `ProxyConfig::from_env` leaves `upstream_override` at `None` and the SSRF
    /// guard refuses private dial targets, both deliberately and neither
    /// reachable from the environment. So the process started here is
    /// `examples/proxy_with_mock_upstream`: the same
    /// [`aa_proxy::proxy::ProxyServer`] built from the same
    /// `ProxyConfig::from_env`, with that one field overridden. See that file's
    /// module docs for what is and is not production code in it.
    ///
    /// It is copied to a file named `aa-proxy` because `aasm proxy start`
    /// resolves the binary with [`aa_core::binary_resolve::resolve_binary`]
    /// (AAASM-5982), which the trust check requires to carry that name.
    /// **That check is therefore not under test through this constructor** —
    /// `cli_run_trusted_proxy.rs` measures it against the genuine binary, and
    /// nothing here relaxes it.
    ///
    /// Since AAASM-5982 that resolver prefers a binary sitting next to the
    /// running executable over anything on `$PATH` (ADR 0030 §6.4), so this
    /// spawns a **copy of `aasm` placed in the same directory as the copied
    /// `aa-proxy` stand-in**, not the genuine `aasm` from `target/debug`. A
    /// genuine `aa-proxy` built by an earlier test in the same run also lives
    /// in `target/debug`, next to the genuine `aasm`; spawning the real
    /// `aasm` would let sibling resolution find that real `aa-proxy` before
    /// `$PATH` is even consulted, so the mock upstream would never see the
    /// traffic under test (AAASM-5982 CI failure).
    ///
    /// `ca_dir` is the caller's so the certificate authority the mock's leaf is
    /// signed by, the one the proxy issues MitM leaves from, and the one the
    /// integration install copies into the launch environment are all one CA. A
    /// harness holding three of them would pass or fail for reasons that have
    /// nothing to do with the product.
    ///
    /// `extra_env` is passed through to the `aasm proxy start` child on top of
    /// the fixed set below (AAASM-5902: e.g. `AA_PROXY_TELEMETRY_ENDPOINT` for a
    /// journey that needs the proxy to report redaction telemetry to a specific
    /// address rather than the production default).
    pub fn start_intercepting(
        ca_dir: &Path,
        upstream: std::net::SocketAddr,
        state_dir: &Path,
        extra_env: &[(&str, &str)],
    ) -> anyhow::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        let built = proxy_with_mock_upstream_binary();

        let tmp = tempfile::tempdir()?;
        let root = tmp.path().to_path_buf();
        let data_dir = root.join("data");
        let proxy_bin_dir = root.join("bin");
        std::fs::create_dir_all(&data_dir)?;
        std::fs::create_dir_all(&proxy_bin_dir)?;

        let proxy_bin = proxy_bin_dir.join("aa-proxy");
        std::fs::copy(&built, &proxy_bin)?;
        std::fs::set_permissions(&proxy_bin, std::fs::Permissions::from_mode(0o755))?;

        // Copied into the same directory as the mock `aa-proxy` above so
        // `aa_core::binary_resolve::resolve_binary`'s exe-sibling search (the
        // first thing it tries, ahead of `$PATH`) finds *this* `aa-proxy`
        // rather than a genuine one another test in the run may have built
        // next to the real `aasm` in `target/debug` — see the doc comment on
        // this function.
        let aasm_src = aasm_binary();
        let aasm = proxy_bin_dir.join("aasm");
        std::fs::copy(&aasm_src, &aasm)?;
        std::fs::set_permissions(&aasm, std::fs::Permissions::from_mode(0o755))?;

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.local_addr()?.port()
        };
        let addr = format!("127.0.0.1:{port}");
        let log_path = root.join("proxy.log");

        let mut cmd = std::process::Command::new(&aasm);
        cmd.env("AA_DATA_DIR", &data_dir)
            .env("PATH", prefixed_path(&proxy_bin_dir)?)
            // Inherited by the spawned proxy: `aasm proxy start` sets a handful
            // of variables on the child and passes the rest of its own
            // environment through.
            .env("AA_TEST_PROXY_UPSTREAM", upstream.to_string())
            // Mirrors the conformance harness: the tool's side channels carry
            // prompt and telemetry bodies too, and a capture set scoped to the
            // model endpoint alone would let a secret leaking down one of them
            // pass unnoticed.
            .env("AA_PROXY_LLM_ONLY", "false")
            // The mock's leaf is signed by the throwaway CA above, which no
            // public root store knows. Debug-only; ignored in release builds.
            .env("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY", "1")
            .env("AASM_STATE_DIR", state_dir);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let out = cmd
            .args([
                "proxy",
                "start",
                "--listen",
                &addr,
                "--ca-dir",
                ca_dir.to_str().expect("temp path is utf-8"),
                "--log-file",
                log_path.to_str().expect("temp path is utf-8"),
            ])
            .output()?;
        anyhow::ensure!(
            out.status.success(),
            "`aasm proxy start` failed — without a running proxy every `aasm run` in this test \
             refuses, and the refusal would be mistaken for the behaviour under test\n\
             stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        Ok(Self {
            _tmp: tmp,
            aasm,
            data_dir,
            proxy_bin_dir,
            addr,
            log_path,
            stopped: false,
        })
    }

    /// The `AA_DATA_DIR` to hand to any `aasm` process that must see this proxy.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The `aasm` binary a caller should spawn for a **second, dedicated**
    /// launch (`aasm run <tool>`) that must resolve its own per-launch
    /// `aa-proxy` (AAASM-5863) to the same mock stand-in this instance
    /// started with, rather than the genuine `aa-proxy` next to
    /// [`aasm_binary`] in `target/debug`.
    ///
    /// For a [`start_intercepting`](Self::start_intercepting) instance this
    /// is a copy of `aasm` placed beside the mock `aa-proxy` in
    /// [`proxy_bin_dir`](Self::proxy_bin_dir), so
    /// `aa_core::binary_resolve::resolve_binary`'s exe-sibling search — which
    /// wins over `$PATH` (AAASM-5982, ADR 0030 §6.4) — finds the mock there
    /// too. Putting `proxy_bin_dir()` on that second launch's `$PATH` alone
    /// is not sufficient post-AAASM-5982: sibling resolution is consulted
    /// first, so a real `aa-proxy` built by another test earlier in the same
    /// run and sitting next to the real `aasm` would still win the race. For
    /// a [`start`](Self::start) instance (no mock involved) this is simply
    /// the real `aasm` binary.
    pub fn aasm(&self) -> &Path {
        &self.aasm
    }

    /// `host:port` the proxy is listening on.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The endpoint a governed launch must be routed at.
    pub fn expected_proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Directory holding the `aa-proxy` binary, for callers that build their own
    /// `PATH` for the child.
    pub fn proxy_bin_dir(&self) -> &Path {
        &self.proxy_bin_dir
    }

    /// Path to the `--log-file` this proxy was started with (AAASM-5902; needed
    /// for cross-process log correlation).
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// OS process id of the running proxy, read from its state file
    /// (`$AA_DATA_DIR/proxy.pid`, first line — see `aa-cli/src/commands/proxy/pid.rs`).
    ///
    /// `None` if the state file cannot be read/parsed, e.g. the proxy has
    /// already been stopped.
    pub fn pid(&self) -> Option<u32> {
        let content = std::fs::read_to_string(self.data_dir.join("proxy.pid")).ok()?;
        content.lines().next()?.trim().parse().ok()
    }

    /// Explicitly stop the proxy via `aasm proxy stop` (SIGTERM, then SIGKILL
    /// after 5s — see `aa-cli/src/commands/proxy/stop.rs`), rather than relying
    /// on `Drop`. Idempotent: a proxy already stopped is reported as such by
    /// `aasm proxy stop` itself and this still returns `Ok`.
    pub fn stop(&mut self) -> anyhow::Result<()> {
        let out = std::process::Command::new(&self.aasm)
            .env("AA_DATA_DIR", &self.data_dir)
            .args(["proxy", "stop"])
            .output()?;
        self.stopped = true;
        anyhow::ensure!(
            out.status.success(),
            "`aasm proxy stop` failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        Ok(())
    }
}

impl Drop for TrustedProxy {
    fn drop(&mut self) {
        // Best-effort safety net: skip if `stop()` was already called
        // explicitly. The temp dir goes away regardless, but the proxy is in
        // its own process group and would outlive the test run otherwise.
        if self.stopped {
            return;
        }
        let _ = std::process::Command::new(&self.aasm)
            .env("AA_DATA_DIR", &self.data_dir)
            .args(["proxy", "stop"])
            .output();
    }
}

/// A start token that is well-formed for whatever scheme the running `aasm`
/// wrote into `state_file`, but names a different incarnation of the PID.
///
/// The scheme tag has to be preserved. Since AAASM-5333 the trust check refuses
/// an *unrecognised* scheme with a diagnostic of its own — that is how a record
/// left by an older `aasm` is told apart from a PID that really was recycled —
/// so substituting an arbitrary string would exercise that path instead of the
/// start-time comparison, and the test would still see a refusal while measuring
/// the wrong one.
pub fn foreign_incarnation_token(state_file: &Path) -> anyhow::Result<String> {
    let content = std::fs::read_to_string(state_file)?;
    let recorded = content
        .lines()
        .nth(2)
        .ok_or_else(|| anyhow::anyhow!("state record at {} has no start-token line", state_file.display()))?;
    let (scheme, _) = recorded
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("recorded start token {recorded:?} carries no scheme tag"))?;
    // `0` is a value no scheme can genuinely produce: the Linux schemes lead
    // with a start tick, which is zero only for a process that began at boot,
    // and the macOS scheme leads with an epoch second.
    let substitute = format!("{scheme}:0");
    anyhow::ensure!(
        substitute != recorded,
        "the substitute token must differ from the recorded one, or the refusal proves nothing"
    );
    Ok(substitute)
}

/// `PATH` with `first` prepended, so a `which` probe in a child finds our binary
/// while the child keeps whatever else it needs from the host.
pub fn prefixed_path(first: &Path) -> anyhow::Result<std::ffi::OsString> {
    let mut parts = vec![first.to_path_buf()];
    parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
    Ok(std::env::join_paths(parts)?)
}
