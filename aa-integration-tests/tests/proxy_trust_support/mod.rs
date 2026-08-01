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
    static BUILT: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, PathBuf>>> =
        std::sync::OnceLock::new();
    let cache = BUILT.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(path) = cache.get(bin) {
        return path.clone();
    }

    // Built from the manifest dir, which is what lets the runs themselves stay
    // hermetic in a temp working directory (cargo cannot find a manifest from
    // there, so `cargo run`-style resolution is not an option).
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "--quiet", "-p", package, "--bin", bin])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke cargo to build {bin}: {e}"));
    assert!(status.success(), "`cargo build -p {package} --bin {bin}` failed");

    let path = cargo_target_dir().join("debug").join(bin);
    assert!(
        path.is_file(),
        "no `{bin}` binary at {} even after building it. Skipping instead would leave the \
         behaviour unmeasured.",
        path.display(),
    );
    cache.insert(bin.to_string(), path.clone());
    path
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
                root.join("proxy.log").to_str().expect("temp path is utf-8"),
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
        })
    }

    /// The `AA_DATA_DIR` to hand to any `aasm` process that must see this proxy.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
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
}

impl Drop for TrustedProxy {
    fn drop(&mut self) {
        // Best effort: the temp dir goes away regardless, but the proxy is in
        // its own process group and would outlive the test run.
        let _ = std::process::Command::new(&self.aasm)
            .env("AA_DATA_DIR", &self.data_dir)
            .args(["proxy", "stop"])
            .output();
    }
}

/// `PATH` with `first` prepended, so a `which` probe in a child finds our binary
/// while the child keeps whatever else it needs from the host.
pub fn prefixed_path(first: &Path) -> anyhow::Result<std::ffi::OsString> {
    let mut parts = vec![first.to_path_buf()];
    parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
    Ok(std::env::join_paths(parts)?)
}
