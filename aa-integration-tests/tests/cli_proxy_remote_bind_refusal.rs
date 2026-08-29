//! `aasm proxy start` refuses a listen address `aasm run` would never trust
//! (AAASM-5348).
//!
//! # Why this is measured end-to-end and not only in `start.rs`
//!
//! The unit tests decide whether the address is acceptable. The claim this file
//! exists for is the one they cannot make: that a refused start leaves **no
//! residue** — no listening socket and no state file. Those are effects of the
//! real process, produced in the order the real `dispatch` produces them, so the
//! only way to observe that the refusal beat them is to run the binary.
//!
//! The `aa-proxy` binary is put on `PATH` for every case here deliberately. The
//! guard runs before the binary is resolved, so a run with no `aa-proxy`
//! available would also fail — for the wrong reason, and the test would pass
//! while measuring nothing. Each case therefore asserts the failure is *not* the
//! missing-binary one.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

// `build_binary` rebuilds unconditionally: `aa-integration-tests` depends on
// neither `aa-cli` nor the `aa-proxy` binary, so a stale artefact in `target/`
// would otherwise be measured instead of this tree — a false pass for a test
// whose whole subject is `aasm` behaviour.
mod proxy_trust_support;

use proxy_trust_support::{aa_proxy_binary, aasm_binary, prefixed_path};

/// A port nothing holds, taken by binding and releasing so the reachability
/// assertions below start from "closed".
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
    listener.local_addr().expect("the bound port").port()
}

struct Refused {
    stderr: String,
    data_dir: PathBuf,
    _tmp: tempfile::TempDir,
}

/// Run `aasm proxy start --listen <addr>` in an isolated `AA_DATA_DIR` with a
/// real `aa-proxy` on `PATH`, and require it to fail.
fn start_expecting_refusal(listen: &str, extra: &[&str]) -> Refused {
    let aasm = aasm_binary();
    let proxy_dir = aa_proxy_binary()
        .parent()
        .expect("the built binary has a parent directory")
        .to_path_buf();

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let data_dir = root.join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let ca_dir = root.join("ca");
    let log_file = root.join("proxy.log");
    let mut args = vec![
        "proxy",
        "start",
        "--listen",
        listen,
        "--ca-dir",
        ca_dir.to_str().expect("temp path is utf-8"),
        "--log-file",
        log_file.to_str().expect("temp path is utf-8"),
    ];
    args.extend_from_slice(extra);

    let out = Command::new(&aasm)
        .env("AA_DATA_DIR", &data_dir)
        .env("PATH", prefixed_path(&proxy_dir).expect("PATH"))
        .args(&args)
        .output()
        .expect("aasm proxy start");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "`aasm proxy start --listen {listen}` must not succeed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("aa-proxy binary not found"),
        "the refusal must come from the listen-address guard, not from a missing binary — \
         otherwise this test proves nothing\nstderr:\n{stderr}"
    );

    Refused {
        stderr,
        data_dir,
        _tmp: tmp,
    }
}

impl Refused {
    /// The operator must not be left with a half-started proxy: nothing may be
    /// listening, and no state file may exist for `aasm proxy status`/`stop` to
    /// find.
    ///
    /// Reachability is probed on loopback because a `0.0.0.0` bind would have
    /// covered it — a wildcard listener that came up anyway is observable from
    /// here, which is the failure this guards against.
    fn left_no_residue(&self, port: u16) {
        let loopback: SocketAddr = format!("127.0.0.1:{port}").parse().expect("the test's own literal");
        assert!(
            std::net::TcpStream::connect_timeout(&loopback, Duration::from_millis(500)).is_err(),
            "a refused start must not have bound port {port}"
        );
        let state = self.data_dir.join("proxy.pid");
        assert!(
            !state.exists(),
            "a refused start must not leave a state file at {}",
            state.display()
        );
    }
}

/// The exact invocation from the ticket: the proxy used to come up here, and
/// `aasm run` then refused to route anything at it.
#[test]
fn a_bare_non_loopback_listen_address_is_refused_before_anything_starts() {
    let port = free_port();
    let listen = format!("0.0.0.0:{port}");
    let refused = start_expecting_refusal(&listen, &[]);

    assert!(
        refused.stderr.contains(&listen),
        "the diagnostic must name the address, got:\n{}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("not a loopback address"),
        "the diagnostic must say what disqualified the address, got:\n{}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("--allow-remote-clients"),
        "the diagnostic must name the option that states the intent, got:\n{}",
        refused.stderr
    );

    refused.left_no_residue(port);
}

/// Asking is not being granted. The proxy has no listener TLS and no client
/// authentication, so the opt-in changes only which refusal the operator gets —
/// and that one has to name what is missing.
#[test]
fn the_opt_in_still_refuses_and_names_the_missing_protections() {
    let port = free_port();
    let listen = format!("0.0.0.0:{port}");
    let refused = start_expecting_refusal(&listen, &["--allow-remote-clients"]);

    assert!(
        refused.stderr.contains("TLS on the proxy listener"),
        "the diagnostic must name the missing transport protection, got:\n{}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("client authentication and authorization"),
        "the diagnostic must name the missing client-identity protection, got:\n{}",
        refused.stderr
    );

    refused.left_no_residue(port);
}

/// The guard must not have cost the working case anything: an explicit loopback
/// address still starts a proxy, and it is one `aasm run` will trust.
#[test]
fn an_explicit_loopback_listen_address_still_starts() {
    // AAASM-5977: this file is not one of the six converted to
    // `common::precondition::require` — its skip is conditioned on a live
    // macOS keychain-authorization outcome no CI lane can guarantee, and (see
    // below) it already re-raises the one failure that would actually be a
    // regression, so the property this ticket protects — a real defect never
    // silently reads as a pass — already holds on the skip path.
    let proxy = match proxy_trust_support::TrustedProxy::start() {
        Ok(p) => p,
        Err(e) => {
            // `aasm proxy start` also installs the CA into the macOS System
            // Keychain, which needs admin, so a start can fail for reasons that
            // say nothing about this guard. A guard that over-reached, though,
            // would fail here too — and skipping on that would turn the
            // regression this test exists to catch into a silent pass. So the
            // one failure that is never environmental is re-raised.
            let reported = format!("{e:#}");
            assert!(
                !reported.contains("refusing to listen on"),
                "a loopback address must never be refused by the listen guard:\n{reported}"
            );
            eprintln!("an_explicit_loopback_listen_address_still_starts: skipping — proxy start failed: {reported}");
            return;
        }
    };

    let addr: SocketAddr = proxy.addr().parse().expect("the harness binds an ip:port literal");
    assert!(addr.ip().is_loopback(), "the harness must exercise a loopback address");
    assert!(
        std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok(),
        "a loopback proxy must still come up and accept connections"
    );
    assert!(
        proxy.data_dir().join("proxy.pid").exists(),
        "an accepted start must still write the state file `aasm run` reads"
    );
}
