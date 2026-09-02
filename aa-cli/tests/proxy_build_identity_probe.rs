//! AAASM-6014 / AAASM-5984 AC5: `aa_cli::commands::proxy::build_identity::probe`
//! never had a test at all — `aa-proxy/tests/build_identity.rs` proves
//! `aa-proxy --version` states the compiled identity correctly, but nothing
//! proved the CLI's own probe of a *real* binary (rather than a synthetic
//! `ProxyBuildEvidence`, which is all the `run_audit.rs` unit tests use)
//! recovers that identity correctly, or that it degrades safely against a
//! binary that isn't `aa-proxy` at all.
//!
//! `env!("CARGO_BIN_EXE_aa-proxy")` makes cargo build the real binary as a
//! dependency of this test target.

use std::path::{Path, PathBuf};

use aa_cli::commands::proxy::build_identity::probe;
use aa_runtime::build_identity::{BuildIdentity, IdentitySource, BUILD_SHA};

/// `aa-cli` depends on `aa-proxy` only as a library, so `cargo` does not
/// build the `aa-proxy` *binary* as a side effect of building this test
/// target and `env!("CARGO_BIN_EXE_aa-proxy")` is unavailable here (that only
/// works within `aa-proxy`'s own package — see `aa-proxy/tests/build_identity.rs`).
/// Build it explicitly and return its path; unconditional rather than a
/// missing-file fallback, so a stale artifact from an earlier tree is never
/// silently measured instead of the current one.
fn built_aa_proxy_path() -> PathBuf {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("aa-cli always has a workspace-root parent")
                .join("target")
        });
    let output = target_dir.join("debug").join("aa-proxy");

    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "--quiet", "-p", "aa-proxy", "--bin", "aa-proxy"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke cargo to build aa-proxy: {e}"));
    assert!(status.success(), "`cargo build -p aa-proxy --bin aa-proxy` failed");
    assert!(
        output.is_file(),
        "no aa-proxy artifact at {} even after building it",
        output.display(),
    );
    output
}

/// The property AAASM-5984 AC5 actually promises: the CLI's probe of the
/// real, resolved `aa-proxy` binary recovers this build's own compiled
/// identity — not a synthetic fixture standing in for it.
#[test]
fn probe_of_the_real_binary_recovers_this_builds_identity() {
    let proxy_path = built_aa_proxy_path();
    let evidence = probe(&proxy_path);

    let compiled = BuildIdentity::of_this_build();
    assert_eq!(
        evidence.identity.build_sha, compiled.build_sha,
        "probing the real aa-proxy binary must recover the SHA it was built at"
    );
    assert_ne!(
        evidence.identity.sha_source,
        IdentitySource::Absent,
        "a successfully probed real binary must not report an unresolved identity source"
    );
    assert_eq!(evidence.executable, proxy_path);
}

/// Negative control (AAASM-6014 AC): a binary that is not `aa-proxy` at all —
/// its `--version` output does not carry the `aa-proxy <ver> (<sha>)` banner
/// probe's parser expects — must yield the `Absent`/unknown sentinel, never a
/// fabricated or borrowed identity. Falsifies the claim that the probe
/// blindly trusts whatever `--version` prints.
#[test]
fn probe_of_a_foreign_binary_reports_absent_not_a_fabricated_identity() {
    // `env!("CARGO")` is cargo itself — a real, always-present binary on this
    // machine whose `--version` output is definitely not an aa-proxy banner.
    let evidence = probe(Path::new(env!("CARGO")));

    assert_eq!(
        evidence.identity.sha_source,
        IdentitySource::Absent,
        "a foreign binary's --version output must not be mistaken for an aa-proxy identity banner"
    );
    assert_ne!(
        evidence.identity.build_sha, BUILD_SHA,
        "the foreign binary's reported identity must not coincidentally equal this build's own SHA"
    );
}

/// Negative control: a path that does not exist at all must degrade the same
/// way as a foreign binary — infallible by contract (AAASM-5984 AC7), never
/// a panic or a launch-blocking error.
#[test]
fn probe_of_a_nonexistent_path_reports_absent() {
    let evidence = probe(Path::new("/nonexistent/definitely-not-a-real-binary-aaasm-6014"));
    assert_eq!(evidence.identity.sha_source, IdentitySource::Absent);
}
