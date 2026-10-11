//! AAASM-6297 (ST-10) -- found while auditing why governed launches on macOS
//! never prompted for System Keychain trust: `CaStore::is_installed()` is
//! implemented with `security find-certificate -c <CN> -a <keychain>` and
//! reads only the command's EXIT STATUS. With `-a`, that command exits 0 when
//! nothing matches (empty output); WITHOUT `-a` it exits 44 for "not found".
//! So the probe answers "installed" for a certificate that is not there, and
//! `CaStore::install()` (which first calls it) becomes a silent no-op: the
//! System Keychain trust install can never fire on such a host.
//!
//! Read-only: only `security find-certificate` (no `add-trusted-cert`, no
//! prompt) is run. Skips (NOT MEASURED) on a host that genuinely has the cert.
#![cfg(target_os = "macos")]

use std::process::Command;

use aa_proxy::tls::CaStore;

const CN: &str = "Agent Assembly CA";
const KEYCHAIN: &str = "/Library/Keychains/System.keychain";

fn security_exit(args: &[&str]) -> i32 {
    Command::new("security")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("security CLI")
        .code()
        .unwrap_or(-1)
}

/// Returns `false` (and says so) when the host really has the certificate,
/// in which case neither assertion below would be meaningful.
fn cert_truly_absent() -> bool {
    let without_a = security_exit(&["find-certificate", "-c", CN, KEYCHAIN]);
    if without_a == 0 {
        eprintln!("NOT MEASURED: `{CN}` genuinely exists in {KEYCHAIN} on this host");
        return false;
    }
    // positive control that the probe can say "not found" at all
    assert_eq!(without_a, 44, "without -a a missing cert exits 44 (item not found)");
    true
}

/// CHARACTERISATION of the observed (wrong) behaviour.
#[tokio::test]
async fn is_installed_answers_true_for_a_certificate_that_is_not_in_the_keychain() {
    if !cert_truly_absent() {
        return;
    }
    // the `-a` form the product uses: exit 0 despite no match
    assert_eq!(
        security_exit(&["find-certificate", "-c", CN, "-a", KEYCHAIN]),
        0,
        "OBSERVED: -a exits 0 on no match"
    );
    let dir = tempfile::tempdir().unwrap();
    let store = CaStore::load_or_create(dir.path()).await.unwrap();
    assert!(
        store.is_installed().unwrap(),
        "OBSERVED: probe says installed although absent"
    );
}

/// DESIRED: the probe reports absence truthfully.
#[tokio::test]
#[ignore = "AAASM-6297 finding: aa-proxy/src/tls/keychain.rs:75 is_cert_trusted trusts the exit status of `find-certificate -a`, which is 0 on no match; install() therefore never runs"]
async fn desired_is_installed_is_false_when_the_certificate_is_absent() {
    if !cert_truly_absent() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = CaStore::load_or_create(dir.path()).await.unwrap();
    assert!(!store.is_installed().unwrap());
}
