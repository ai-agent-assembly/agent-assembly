//! AAASM-6297 (ST-10): `aasm run --isolation process -- claude` on macOS must
//! refuse CLEANLY, not boot a guest that cannot run the binary.
//!
//! What this file can and cannot show, stated up front:
//!
//! * It exercises the backend's real pre-boot gate, [`paths::to_guest_path`]
//!   (`aa-isolation-macos-vm/src/lib.rs:390` calls it before `vmm::boot`). It
//!   boots no guest: this host has no VM substrate, so the booted-guest arm is
//!   NOT MEASURED here. A test that only reached "refused" because the backend
//!   is unavailable would prove nothing about this gate, so the gate is driven
//!   directly with positive controls.
//! * The `claude` path used is a literal string; no real agent is executed or
//!   even read.
//! * `desired_*` is `#[ignore]`d: it pins the contract the product does not
//!   meet today (see its reason).

use std::path::{Path, PathBuf};

use aa_isolation_macos_vm::paths::{to_guest_path, PathMappingError};

/// A unique scratch directory under the OS temp dir (this crate has no
/// `tempfile` dev-dependency and a pure path test does not warrant adding one).
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aaasm6297-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// POSITIVE control: the gate is not simply refusing everything.
#[test]
fn a_guest_resident_program_and_a_path_under_the_share_are_reachable() {
    assert_eq!(to_guest_path("/bin/sh", None), Ok("/bin/sh".to_string()));
    assert_eq!(
        to_guest_path("/Users/dev/proj/bin/tool", Some(Path::new("/Users/dev/proj"))),
        Ok("/mnt/share/bin/tool".to_string())
    );
}

/// The ticket's scenario: a host-installed `claude` outside the project
/// directory is refused up front, naming the path, before any boot.
#[test]
fn a_host_installed_claude_outside_the_share_is_refused_before_any_boot() {
    for claude in [
        "/opt/homebrew/bin/claude",
        "/usr/local/bin/claude",
        "/Users/dev/.local/bin/claude",
    ] {
        let err = to_guest_path(claude, Some(Path::new("/Users/dev/proj"))).expect_err("must refuse");
        assert_eq!(
            err,
            PathMappingError::Unreachable {
                host_path: claude.to_string()
            }
        );
        assert!(
            err.to_string().contains(claude),
            "the refusal must name the path: {err}"
        );
        // and with no share configured at all
        assert_eq!(to_guest_path(claude, None), Err(PathMappingError::NoShareConfigured));
    }
}

/// Property-specific negative: the refusal is caused by REACHABILITY, not by
/// the program being called `claude` -- the same name under the share maps.
#[test]
fn the_refusal_follows_reachability_not_the_program_name() {
    let share = Path::new("/Users/dev/proj");
    assert!(to_guest_path("/Users/dev/proj/claude", Some(share)).is_ok());
    assert!(to_guest_path("/Users/dev/other/claude", Some(share)).is_err());
}

/// CHARACTERISATION of the gap: reachability is the ONLY thing checked. A
/// macOS Mach-O executable that happens to live under the shared project
/// directory is mapped into the Linux guest unchallenged -- the failure would
/// surface only after a guest boot, as an exec error inside the guest.
#[test]
fn a_macho_binary_under_the_share_is_mapped_into_the_guest_without_a_format_check() {
    let share = scratch("macho-char");
    let fake = share.join("claude");
    // Mach-O 64-bit little-endian magic (arm64/x86_64 macOS), then padding.
    std::fs::write(&fake, [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).unwrap();
    let mapped = to_guest_path(&fake.to_string_lossy(), Some(&share));
    assert_eq!(mapped, Ok("/mnt/share/claude".to_string()), "OBSERVED: no format check");
}

/// DESIRED: a program the guest cannot execute (a macOS Mach-O) is refused
/// before the guest is booted.
#[test]
#[ignore = "AAASM-6297 finding: paths::to_guest_path (aa-isolation-macos-vm/src/paths.rs) and the pre-boot gate at lib.rs:390 check reachability only, never executable format; a Mach-O under the share boots a guest that cannot exec it"]
fn desired_a_macho_binary_is_refused_before_boot() {
    let share = scratch("macho-desired");
    let fake = share.join("claude");
    std::fs::write(&fake, [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).unwrap();
    assert!(to_guest_path(&fake.to_string_lossy(), Some(&share)).is_err());
}
