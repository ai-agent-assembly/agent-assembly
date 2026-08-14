//! AAASM-5311 — cross-platform regression tests for the `aa-ebpf-loaderd`
//! path-resolution helpers used by `e2e_ebpf.rs::loaderd_bin_path()`.
//!
//! `e2e_ebpf.rs` is `#![cfg(all(target_os = "linux", feature = "integration-test"))]`
//! (it links `aa-ebpf`/`aya`, which don't build off Linux), so it cannot run
//! its own `#[test]`s on a macOS dev machine. This file is unconditional —
//! no `cfg` gate, no Linux-only dependency — and `mod`-includes the exact
//! same `loaderd_path_support` module that `e2e_ebpf.rs` calls in
//! production, so what's tested here is what actually runs in CI.
//!
//! The case this exists to guard: a Cargo nightly build-directory layout
//! change moved the test binary itself out from under `target/<profile>/deps/`,
//! which broke a fixed `current_exe().parent().parent()` assumption even
//! though the sibling `aa-ebpf-loaderd` binary was built correctly. See the
//! module doc on `loaderd_path_support` and the comment on
//! `e2e_ebpf::loaderd_bin_path` for the full history.

mod loaderd_path_support;

use std::fs;
use std::path::PathBuf;

/// The exact failure mode AAASM-5311 fixed: the "current test executable" is
/// several directories above the profile dir that holds the sibling binary —
/// not exactly two, as the old `.parent().parent()` chain assumed. Walking
/// ancestors must still find it.
#[test]
fn find_sibling_binary_locates_binary_under_new_nightly_layout() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let profile_dir = tmp.path().join("target").join("debug");
    // Mirrors target/debug/build/aa-integration-tests/<hash>/out/e2e_ebpf-<hash>
    let nested_exe_dir = profile_dir
        .join("build")
        .join("aa-integration-tests")
        .join("abcd1234")
        .join("out");
    fs::create_dir_all(&nested_exe_dir).expect("mkdir nested (new-layout) exe dir");
    let fake_exe = nested_exe_dir.join("e2e_ebpf-deadbeef");
    fs::write(&fake_exe, b"").expect("write fake test exe");

    let real_bin = profile_dir.join("aa-ebpf-loaderd");
    fs::write(&real_bin, b"").expect("write fake aa-ebpf-loaderd");

    let found = loaderd_path_support::find_sibling_binary(&fake_exe, "aa-ebpf-loaderd")
        .expect("should locate aa-ebpf-loaderd by walking ancestors of a deeply-nested exe path");
    assert_eq!(found, real_bin);
}

/// The old layout (`target/<profile>/deps/<name>-<hash>`, two levels above
/// the daemon binary) must still resolve — the fix must not regress it.
#[test]
fn find_sibling_binary_locates_binary_under_old_deps_layout() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let profile_dir = tmp.path().join("target").join("debug");
    let deps_dir = profile_dir.join("deps");
    fs::create_dir_all(&deps_dir).expect("mkdir deps dir");
    let fake_exe = deps_dir.join("e2e_ebpf-5fafa8cfcc64d109");
    fs::write(&fake_exe, b"").expect("write fake test exe");

    let real_bin = profile_dir.join("aa-ebpf-loaderd");
    fs::write(&real_bin, b"").expect("write fake aa-ebpf-loaderd");

    let found = loaderd_path_support::find_sibling_binary(&fake_exe, "aa-ebpf-loaderd")
        .expect("should still locate aa-ebpf-loaderd under the old deps/ layout");
    assert_eq!(found, real_bin);
}

/// When the binary genuinely isn't anywhere above the exe (not yet built),
/// resolution must report absence rather than panicking or fabricating a path
/// — the caller relies on `None` to trigger the `cargo build` fallback.
#[test]
fn find_sibling_binary_returns_none_when_absent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let exe_dir = tmp.path().join("target").join("debug").join("deps");
    fs::create_dir_all(&exe_dir).expect("mkdir");
    let fake_exe = exe_dir.join("e2e_ebpf-deadbeef");
    fs::write(&fake_exe, b"").expect("write fake test exe");

    assert!(loaderd_path_support::find_sibling_binary(&fake_exe, "aa-ebpf-loaderd").is_none());
}

/// The authoritative fallback: parsing real `cargo build
/// --message-format=json-render-diagnostics` stdout must pick out the
/// `executable` field of the matching `compiler-artifact` message and ignore
/// unrelated artifacts (e.g. the `aa-ebpf` lib target built as a dependency).
#[test]
fn parse_executable_from_cargo_json_extracts_matching_artifact() {
    let stdout = concat!(
        r#"{"reason":"compiler-artifact","target":{"name":"aa-ebpf"},"executable":null}"#,
        "\n",
        r#"{"reason":"compiler-artifact","target":{"name":"aa-ebpf-loaderd"},"executable":"/repo/target/debug/aa-ebpf-loaderd"}"#,
        "\n",
        r#"{"reason":"build-finished","success":true}"#,
        "\n",
    );

    let found = loaderd_path_support::parse_executable_from_cargo_json(stdout, "aa-ebpf-loaderd");
    assert_eq!(found, Some(PathBuf::from("/repo/target/debug/aa-ebpf-loaderd")));
}

/// No message for the requested target name — e.g. the build was invoked for
/// the wrong package — must report absence rather than picking an unrelated
/// artifact.
#[test]
fn parse_executable_from_cargo_json_returns_none_when_target_absent() {
    let stdout = concat!(
        r#"{"reason":"compiler-artifact","target":{"name":"aa-ebpf"},"executable":"/repo/target/debug/aa-ebpf"}"#,
        "\n",
    );

    assert_eq!(
        loaderd_path_support::parse_executable_from_cargo_json(stdout, "aa-ebpf-loaderd"),
        None
    );
}

/// Non-JSON / malformed lines (Cargo interleaves plain-text warnings even
/// under `--message-format=json-render-diagnostics` in some versions) must be
/// skipped rather than panicking the parser.
#[test]
fn parse_executable_from_cargo_json_skips_malformed_lines() {
    let stdout = concat!(
        "warning: unused import\n",
        r#"{"reason":"compiler-artifact","target":{"name":"aa-ebpf-loaderd"},"executable":"/repo/target/debug/aa-ebpf-loaderd"}"#,
        "\n",
    );

    let found = loaderd_path_support::parse_executable_from_cargo_json(stdout, "aa-ebpf-loaderd");
    assert_eq!(found, Some(PathBuf::from("/repo/target/debug/aa-ebpf-loaderd")));
}
