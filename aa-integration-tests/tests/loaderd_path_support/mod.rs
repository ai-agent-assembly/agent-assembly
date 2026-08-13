//! AAASM-5311 — pure, platform-independent helpers for locating a
//! cargo-built binary artifact, factored out of `e2e_ebpf.rs::loaderd_bin_path()`
//! so they can be unit-tested without Linux, root, or `aa-ebpf`/`aya`.
//!
//! `e2e_ebpf.rs` (the production consumer of these helpers) is
//! `#![cfg(target_os = "linux")]`-gated because it links `aa-ebpf`/`aya`,
//! which don't build off Linux — so it can't run its own `#[test]`s on a
//! macOS dev machine. This module has no such dependency (std + `serde_json`
//! only, both available on every platform this crate builds on) and is
//! `mod`-included by both `e2e_ebpf.rs` and `../loaderd_bin_path.rs` (the
//! cross-platform regression test), so the code under test is the exact
//! code that ships to CI, not a parallel reimplementation that could drift.
//!
//! ## Why this exists
//!
//! A Cargo nightly build-directory-layout change (observed between
//! 2026-07-26 and 2026-07-30) moved test binaries from
//! `target/<profile>/deps/<name>-<hash>` to
//! `target/<profile>/build/<crate>/<hash>/out/<name>-<hash>`. The old lookup
//! assumed `current_exe().parent().parent()` was always exactly the
//! `<profile>` directory — true only under the old layout. `current_exe()`-
//! relative `target/` layout is a Cargo implementation detail, not a stable
//! contract (it has changed before and will change again); do not reintroduce
//! a fixed-depth `.parent()` chain here or elsewhere.

use std::path::{Path, PathBuf};

/// Walk upward from `start` (inclusive of `start`'s own directory) looking
/// for a sibling file named `bin_name` in each ancestor directory.
///
/// This tolerates any `target/` layout depth between the current test
/// executable and the sibling binary, unlike a fixed `.parent().parent()`
/// chain. It is a fast, cargo-free pre-check; the authoritative source of
/// truth (immune to *future* layout changes too, since it asks Cargo
/// directly) is [`parse_executable_from_cargo_json`].
pub(crate) fn find_sibling_binary(start: &Path, bin_name: &str) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|dir| dir.join(bin_name))
        .find(|candidate| candidate.exists())
}

/// Parse `cargo build --message-format=json-render-diagnostics` stdout
/// (newline-delimited JSON messages) for the `executable` path reported by
/// the `compiler-artifact` message whose target name is `target_name`.
///
/// This is authoritative regardless of `target/` directory layout, present
/// or future, because it asks Cargo directly where it placed the artifact
/// rather than guessing from `current_exe()`.
pub(crate) fn parse_executable_from_cargo_json(stdout: &str, target_name: &str) -> Option<PathBuf> {
    for line in stdout.lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if msg.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        let name_matches = msg.get("target").and_then(|t| t.get("name")).and_then(|n| n.as_str()) == Some(target_name);
        if !name_matches {
            continue;
        }
        if let Some(exe) = msg.get("executable").and_then(|e| e.as_str()) {
            return Some(PathBuf::from(exe));
        }
    }
    None
}
