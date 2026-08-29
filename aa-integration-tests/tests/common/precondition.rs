//! Shared skip-guard visibility mechanism (AAASM-5977).
//!
//! A test gated on a runtime precondition (a binary not built, a tool not on
//! `PATH`) historically took a silent early `return` and reported `PASS` to
//! `cargo nextest` — indistinguishable from a test that ran every assertion.
//! This already let a fixture (`MINIMAL_POLICY`) rot undetected behind a
//! guard whose cwd-relative probe always missed (AAASM-5937).
//!
//! [`require`] closes that gap without claiming nextest can report a dynamic
//! runtime skip as its own outcome — it can't; `#[ignore]` is compile-time and
//! cannot reflect a binary the same CI job builds moments earlier, and nextest
//! has no post-hoc "mark this test skipped" API. Instead: on a developer
//! machine an unmet precondition still degrades gracefully (today's
//! behaviour, preserved), but in a lane that provisions its own binaries —
//! signalled by [`REQUIRE_ENV`] — the same unmet precondition panics, which
//! nextest reports as a distinct, non-green `FAILED`. Every call also records
//! to the AAASM-5465 evidence ledger via [`evidence::record`], so the CI
//! summary step can see the decline even on a machine where the ledger isn't
//! read.
//!
//! # Not every guard in the ticket's file list uses this
//!
//! AAASM-5977 named six files. Three (`cli_gateway.rs`,
//! `e2e_runtime_gateway_deny.rs`, `e2e_sdk_go.rs`) are converted to this
//! module. The other three are left as-is, each with a rationale at its site:
//! `cli_proxy.rs`'s guard is *inverted* (it skips when the binary is
//! resolvable, so provisioning would disable the test);
//! `cli_proxy_remote_bind_refusal.rs` already re-raises the one
//! non-environmental failure on its skip path, so no regression can hide
//! behind it; `cli_dashboard.rs` has no early `return` at all — its
//! conditional only picks which assertions apply, so it isn't the pathology
//! this ticket targets.
//!
//! No `#![allow(dead_code)]` here — the outer `#[allow(dead_code)]` on this
//! module's `pub mod precondition;` declaration in `common/mod.rs` already
//! covers it, matching every other module in this directory. A second one
//! here duplicated that suppression on the same item (clippy's
//! `duplicated_attributes`).
//!
//! `evidence` is loaded here (`#[path = "../evidence/mod.rs"] pub mod
//! evidence;` below) rather than assuming every consumer already has it at
//! its own crate root — most of `common`'s ~64 callers don't. Four binaries
//! (`cli_run_claude_deterministic_conformance.rs` and others, via
//! `conformance_support`) *do* already load the same file as `crate::evidence`
//! for their own reasons; for those, loading it a second time here would trip
//! clippy's `duplicate_mod` (the same file loaded via two `mod` paths within
//! one binary). Their fix lives at their own call site: `pub use
//! crate::common::precondition::evidence;` — a re-export, not a second `mod`,
//! per clippy's own suggested fix ("replace all but one `mod` item with `use`
//! items") and matching how `conformance_support/mod.rs` already re-exports
//! `crate::evidence` rather than redeclaring it.

#[path = "../evidence/mod.rs"]
pub mod evidence;
use evidence::Measurement;

use std::path::{Path, PathBuf};

/// Set only by `.github/workflows/integration-tests.yml`. That lane builds
/// every binary its own guards check for, so an unmet precondition there is a
/// broken lane, not an honest opt-out — a graceful return would report it as
/// a pass, which is the exact invisibility this ticket exists to remove.
pub const REQUIRE_ENV: &str = "AA_REQUIRE_PRECONDITIONS";

/// Gate a test on an environment precondition (AAASM-5977).
///
/// `met` carries the failure reason on `Err` so the evidence-ledger record and
/// the strict-mode panic message are the same text. Returns `true` when the
/// precondition holds (the caller proceeds); on `Err`, records a
/// [`Measurement::ToolAbsent`] decline and either panics (when
/// [`REQUIRE_ENV`] is set) or returns `false` (graceful skip, today's
/// behaviour on a developer machine).
pub fn require(scenario: &str, met: Result<(), String>) -> bool {
    let Err(reason) = met else {
        return true;
    };
    println!("SKIP [{scenario}]: {reason}");
    evidence::record(scenario, Measurement::ToolAbsent, &reason);
    if std::env::var_os(REQUIRE_ENV).is_some() {
        panic!("{scenario}: environment precondition unmet in a lane that forbids skips: {reason}");
    }
    false
}

/// As [`require`], for a precondition the host *platform* can never satisfy
/// (not merely a missing binary a build step could provision). Distinct
/// ledger token — [`Measurement::UnsupportedPlatform`] — because provisioning
/// cannot fix a wrong runner, so a strict lane that hits this is not the same
/// class of broken as one that hits [`require`].
pub fn require_platform(scenario: &str, met: Result<(), String>) -> bool {
    let Err(reason) = met else {
        return true;
    };
    println!("SKIP [{scenario}]: {reason}");
    evidence::record(scenario, Measurement::UnsupportedPlatform, &reason);
    if std::env::var_os(REQUIRE_ENV).is_some() {
        panic!("{scenario}: platform precondition unmet in a lane that forbids skips: {reason}");
    }
    false
}

/// The workspace's build-output root, honoring `CARGO_TARGET_DIR` (this
/// repo's shared-target convention) — a hardcoded `<workspace>/target` would
/// silently miss a binary that actually landed under a redirected target dir.
///
/// Deliberately a second copy of the identical helper in `cli_proxy.rs`
/// (AAASM-5974): lifting it to a shared location would refactor a file this
/// ticket does not otherwise touch.
pub fn cargo_target_root() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("CARGO_MANIFEST_DIR has parent")
                .join("target")
        })
}
