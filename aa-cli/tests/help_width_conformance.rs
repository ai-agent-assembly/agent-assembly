//! `aasm --help` rendering at narrow terminal width (AAASM-6235).
//!
//! ADR-0013 §5 (company CLI Experience v1 contract) requires narrow-terminal
//! help to have no uncontrolled horizontal overflow and deterministic
//! wrapping. HORO-1608's conformance audit (and this ticket's own
//! re-verification, built fresh from the `ai-agent-assembly/agent-assembly`
//! org remote's `main` tip) measured this CLI's root `--help` as
//! byte-identical at `COLUMNS=70/110/160`, with a max rendered line of 519
//! characters, because `clap`'s `wrap_help` feature — which enables
//! terminal-width-aware reflow via the `terminal_size` crate — was not
//! enabled. (A previously-audited Homebrew-distributed build measured 337
//! chars on a materially different, older command surface — not reproduced
//! here, and not the number this test guards against.) This test runs the
//! real compiled `aasm` binary (not an in-process `clap::Command`) so it
//! exercises exactly what an operator's terminal sees, and fails on any
//! build that regresses back to width-insensitive rendering.
use std::process::Command;

use assert_cmd::prelude::*;

/// The longest line in `s`, measured in characters (not bytes) so
/// multi-byte/Unicode output isn't undercounted.
fn max_line_len(s: &str) -> usize {
    s.lines().map(|l| l.chars().count()).max().unwrap_or(0)
}

/// `aasm --help` must not overflow a narrow terminal: every rendered line
/// must fit within the advertised `COLUMNS` width. Fails on the pre-fix
/// binary (measured 519-523 chars wide regardless of `COLUMNS`); passes once
/// `wrap_help` reflows to the requested width.
#[test]
fn root_help_wraps_to_narrow_terminal_width() {
    let width = 70u16;
    let output = Command::cargo_bin("aasm")
        .expect("aasm binary")
        .arg("--help")
        .env("COLUMNS", width.to_string())
        .output()
        .expect("aasm --help must run");
    assert!(output.status.success(), "aasm --help must exit 0");

    let stdout = String::from_utf8(output.stdout).expect("help output must be valid UTF-8");
    let longest = max_line_len(&stdout);
    assert!(
        longest <= width as usize,
        "aasm --help rendered a {longest}-char line at COLUMNS={width} \
         (ADR-0013 §5: no uncontrolled horizontal overflow at narrow width)"
    );
}

/// Root help must actually reflow, not just happen to fit — a binary that
/// renders byte-identical output regardless of terminal width (this CLI's
/// pre-fix state) would otherwise slip past a bound-only assertion the first
/// time its text got short enough to fit 70 columns by coincidence.
#[test]
fn root_help_rendering_is_width_sensitive() {
    let narrow = Command::cargo_bin("aasm")
        .expect("aasm binary")
        .arg("--help")
        .env("COLUMNS", "70")
        .output()
        .expect("aasm --help must run");
    let wide = Command::cargo_bin("aasm")
        .expect("aasm binary")
        .arg("--help")
        .env("COLUMNS", "160")
        .output()
        .expect("aasm --help must run");

    assert_ne!(
        narrow.stdout, wide.stdout,
        "aasm --help rendered byte-identical output at COLUMNS=70 and COLUMNS=160 \
         (wrap_help is not reflowing — the CLI is width-insensitive again)"
    );
}
