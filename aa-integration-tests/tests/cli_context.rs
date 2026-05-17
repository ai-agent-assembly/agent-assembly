//! CLI integration tests for `aasm context` (AAASM-1463 / F121 follow-up).
//!
//! Exercises the three real `context` leaves shipped in master: `list`,
//! `set <NAME>`, and `use <NAME>`. Backed purely by the local config file
//! at `~/.aa/config.yaml`; no gateway calls — the in-process gateway that
//! `CliFixture::start()` boots sits idle for these tests, but the fixture
//! is used anyway to keep the harness contract uniform across cli_*.rs
//! files (per AAASM-1258 test-design rule "All tests use the shared
//! `CliFixture` — no per-test-file gateway boot helpers").
//!
//! ## Divergence from subtask description
//!
//! The AAASM-1463 description was drafted against a *planned* context
//! surface (`show` leaf, `--gateway-url`/`--token` flags, `--output` json
//! format, config at `~/.aasm/config.toml`). Master ships `list`/`set`/
//! `use` with positional `<NAME>` + `--api-url`/`--api-key`, plain-text
//! output only, config at `~/.aa/config.yaml`. Tests are written against
//! the real surface; see the AAASM-1463 starting-work comment for the
//! full reconciliation.
//!
//! ## $HOME isolation
//!
//! `aa_cli::config::config_dir()` calls `dirs::home_dir()`, which on Unix
//! reads `$HOME`. Each test injects `HOME=<tempfile::TempDir>` on the
//! `Command` so config writes land inside the tempdir and disappear when
//! the test ends. The shared `CliFixture::cmd()` does not set `HOME`
//! (it only sets `AA_DATA_DIR`); per-test override here keeps the
//! isolation pattern contained to this file.
//!
//! ## Leaf surface (from `aa-cli/src/commands/context.rs`)
//!
//! | Leaf | Args | Backend | Notes |
//! | --- | --- | --- | --- |
//! | `list` | — | filesystem (`~/.aa/config.yaml`) | prints `<name>[ *]  <url>[ (key set)]` per line; empty config → "No contexts configured." |
//! | `set` | `<NAME> --api-url <U> [--api-key <K>]` | filesystem | first inserted context becomes default; re-`set` of an existing name replaces both URL and key |
//! | `use` | `<NAME>` | filesystem | switches default; non-zero exit when name absent |

mod common;

use common::cli::CliFixture;
use tempfile::TempDir;

// ============================================================================
// aasm context list
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn context_list_empty_prints_helpful_message() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let home = TempDir::new().expect("tempdir for HOME");

    let out = fixture
        .cmd()
        .env("HOME", home.path())
        .args(["context", "list"])
        .output()
        .expect("aasm context list should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No contexts configured"),
        "empty list should print helpful message; got:\n{stdout}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn context_list_with_two_contexts_shows_both_names_and_urls() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let home = TempDir::new().expect("tempdir for HOME");

    // Seed via the CLI itself — exercises real `set` writes.
    for (name, url) in [
        ("prod", "https://prod.example.com"),
        ("staging", "https://staging.example.com"),
    ] {
        let out = fixture
            .cmd()
            .env("HOME", home.path())
            .args(["context", "set", name, "--api-url", url])
            .output()
            .expect("aasm context set should execute");
        assert!(out.status.success(), "seed `set {name}` should succeed");
    }

    let out = fixture
        .cmd()
        .env("HOME", home.path())
        .args(["context", "list"])
        .output()
        .expect("aasm context list should execute");
    assert!(out.status.success(), "list should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("prod"), "list missing 'prod' line; got:\n{stdout}");
    assert!(
        stdout.contains("staging"),
        "list missing 'staging' line; got:\n{stdout}"
    );
    assert!(
        stdout.contains("https://prod.example.com"),
        "list missing prod URL; got:\n{stdout}",
    );
    assert!(
        stdout.contains("https://staging.example.com"),
        "list missing staging URL; got:\n{stdout}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn context_list_marks_default_with_asterisk_and_others_without() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let home = TempDir::new().expect("tempdir for HOME");

    // First `set` becomes the default (asserted in detail by
    // `context_set_first_context_becomes_default`); second does not.
    for (name, url) in [("first-default", "http://one:8080"), ("other", "http://two:8080")] {
        let out = fixture
            .cmd()
            .env("HOME", home.path())
            .args(["context", "set", name, "--api-url", url])
            .output()
            .expect("seed set");
        assert!(out.status.success(), "seed `set {name}` should succeed");
    }

    let out = fixture
        .cmd()
        .env("HOME", home.path())
        .args(["context", "list"])
        .output()
        .expect("list");
    assert!(out.status.success(), "list should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);

    let default_line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("first-default"))
        .unwrap_or_else(|| panic!("missing 'first-default' line in:\n{stdout}"));
    assert!(
        default_line.contains(" *"),
        "default context line should contain ' *' marker; got: {default_line:?}",
    );
    let other_line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("other"))
        .unwrap_or_else(|| panic!("missing 'other' line in:\n{stdout}"));
    assert!(
        !other_line.contains(" *"),
        "non-default context line should not have ' *' marker; got: {other_line:?}",
    );
}
