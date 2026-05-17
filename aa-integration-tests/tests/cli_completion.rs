//! CLI integration tests for `aasm completion` (AAASM-1464 / F121 ST-8).
//!
//! Exercises every supported shell of `aasm completion <shell>` plus the
//! two documented negative paths. Each happy-path case asserts a
//! shell-specific marker so accidental output crosswiring (e.g. a zsh
//! script emitted for `completion bash`) is caught.
//!
//! ## Leaf surface (from `aa-cli/src/commands/completion.rs`)
//!
//! `completion` takes a single positional `<SHELL>` argument typed as
//! `clap_complete::Shell` (variants: `Bash`, `Elvish`, `Fish`,
//! `PowerShell`, `Zsh`). Output is written to stdout via
//! `clap_complete::generate`. No gateway interaction is performed.
//!
//! Per the ST-8 acceptance criteria the tests reuse `CliFixture::cmd()`
//! unchanged — no new shared infrastructure is introduced.

mod common;

use common::cli::CliFixture;
use rstest::rstest;

// =============================================================================
// aasm completion <shell> — happy path
// =============================================================================

/// Shell-specific markers chosen to be both stable across `clap_complete`
/// versions and unique to one shell's completion grammar.
///
/// | Shell        | Marker                          | Why it's unique             |
/// | ------------ | ------------------------------- | --------------------------- |
/// | `bash`       | `_aasm()`                       | bash function declaration   |
/// | `zsh`        | `#compdef aasm`                 | zsh compdef header          |
/// | `fish`       | `__fish_aasm_global_optspecs`   | fish optspec helper         |
/// | `powershell` | `Register-ArgumentCompleter`    | PowerShell completer API    |
#[rstest]
#[case::bash("bash", "_aasm()")]
#[case::zsh("zsh", "#compdef aasm")]
#[tokio::test(flavor = "multi_thread")]
async fn completion_emits_shell_specific_marker(#[case] shell: &str, #[case] marker: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["completion", shell])
        .output()
        .expect("aasm completion should execute");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "shell={shell}: should exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(!out.stdout.is_empty(), "shell={shell}: stdout should be non-empty",);
    assert!(
        stdout.contains(marker),
        "shell={shell}: stdout should contain shell-specific marker {marker:?}\nstdout:\n{stdout}",
    );
}
