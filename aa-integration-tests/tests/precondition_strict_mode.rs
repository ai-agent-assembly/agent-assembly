//! Regression coverage for `common::precondition::require` itself
//! (AAASM-5977 AC3).
//!
//! The mechanism this guards is invisible by construction — an unmet
//! precondition either quietly returns `false` or panics, and both outcomes
//! look, from outside, like "the test didn't do much". So this doesn't assert
//! on `require`'s return value directly; it re-execs this same test binary
//! with one environment variable moved and checks the *process outcome* of
//! each arm — a control that moves with the variable under test, not two
//! hand-written constants cross-checking (see AAASM-5977's own falsification
//! requirement: the reverted mechanism must be shown going red).

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::precondition::REQUIRE_ENV;

/// Not a real test — a probe re-exec'd by
/// [`strict_mode_turns_an_unmet_precondition_red`] below. `#[ignore]` keeps
/// it out of a normal `cargo nextest run`; the mechanism test runs just this
/// one via `--exact --ignored`.
///
/// The precondition is forced unmet with a literal `Err` rather than calling
/// a real guard (e.g. `cli_gateway`'s `gateway_binary_available`) — on the
/// machine the AAASM-5977 CI provisioning fix builds the gateway, that real
/// guard would be *met*, both arms below would exit 0, and this test would
/// assert nothing.
#[test]
#[ignore]
fn probe_forced_unmet_precondition() {
    common::precondition::require("probe", Err("forced unmet".to_string()));
}

/// AC3: strict mode turns an unmet precondition into a failing test; without
/// it, the identical unmet precondition is a clean pass. Reverting
/// `require` to unconditionally return `false` (the pre-AAASM-5977 shape)
/// makes the first assertion below fail — this is the negative control the
/// ticket's falsification requirement asks for, expressed as a moved
/// variable rather than a manual revert-and-observe step.
#[test]
fn strict_mode_turns_an_unmet_precondition_red() {
    let exe = std::env::current_exe().expect("nextest test binaries are libtest-compatible executables");
    let args = ["--exact", "probe_forced_unmet_precondition", "--ignored", "--nocapture"];

    // Positive: strict mode arms the panic.
    let strict = Command::new(&exe)
        .args(args)
        .env(REQUIRE_ENV, "1")
        .output()
        .expect("run probe (strict)");
    assert!(
        !strict.status.success(),
        "strict mode must not let an unmet precondition pass cleanly; stdout={}",
        String::from_utf8_lossy(&strict.stdout)
    );
    let strict_out = format!(
        "{}{}",
        String::from_utf8_lossy(&strict.stdout),
        String::from_utf8_lossy(&strict.stderr)
    );
    assert!(
        strict_out.contains("forced unmet"),
        "strict-mode failure should name the precondition reason; got: {strict_out}"
    );

    // Negative control: the SAME binary, the SAME forced-unmet precondition,
    // one variable moved. `env_remove` is load-bearing — in a strict CI lane
    // the parent process already has REQUIRE_ENV set and the child would
    // inherit it, so without this both arms are the positive arm and the
    // control can never go red.
    let lax = Command::new(&exe)
        .args(args)
        .env_remove(REQUIRE_ENV)
        .output()
        .expect("run probe (lax)");
    assert!(
        lax.status.success(),
        "without strict mode the same unmet precondition must be a clean pass (today's dev-machine behaviour); stderr={}",
        String::from_utf8_lossy(&lax.stderr)
    );
    let lax_out = format!(
        "{}{}",
        String::from_utf8_lossy(&lax.stdout),
        String::from_utf8_lossy(&lax.stderr)
    );
    assert!(
        lax_out.contains("SKIP ["),
        "the lax arm should still print the skip line; got: {lax_out}"
    );
}

/// Closes the propagation hole: if `AA_REQUIRE_PRECONDITIONS` silently failed
/// to reach the integration-tests lane (a workflow edit that drops the env
/// block, for instance), strict mode degrades to today's graceful-skip
/// behaviour and the lane stays green — exactly the invisibility AAASM-5977
/// exists to remove. `GITHUB_WORKFLOW` is stamped by GitHub itself from the
/// workflow's `name:` field, not by the step's own `env:` block, so whatever
/// deletion breaks the env var propagation cannot also delete this signal.
///
/// Name verified distinct from the other workflows that also run this crate's
/// tests: `ci.yml` names its workflow "CI", `claude-code-conformance.yml`
/// names its "Claude Code conformance" — neither collides with
/// `integration-tests.yml`'s "Integration tests", so this must not fire
/// there.
#[test]
fn the_integration_lane_arms_the_strict_gate() {
    if std::env::var("GITHUB_WORKFLOW").as_deref() == Ok("Integration tests") {
        assert!(
            std::env::var_os(REQUIRE_ENV).is_some(),
            "the integration-tests.yml lane must set {REQUIRE_ENV}=1 (AAASM-5977) — \
             without it, every precondition-gated test in this lane degrades to a \
             silent skip-as-pass, which is the exact invisibility this ticket exists to remove"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// AAASM-6224 — the population gate.
//
// AAASM-5977 built the mechanism above and then reached only part of the
// tree: 15 guard sites went on printing a bare `eprintln!` and returning
// early, so arming `REQUIRE_ENV` could not touch them. Nothing noticed,
// because a skip-shaped early `return` from a `#[test]` fn is a PASS and
// nextest suppresses captured output for passing tests — the bypass count
// could grow indefinitely without a single red check.
//
// So the count is asserted from source. Every skip-shaped `eprintln!` in this
// crate's test tree must either be gone (routed through
// `common::precondition`) or be named below with the reason it is allowed to
// stay. The list is deliberately short and deliberately awkward to extend.
// ───────────────────────────────────────────────────────────────────────────

/// A skip-shaped `eprintln!` that legitimately does not route through
/// `common::precondition`, and why.
struct AllowedBypass {
    /// Path relative to `aa-integration-tests/tests/`.
    file: &'static str,
    /// Distinctive substring of the message. Keyed on text rather than a line
    /// number so an unrelated edit above it does not fail this gate.
    marker: &'static str,
    /// Why `require` would be the wrong call here.
    why: &'static str,
}

/// The exhaustive list, as of AAASM-6224.
///
/// Every entry has the same shape of reason: the integration lane does **not**
/// provision the capability being probed, so `require` — which panics under
/// `REQUIRE_ENV` — would redden the lane for something no CI configuration
/// change in this repository can satisfy. That is the one and only justification
/// this list accepts. "The test is awkward to provision" is not one; neither is
/// "converting it would go red", which is the finding, not the excuse.
///
/// These are still weaker than a real assertion. They are tracked in
/// AAASM-6228 rather than declared acceptable — a named ticket, so the claim is
/// checkable from here instead of taken on trust.
const ALLOWED_BYPASSES: &[AllowedBypass] = &[
    AllowedBypass {
        file: "cli_dashboard.rs",
        marker: "no /assets/*.js reference in served index",
        why: "skips one assertion inside a test that still asserts the rest; needs a \
              real `pnpm build` of dashboard/, which this lane does not run",
    },
    AllowedBypass {
        file: "cli_proxy.rs",
        marker: "aa-proxy resolvable via `which`",
        why: "inverted guard — the scenario is 'aa-proxy is NOT resolvable', so a host \
              where it IS resolvable cannot run it at all",
    },
    AllowedBypass {
        file: "cli_proxy.rs",
        marker: "build exists beside the aasm executable",
        why: "same inverted guard as above, via the sibling-binary resolution path",
    },
    AllowedBypass {
        file: "cli_proxy.rs",
        marker: "proxy_start_with_unreachable_gateway_still_boots: skipping",
        why: "`aasm proxy start` needs the macOS CA trust store, which needs admin; the \
              two fully-blocked cases in this file are already `#[ignore]` for the same reason",
    },
    AllowedBypass {
        file: "cli_proxy.rs",
        marker: "proxy_start_spawns_proxy_and_writes_pid_file: skipping",
        why: "same admin-gated CA trust store",
    },
    AllowedBypass {
        file: "cli_proxy_remote_bind_refusal.rs",
        marker: "an_explicit_loopback_listen_address_still_starts: skipping",
        why: "same admin-gated CA trust store, and this one already re-raises the single \
              failure that is never environmental before declining",
    },
];

/// Parse the string literal that a macro's format argument opens with, if it
/// opens with one at all.
///
/// Handles the plain form and Rust's raw forms (`r"…"`, `r#"…"#`). The raw
/// forms are covered not because this tree uses them but because a gate whose
/// job is completeness must not have a shape that walks straight past it — the
/// same message in a raw literal is the same defect wearing different quotes.
/// Returns `None` when the first argument is not a literal (a variable, a
/// `format!`, a `concat!`) — those are not the skip-message shape.
///
/// Deliberately not bounded by a search for `;` or `)`: both occur inside these
/// messages, and the first attempt at this function truncated the
/// `cli_dashboard.rs` message at the `;` in "build.rs stub; skipping", so the
/// word the scanner was looking for fell outside what it read and the site went
/// undetected. A literal terminates itself; nothing else needs to.
fn leading_string_literal(after_open_paren: &str) -> Option<String> {
    let s = after_open_paren.trim_start();
    let (body, terminator) = if let Some(rest) = s.strip_prefix('"') {
        (rest, String::from("\""))
    } else {
        // `?` rather than an `else if let` + `else return None`: clippy's
        // `question_mark` lint rejects the latter, and the lane runs
        // `--all-targets --all-features -- -D warnings`.
        let rest = s.strip_prefix('r')?;
        let hashes = rest.len() - rest.trim_start_matches('#').len();
        let rest = rest[hashes..].strip_prefix('"')?;
        (rest, format!("\"{}", "#".repeat(hashes)))
    };

    if terminator != "\"" {
        // Raw literal: no escapes, so the first terminator ends it.
        return Some(body[..body.find(&terminator)?].to_string());
    }

    let mut literal = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(literal),
            '\\' => match chars.next() {
                // Collapse Rust's `\`-newline continuation so a word split
                // across two source lines is still matched.
                Some('\n') => {
                    for c in chars.by_ref() {
                        if !c.is_whitespace() {
                            literal.push(c);
                            break;
                        }
                    }
                }
                Some(other) => literal.push(other),
                None => break,
            },
            other => literal.push(other),
        }
    }
    None
}

/// Extract every `eprintln!` in `dir` whose first string literal mentions
/// "skip".
///
/// Hand-written rather than regex-driven on purpose: the shapes in this tree
/// span multiple lines and use `\`-continuations, and this repo's `grep` is
/// ugrep, which silently drops matches on patterns with several optional
/// groups. A tiny scanner that is wrong loudly beats a pattern that is wrong
/// quietly.
fn skip_shaped_eprintln_sites(dir: &Path) -> Vec<(String, usize, String)> {
    fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    let mut files = Vec::new();
    rs_files(dir, &mut files);
    files.sort();

    let mut sites = Vec::new();
    for file in files {
        // The mechanism's own `SKIP [...]` line lives here. Excluding the file
        // that *implements* the ledger is not a loophole: it has no early
        // `return` to hide behind, and a bypass added here would still have to
        // be called from somewhere this gate does scan.
        if file.ends_with("common/precondition.rs") {
            continue;
        }
        let src = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        let rel = file
            .strip_prefix(dir)
            .expect("file is under the tests dir")
            .to_string_lossy()
            .to_string();

        for (offset, _) in src.match_indices("eprintln!(") {
            let after = &src[offset + "eprintln!(".len()..];
            let Some(literal) = leading_string_literal(after) else {
                continue;
            };
            if literal.to_lowercase().contains("skip") {
                let line = src[..offset].matches('\n').count() + 1;
                sites.push((rel.clone(), line, literal));
            }
        }
    }
    sites
}

/// AAASM-6224 AC6: the set of skip-shaped guards that bypass
/// `common::precondition` is exactly [`ALLOWED_BYPASSES`] — no additions, no
/// stale entries.
///
/// Additions fail because a new bypass is a new test that can report PASS while
/// asserting nothing, which is this ticket's entire defect. Stale entries fail
/// because a list that outlives the code it describes stops being read, and
/// then stops being true — which is how the `REQUIRE_ENV` doc comment came to
/// claim the lane built every binary its guards checked for.
#[test]
fn every_skip_shaped_guard_is_accounted_for() {
    let tests_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let sites = skip_shaped_eprintln_sites(&tests_dir);

    let mut unaccounted = Vec::new();
    for (file, line, literal) in &sites {
        let allowed = ALLOWED_BYPASSES
            .iter()
            .any(|a| file == a.file && literal.contains(a.marker));
        if !allowed {
            unaccounted.push(format!("{file}:{line}: {literal}"));
        }
    }
    assert!(
        unaccounted.is_empty(),
        "these skip-shaped guards neither route through `common::precondition::require` \
         nor appear in ALLOWED_BYPASSES.\n\n\
         An `eprintln!` plus an early `return` from a `#[test]` fn is reported as a PASS, \
         and nextest suppresses captured output for passing tests — so this shape is a test \
         that asserts nothing and says nothing about it (AAASM-6224).\n\n\
         Route it through `common::precondition::require`, or — only if the integration lane \
         genuinely cannot provision the capability — add it to ALLOWED_BYPASSES with the \
         reason.\n\n{}",
        unaccounted.join("\n")
    );

    let stale: Vec<&str> = ALLOWED_BYPASSES
        .iter()
        .filter(|a| {
            !sites
                .iter()
                .any(|(file, _, literal)| file == a.file && literal.contains(a.marker))
        })
        .map(|a| a.marker)
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWED_BYPASSES names guards that no longer exist — delete the entries rather than \
         leaving a list that describes code that is gone: {stale:?}"
    );

    // Guards the scanner itself: if it silently stopped matching anything (a
    // wrong path, a parsing regression) both assertions above would pass
    // vacuously and the gate would be decorative.
    assert_eq!(
        sites.len(),
        ALLOWED_BYPASSES.len(),
        "expected exactly {} accounted-for sites, found {} — the scanner is not reading what \
         it thinks it is reading: {sites:#?}",
        ALLOWED_BYPASSES.len(),
        sites.len()
    );

    for a in ALLOWED_BYPASSES {
        assert!(
            !a.why.trim().is_empty(),
            "every ALLOWED_BYPASSES entry needs a reason: {}",
            a.marker
        );
    }
}
