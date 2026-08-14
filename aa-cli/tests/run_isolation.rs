//! `aasm run --isolation` — the host-independent half (AAASM-5711).
//!
//! Everything here holds on any host, because none of it needs a backend that
//! can actually confine something. The measurements that need one live in
//! `run_isolation_linux.rs`, which declines loudly when the host cannot provide
//! it.
//!
//! # The two properties this file exists to pin
//!
//! **The policy seam is closed.** Before this ticket nothing in the run path
//! constructed the canonical policy AST, so no isolation requirement could be
//! sourced from an effective policy *at all* and the AAASM-5710 report rendered
//! every domain `not_derived`. That reads far more benign than "no policy source
//! exists", which is why it is asserted rather than assumed.
//! [`a_capability_denial_becomes_a_lowered_requirement_in_the_resolved_plan`] is
//! the control, and it is a pair: the same launch under a policy that states no
//! filesystem restriction reports `not_stated` for the same domain, so the
//! assertion is about the *denial* crossing rather than about the field being
//! populated by anything at all. Delete the `canonical` retention from
//! `aa_policy::PolicyResolution` and this test goes red.
//!
//! **There is no silent unconfined fallback.** Every refusal test asserts on an
//! *effect* — a file the child would have created and did not — and not merely
//! on an error being returned. A launch that quietly ran the program outside the
//! boundary would return the same error shape and leave the file behind.

use std::path::{Path, PathBuf};

use aa_cli::commands::run::{execute_with_adapters, IsolationIntent, RunArgs};
use aa_core::DevToolAdapter;

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// A scratch directory that removes itself.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        // Digits and dashes only. The paths below are interpolated into a
        // shell redirection, and a directory name carrying a space or a brace
        // would break the command rather than the boundary — which would make
        // "the file is absent" mean nothing at all.
        let root = std::env::temp_dir().join(format!(
            "aa-run-isolation-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&root).expect("scratch directory");
        Self { root }
    }

    /// A path inside the scratch tree that nothing has created yet.
    fn target(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Write a policy artifact and return its path.
///
/// Pinned with `--policy` on every launch below, so a developer machine that
/// happens to have `~/.aasm/policy.yaml` installed cannot change what these
/// measure.
fn policy(scratch: &Scratch, name: &str, spec: &str) -> PathBuf {
    let path = scratch.root.join(name);
    std::fs::write(
        &path,
        format!(
            "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: {name}\nspec:\n{spec}",
            name = name.trim_end_matches(".yaml"),
        ),
    )
    .expect("write policy");
    path
}

/// A policy whose only content is a tool rule.
///
/// The control artifact: it launches (a launch refuses without at least one tool
/// rule, AAASM-5349) and states nothing at all about the filesystem, so every
/// filesystem domain must come back `not_stated`.
const TOOL_RULE_ONLY: &str = "  tools:\n    bash:\n      allow: true\n";

/// The same artifact plus a whole-domain write denial.
const TOOL_RULE_AND_WRITE_DENIAL: &str =
    "  tools:\n    bash:\n      allow: true\n  capabilities:\n    deny:\n      - file_write\n";

/// `aasm run exec -- <argv>` with the flags every test here shares.
///
/// `--no-proxy` because these measure the execution boundary, not proxy trust;
/// without it a launch refuses unless a verified proxy is running on this host.
fn exec_args(policy: &Path, argv: &[&str]) -> RunArgs {
    RunArgs {
        tool: "exec".into(),
        tool_args: argv.iter().map(|a| (*a).to_string()).collect(),
        agent_id: None,
        team_id: None,
        root_agent: None,
        governance_level: None,
        no_proxy: true,
        policy: Some(policy.to_path_buf()),
        workdir: None,
        dry_run: false,
        enforcement_mode: None,
        observe: false,
        isolation: IsolationIntent::None,
        isolation_backend: None,
    }
}

/// A shell command whose whole observable effect is creating `target`.
fn creates(target: &Path) -> String {
    // Never `2>/dev/null` here: under a default-deny boundary the null device is
    // opened for writing and the redirection itself is denied, which turns every
    // confined run into a spurious decline.
    format!("printf x > {}", target.display())
}

/// Run `aasm run` with no adapters registered, returning the command's result.
fn run(args: &RunArgs) -> anyhow::Result<i32> {
    let adapters: std::collections::HashMap<&str, Box<dyn DevToolAdapter>> = std::collections::HashMap::new();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(execute_with_adapters(args, &adapters))
}

/// The `--dry-run` receipt for `args`, as the operator sees it.
///
/// Driven through the real binary rather than through `dry_run_preview`, because
/// the claim is about what an operator reads and the receipt is printed rather
/// than returned.
fn receipt(policy: &Path, extra: &[&str]) -> String {
    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    cmd.arg("run")
        .arg("exec")
        .arg("--dry-run")
        .arg("--no-proxy")
        .arg("--policy")
        .arg(policy);
    for flag in extra {
        cmd.arg(flag);
    }
    let output = cmd.arg("--").arg("/bin/echo").arg("hi").output().expect("aasm run");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// ---------------------------------------------------------------------------
// The policy seam.
// ---------------------------------------------------------------------------

/// **The negative control for the AAASM-5711 policy seam.**
///
/// A `capabilities.deny: [file_write]` entry is invisible in the projection a
/// dev-tool adapter receives — `aa_policy::resolve::project_rules` keeps only the
/// `tools:` dimension — so before this ticket it could not reach
/// `aa_isolation::lower_policy` and the domain reported `not_derived`.
///
/// The control is the pair. The same launch under an artifact that says nothing
/// about the filesystem must report `not_stated` for the identical domain, which
/// is a *third* value: the schema has a node and the operator left it unset. If
/// the retention is removed, both halves collapse to `not_derived` and this
/// fails on the first assertion.
#[test]
fn a_capability_denial_becomes_a_lowered_requirement_in_the_resolved_plan() {
    let scratch = Scratch::new("seam");
    let denying = policy(&scratch, "denying.yaml", TOOL_RULE_AND_WRITE_DENIAL);
    let plain = policy(&scratch, "plain.yaml", TOOL_RULE_ONLY);

    let stated = receipt(&denying, &[]);
    assert!(
        stated.contains("domain.filesystem_write.requested=stated"),
        "a policy denying file_write lowered to no filesystem_write requirement — the run path is not \
         reading the canonical projection.\n{stated}"
    );

    let control = receipt(&plain, &[]);
    assert!(
        control.contains("domain.filesystem_write.requested=not_stated"),
        "the control artifact states nothing about the filesystem and must report not_stated, which is a \
         different value from both `stated` and `not_derived`.\n{control}"
    );
    assert!(
        !control.contains("domain.filesystem_write.requested=stated"),
        "the control reported a requirement nobody wrote.\n{control}"
    );
}

/// A domain the schema cannot express must never render as "no restriction
/// required", on either artifact.
///
/// `PolicyCannotExpress` and `NotStated` are the pair that must not collapse:
/// one has a policy line to write and the other does not, and an operator who
/// cannot tell them apart will believe a boundary is complete when four of its
/// nine domains cannot be asked about at all.
#[test]
fn the_domains_the_schema_cannot_reach_are_named_rather_than_left_blank() {
    let scratch = Scratch::new("unrepresentable");
    let artifact = policy(&scratch, "denying.yaml", TOOL_RULE_AND_WRITE_DENIAL);
    let printed = receipt(&artifact, &[]);

    for domain in ["name_resolution", "ipc", "credential", "resource"] {
        assert!(
            printed.contains(&format!("domain.{domain}.requested=policy_cannot_express")),
            "{domain} must be reported as unrepresentable, not as an absent requirement.\n{printed}"
        );
    }
    // The control, in the same receipt: a domain the schema *can* reach reports
    // one of the other two values, so the assertion above is about these four
    // domains rather than about every domain carrying the same token.
    assert!(
        printed.contains("domain.filesystem_write.requested=stated"),
        "{printed}"
    );
}

// ---------------------------------------------------------------------------
// Backward compatibility.
// ---------------------------------------------------------------------------

/// The default is no boundary, it says so, and the launch is otherwise the
/// launch it always was.
///
/// The posture line is asserted alongside the exit code because "no boundary"
/// has to be *stated*: a receipt that simply omitted the section would leave a
/// reader to infer the answer from an absence, which is how an unconfined run
/// comes to look governed.
#[test]
fn the_default_establishes_no_boundary_and_says_so() {
    let scratch = Scratch::new("default");
    let artifact = policy(&scratch, "p.yaml", TOOL_RULE_ONLY);
    let printed = receipt(&artifact, &[]);

    assert!(printed.contains("posture=no_boundary"), "{printed}");
    assert!(
        printed.contains("`--isolation none`, the default"),
        "the reason must name the default rather than leaving it to be inferred.\n{printed}"
    );
    assert!(printed.contains("backend_selected=false"), "{printed}");
}

// ---------------------------------------------------------------------------
// No silent unconfined fallback.
// ---------------------------------------------------------------------------

/// An unknown backend id refuses, and the program does not run.
///
/// Host-independent: no build has a backend under this id, so the refusal is a
/// property of selection rather than of the runner. The assertion is on the
/// effect — a fallback that ran the program unconfined would return an error of
/// some other shape and still leave the file behind.
#[test]
fn an_unknown_backend_id_refuses_and_starts_nothing() {
    let scratch = Scratch::new("unknown-backend");
    let artifact = policy(&scratch, "p.yaml", TOOL_RULE_ONLY);
    let target = scratch.target("must-not-exist");

    let mut args = exec_args(&artifact, &["/bin/sh", "-c", &creates(&target)]);
    args.isolation = IsolationIntent::Process;
    args.isolation_backend = Some("no-such-backend".into());

    let error = run(&args).expect_err("an id no backend answers to must refuse");
    assert!(
        error.to_string().contains("no-such-backend"),
        "the refusal must name the id that was asked for: {error}"
    );
    assert!(
        !target.exists(),
        "the program ran even though no backend could be selected: {} exists",
        target.display()
    );

    // The positive control. Without it, "the file is absent" would also be
    // satisfied by a command that never worked — a mistyped path, an unwritable
    // directory or a shell that could not parse the redirection all produce the
    // same absence as a refused launch. The governed baseline needs a gateway to
    // register against and is measured in `run_command.rs`; what is asserted
    // here is that this exact command produces this exact effect when nothing
    // stops it.
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(creates(&target))
        .status()
        .expect("the control command runs");
    assert!(
        status.success() && target.exists(),
        "the control command produced no effect"
    );
}

/// Naming a backend for a launch that asked for no boundary is refused rather
/// than half-honoured, and the program does not run.
///
/// Ignoring one of the two flags would leave an operator believing the other
/// took effect — which, for a flag whose whole purpose is reproducing a result
/// on a named mechanism, means believing a run was confined when it was not.
#[test]
fn a_backend_id_without_an_isolation_intent_refuses_and_starts_nothing() {
    let scratch = Scratch::new("backend-without-intent");
    let artifact = policy(&scratch, "p.yaml", TOOL_RULE_ONLY);
    let target = scratch.target("must-not-exist");

    let mut args = exec_args(&artifact, &["/bin/sh", "-c", &creates(&target)]);
    args.isolation_backend = Some("sandlock".into());

    let error = run(&args).expect_err("a backend id with --isolation none must refuse");
    assert!(
        error.to_string().contains("--isolation-backend"),
        "the refusal must name the flag that contradicts the intent: {error}"
    );
    assert!(!target.exists(), "the program ran: {} exists", target.display());
}

/// A requested boundary on a host that cannot provide one refuses; it never
/// degrades to an unconfined launch.
///
/// Only measurable where the backend is genuinely unavailable, which is every
/// host that is not a Linux box with the mechanism installed. Where it *is*
/// available the scenario has no meaning, so it declines rather than asserting
/// the opposite — `run_isolation_linux.rs` is the suite that measures that side.
#[test]
fn a_requested_boundary_with_no_available_backend_refuses_and_starts_nothing() {
    let backend = aa_isolation_sandlock::SandlockBackend::discover();
    if aa_isolation::IsolationBackend::capabilities(&backend)
        .availability()
        .is_available()
    {
        println!(
            "SKIP [a_requested_boundary_with_no_available_backend_refuses]: this host can select the \
             backend, so there is no unavailable case to measure here; run_isolation_linux.rs measures \
             the available side"
        );
        return;
    }

    let scratch = Scratch::new("unavailable");
    let artifact = policy(&scratch, "p.yaml", TOOL_RULE_ONLY);
    let target = scratch.target("must-not-exist");

    let mut args = exec_args(&artifact, &["/bin/sh", "-c", &creates(&target)]);
    args.isolation = IsolationIntent::Process;

    let error = run(&args).expect_err("a boundary that cannot be built must refuse the launch");
    let text = error.to_string();
    assert!(
        text.contains("There is no fallback"),
        "the refusal must say that no unconfined fallback exists: {text}"
    );
    assert!(
        !target.exists(),
        "the program ran unconfined after the boundary could not be built: {} exists",
        target.display()
    );
}

/// `--dry-run` and the live path agree about the boundary.
///
/// Asserted on the refusal text because that is the case where they could most
/// easily disagree: the preview reports what a live run would do, and a preview
/// that said "would refuse" while the live run launched — or the reverse — is the
/// AAASM-5327 / AAASM-5329 failure in a new field.
#[test]
fn the_preview_and_the_live_path_agree_about_a_boundary_that_cannot_be_built() {
    let backend = aa_isolation_sandlock::SandlockBackend::discover();
    if aa_isolation::IsolationBackend::capabilities(&backend)
        .availability()
        .is_available()
    {
        println!("SKIP [the_preview_and_the_live_path_agree]: this host can select the backend");
        return;
    }

    let scratch = Scratch::new("preview-parity");
    let artifact = policy(&scratch, "p.yaml", TOOL_RULE_ONLY);

    let previewed = receipt(&artifact, &["--isolation", "process"]);
    assert!(
        previewed.contains("a live `aasm run` with these flags would refuse to launch"),
        "{previewed}"
    );

    let mut args = exec_args(&artifact, &["/bin/echo", "hi"]);
    args.isolation = IsolationIntent::Process;
    let live = run(&args).expect_err("the live run refuses").to_string();

    // The same sentence, from both surfaces. Comparing the whole receipt would
    // fail on the minted identity, which legitimately differs.
    assert!(
        previewed.contains("There is no fallback") && live.contains("There is no fallback"),
        "preview:\n{previewed}\nlive:\n{live}"
    );
}
