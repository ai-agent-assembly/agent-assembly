//! The live `aasm run` isolation matrix (AAASM-6296, QA ST-9, journey J88):
//! `--isolation {auto,process,none}` x `--isolation-backend {-,sandlock,
//! aasm-native,aasm-macos-vm}` x a policy requiring {fs-write, network,
//! syscall} prevention, driven through the REAL compiled `aasm` binary.
//!
//! # The invariant (one assertion per cell)
//!
//! Every cell must either **name the backend it selected** or **refuse with a
//! reason**. The failing shape is a third outcome: a launch that says nothing
//! about a boundary it was asked for. A refusal is asserted on its *effect*
//! (the program did not run: the file it would create is absent) and not only
//! on a message, using the same technique as `run_isolation.rs`.
//!
//! # What this host can and cannot show
//!
//! Which cells *select* depends on the host (Linux Landlock for sandlock/native,
//! a provisioned VM substrate for macos-vm). The assertions are therefore
//! host-conditional on the *preview*: if the preview reports a boundary the
//! test accepts it only when a real backend id is named as the selected one; if
//! it reports a refusal the live launch must refuse too and run nothing. On a
//! host where every backend is unavailable (macOS without the VM substrate)
//! every confining cell is a refusal and the positive "selected" arm is not
//! exercised: that arm is covered, on real reporting logic, by
//! `planner_real_backend_matrix.rs`, and on a real kernel only by the Linux lane.

use std::path::{Path, PathBuf};
use std::process::Output;

const BACKENDS: [&str; 3] = [
    aa_isolation_sandlock::BACKEND_ID,
    aa_isolation_native::BACKEND_ID,
    aa_isolation_macos_vm::BACKEND_ID,
];

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "aa-planner-matrix-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&root).expect("scratch directory");
        Self { root }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The three policy shapes, each stating exactly one domain a backend must
/// prevent. Every one carries the tool rule a launch needs to start at all.
fn policy_for(scratch: &Scratch, domain: &str) -> PathBuf {
    let body = match domain {
        "fs-write" => "  capabilities:\n    deny:\n      - file_write\n",
        "network" => "  capabilities:\n    deny:\n      - network_outbound\n",
        "syscall" => "  syscalls:\n    allow:\n      - read\n",
        other => panic!("unknown domain {other}"),
    };
    let path = scratch.root.join(format!("{domain}.yaml"));
    std::fs::write(
        &path,
        format!("apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: {domain}\nspec:\n  tools:\n    bash:\n      allow: true\n{body}"),
    )
    .expect("write policy");
    path
}

fn state_dir(scratch: &Scratch) -> PathBuf {
    let dir = scratch.root.join("state");
    std::fs::create_dir_all(&dir).expect("state dir");
    dir
}

fn aasm(scratch: &Scratch, policy: &Path, intent: &str, backend: Option<&str>, dry_run: bool, argv: &[&str]) -> Output {
    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    cmd.env("AASM_STATE_DIR", state_dir(scratch))
        .arg("run")
        .arg("exec")
        .arg("--no-proxy")
        .arg("--policy")
        .arg(policy)
        .arg("--isolation")
        .arg(intent);
    if let Some(backend) = backend {
        cmd.arg("--isolation-backend").arg(backend);
    }
    if dry_run {
        cmd.arg("--dry-run");
    }
    cmd.arg("--").args(argv);
    cmd.output().expect("spawn aasm")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The line starting with `key:` in the rendered report, trimmed.
fn report_line<'a>(printed: &'a str, key: &str) -> Option<&'a str> {
    printed.lines().find_map(|l| l.strip_prefix(key).map(str::trim_start))
}

/// What a preview of a cell reported.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// A boundary would be established and this backend is named as the one.
    Selected(String),
    /// The launch would refuse, with a stated reason.
    Refused,
}

fn classify(printed: &str, cell: &str) -> Outcome {
    let refused = printed.contains("a live `aasm run` with these flags would refuse to launch")
        || printed.contains("refusing to launch");
    let no_boundary = report_line(printed, "posture:").is_some_and(|p| p.starts_with("NO BOUNDARY ESTABLISHED"));
    let backend_line = report_line(printed, "backend:").unwrap_or_default();
    let named = BACKENDS.iter().find(|id| backend_line.contains(**id));

    match (refused, named) {
        (true, None) => {
            assert!(
                no_boundary,
                "{cell}: a refusal must leave the report at NO BOUNDARY ESTABLISHED:\n{printed}"
            );
            assert!(
                printed.contains("There is no fallback") || printed.contains("names a backend"),
                "{cell}: a refusal must carry its reason:\n{printed}"
            );
            Outcome::Refused
        }
        (false, Some(id)) => {
            assert!(
                !no_boundary,
                "{cell}: a named backend with no boundary is a contradiction:\n{printed}"
            );
            Outcome::Selected((*id).to_string())
        }
        (refused, named) => panic!(
            "{cell}: neither a clear selection nor a clear refusal (refused={refused}, named={named:?}) -- \
             a silent downgrade would look exactly like this:\n{printed}"
        ),
    }
}

/// Every confining cell either names its backend or refuses; a refusal in the
/// preview is a refusal live, with the program not run.
#[test]
fn every_confining_cell_names_its_backend_or_refuses_and_runs_nothing() {
    let scratch = Scratch::new("matrix");
    let mut cells = 0;
    let mut refused = 0;
    let mut selected = 0;

    for intent in ["auto", "process"] {
        for backend in [None, Some(BACKENDS[0]), Some(BACKENDS[1]), Some(BACKENDS[2])] {
            for domain in ["fs-write", "network", "syscall"] {
                let cell = format!("--isolation {intent} --isolation-backend {backend:?} policy={domain}");
                let policy = policy_for(&scratch, domain);

                let preview = aasm(&scratch, &policy, intent, backend, true, &["/bin/echo", "hi"]);
                let outcome = classify(&text(&preview), &cell);
                cells += 1;

                match outcome {
                    Outcome::Selected(id) => {
                        selected += 1;
                        // A pin must be the backend that was selected.
                        if let Some(pinned) = backend {
                            assert_eq!(id, pinned, "{cell}: a pin was replaced by another backend");
                        }
                    }
                    Outcome::Refused => {
                        refused += 1;
                        let target = scratch
                            .root
                            .join(format!("ran-{intent}-{}-{domain}", backend.unwrap_or("auto")));
                        let live = aasm(
                            &scratch,
                            &policy,
                            intent,
                            backend,
                            false,
                            &["/bin/sh", "-c", &format!("printf x > {}", target.display())],
                        );
                        assert!(
                            !live.status.success(),
                            "{cell}: the preview said refuse but the live launch succeeded"
                        );
                        // The isolation reason specifically: a launch can also stop
                        // for an unrelated reason (no gateway is running in this
                        // suite), and "refusing to launch unregistered" must not be
                        // able to stand in for the planner's own refusal.
                        let live_text = text(&live);
                        assert!(
                            live_text.contains("There is no fallback") || live_text.contains("names a backend"),
                            "{cell}: the live refusal is not the isolation planner's own:\n{live_text}"
                        );
                        assert!(
                            !target.exists(),
                            "{cell}: the program ran unconfined: {}",
                            target.display()
                        );
                    }
                }
            }
        }
    }

    assert_eq!(cells, 24);
    assert_eq!(selected + refused, cells);
    println!(
        "planner matrix: {cells} confining cells, {selected} selected a named backend, {refused} refused with a reason"
    );
}

/// `--isolation none` states that no boundary exists rather than leaving it to
/// be inferred, and naming a backend with it is a contradiction that refuses.
#[test]
fn isolation_none_states_it_and_a_named_backend_with_it_refuses() {
    let scratch = Scratch::new("none");
    for domain in ["fs-write", "network", "syscall"] {
        let policy = policy_for(&scratch, domain);

        let preview = text(&aasm(&scratch, &policy, "none", None, true, &["/bin/echo", "hi"]));
        assert!(preview.contains("NO BOUNDARY ESTABLISHED"), "{domain}: {preview}");
        assert!(
            preview.contains("no execution-isolation boundary was requested"),
            "{domain}: `none` must state that it requested no boundary:\n{preview}"
        );
        assert!(
            BACKENDS
                .iter()
                .all(|id| !report_line(&preview, "backend:").unwrap_or_default().contains(*id)),
            "{domain}: `none` must not name a backend:\n{preview}"
        );

        for backend in BACKENDS {
            let preview = text(&aasm(
                &scratch,
                &policy,
                "none",
                Some(backend),
                true,
                &["/bin/echo", "hi"],
            ));
            assert!(preview.contains("names a backend"), "{domain}/{backend}: {preview}");
        }
    }
}

/// The same request against the same host selects/refuses identically on
/// every run, and a recorded automatic walk names every candidate it looked at.
#[test]
fn the_automatic_choice_is_deterministic_and_its_reasoning_is_in_the_receipt() {
    let scratch = Scratch::new("determinism");
    let policy = policy_for(&scratch, "fs-write");

    let walk_lines = |printed: &str| -> Vec<String> {
        printed
            .lines()
            .filter(|l| l.starts_with("backend_selection") || l.trim_start().starts_with("considered:"))
            .map(str::to_string)
            .collect()
    };

    let first = text(&aasm(&scratch, &policy, "auto", None, true, &["/bin/echo", "hi"]));
    let first_walk = walk_lines(&first);
    assert!(first.contains("backend_selection_mode=automatic"), "{first}");
    assert!(
        first.contains("backend_selection.considered_count="),
        "the selection must be in the receipt:\n{first}"
    );
    assert!(!first_walk.is_empty());
    for _ in 0..3 {
        let again = text(&aasm(&scratch, &policy, "auto", None, true, &["/bin/echo", "hi"]));
        assert_eq!(
            walk_lines(&again),
            first_walk,
            "the automatic walk changed between identical runs"
        );
        assert_eq!(classify(&again, "rerun"), classify(&first, "first"));
    }
}
