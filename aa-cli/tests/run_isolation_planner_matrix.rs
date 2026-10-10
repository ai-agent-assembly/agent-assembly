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
//!
//! # What a refusal here does and does NOT show
//!
//! On a host where every backend is `Unavailable` (macOS without the VM
//! substrate) each confining cell refuses because of **host availability**, not
//! because the requested property is unmet: the structured record says
//! `rejected_unavailable` for every candidate and this file asserts exactly that
//! verdict. Property-driven refusal (`rejected_requirements_unmet` naming the
//! demanded domain) is exercised only at planner / `capability::discover` level
//! (`aa-isolation/tests/planner_falsification.rs`,
//! `planner_real_backend_matrix.rs`) on such a host; it is not claimed here.
//! The live launches run in-process against a real gateway (so a launch that is
//! *allowed* actually reaches the program), with a positive control proving the
//! harness can observe the program run.
//!
//! The `--isolation none` positive control establishes **harness observability
//! only**. It is not, and must not be read as, evidence that any confined
//! backend was selected or that confinement works: no confining cell can run
//! on this host. Pinned (`--isolation-backend`) cells have no walk record by
//! design, so their cause is asserted from the pinned backend's own sentence.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Output;

use aa_cli::commands::run::{execute_with_adapters, IsolationIntent, RunArgs};
use aa_core::DevToolAdapter;

mod gateway_support;
use gateway_support::{GatewayEnv, TestGateway};

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

/// Parsed `key=value` machine lines of a preview.
fn machine(printed: &str) -> BTreeMap<String, String> {
    printed
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| k.starts_with("backend_selection") || k.starts_with("posture") || k.starts_with("backend_"))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Whether this host can possibly make `id` available. When false the only
/// legitimate verdict for `id` is `rejected_unavailable`.
fn must_be_unavailable(id: &str) -> bool {
    if id == aa_isolation_macos_vm::BACKEND_ID {
        return ["HELPER", "KERNEL", "ROOTFS"]
            .iter()
            .any(|k| std::env::var(format!("AA_ISOLATION_MACOS_VM_{k}")).is_err());
    }
    !cfg!(target_os = "linux")
}

fn args_for(policy: &Path, intent: IsolationIntent, backend: Option<&str>, argv: &[&str]) -> RunArgs {
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
        workspace_tx: false,
        workspace_tx_exclude: vec![],
        workspace_tx_protect: vec![],
        workspace_tx_approve: false,
        dry_run: false,
        enforcement_mode: None,
        observe: false,
        isolation: intent,
        isolation_backend: backend.map(str::to_string),
        max_memory_bytes: None,
        max_pids: None,
        max_open_files: None,
        max_file_size_bytes: None,
        max_wall_clock_seconds: None,
        max_cpu_seconds: None,
    }
}

/// Drive one live launch in-process against a real gateway, so the only thing
/// that can stop the program is the isolation decision under test.
fn launch(args: &RunArgs) -> anyhow::Result<i32> {
    let adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let gateway = TestGateway::start().await.expect("test gateway");
        let _env = GatewayEnv::point_at(gateway.endpoint());
        execute_with_adapters(args, &adapters).await
    })
}

fn creates(target: &Path) -> String {
    format!("printf x > {}", target.display())
}

fn intent_of(name: &str) -> IsolationIntent {
    match name {
        "auto" => IsolationIntent::Auto,
        "process" => IsolationIntent::Process,
        _ => IsolationIntent::None,
    }
}

/// **Positive control for every "the program did not run" assertion below.**
/// With `--isolation none` the same harness, same gateway, same command and the
/// same policy DOES create the file, so a missing file in a refused cell is
/// attributable to the refusal and not to a broken command, gateway or path.
#[test]
fn the_harness_can_observe_the_program_run_when_launch_is_allowed() {
    let scratch = Scratch::new("positive-control");
    for domain in ["fs-write", "network", "syscall"] {
        let policy = policy_for(&scratch, domain);
        let target = scratch.root.join(format!("control-{domain}"));
        let code = launch(&args_for(
            &policy,
            IsolationIntent::None,
            None,
            &["/bin/sh", "-c", &creates(&target)],
        ))
        .unwrap_or_else(|e| panic!("{domain}: the allowed control launch failed: {e:#}"));
        assert_eq!(code, 0, "{domain}: the control program exited non-zero");
        assert!(
            target.exists(),
            "{domain}: an allowed launch did not create {}; every 'target absent' below would mean nothing",
            target.display()
        );
    }
}

/// Every confining cell: the structured preview says why, and the live launch
/// agrees about whether the program may run.
///
/// * Preview refusal, auto cells: every candidate's verdict is read from the
///   machine record. A candidate this host cannot provide MUST be exactly
///   `rejected_unavailable` with no unmet domain (it is a host fact, not a
///   property verdict); `selected` is accepted only for a candidate the host
///   could provide.
/// * Preview refusal, pinned cells: the refusal is the pinned backend's own
///   unavailability, naming that backend.
/// * Live: a refused cell errors with the same reason and the program does not
///   run (paired with the positive control above). A selected cell is checked
///   live too: it must be the pinned backend if pinned, and under the
///   file-write-denying policy the program must not create the file.
#[test]
fn every_confining_cell_is_decided_by_the_structured_record_and_runs_nothing_when_refused() {
    let scratch = Scratch::new("matrix");
    let (mut cells, mut refused, mut selected) = (0, 0, 0);

    for intent in ["auto", "process"] {
        for backend in [None, Some(BACKENDS[0]), Some(BACKENDS[1]), Some(BACKENDS[2])] {
            for domain in ["fs-write", "network", "syscall"] {
                let cell = format!("--isolation {intent} --isolation-backend {backend:?} policy={domain}");
                let policy = policy_for(&scratch, domain);
                let preview_text = text(&aasm(&scratch, &policy, intent, backend, true, &["/bin/echo", "hi"]));
                let outcome = classify(&preview_text, &cell);
                let m = machine(&preview_text);
                cells += 1;

                // Which backend does the walk's pin/explicit-name resolve to?
                let walk_applies = intent == "auto" && backend.is_none();

                match &outcome {
                    Outcome::Refused => {
                        refused += 1;
                        if walk_applies {
                            assert_eq!(m["backend_selection_mode"], "automatic", "{cell}: {preview_text}");
                            assert_eq!(m["backend_selection.considered_count"], "3", "{cell}: {preview_text}");
                            for (n, id) in BACKENDS.iter().enumerate() {
                                assert_eq!(m[&format!("backend_selection.considered.{n}.id")], *id, "{cell}");
                                let verdict = &m[&format!("backend_selection.considered.{n}.verdict")];
                                assert_ne!(verdict, "selected", "{cell}: a refused walk selected {id}");
                                if verdict == "rejected_requirements_unmet" {
                                    // A property verdict must name the domain the policy demanded.
                                    let demanded = match domain {
                                        "fs-write" => "filesystem_write",
                                        "network" => "network_egress",
                                        _ => "syscall",
                                    };
                                    let count: usize = m
                                        [&format!("backend_selection.considered.{n}.unmet_domain_count")]
                                        .parse()
                                        .expect("count");
                                    assert!(
                                        (0..count)
                                            .any(|g| m[&format!("backend_selection.considered.{n}.unmet_domain.{g}")]
                                                == demanded),
                                        "{cell}: {id} was rejected as unmet but does not name {demanded}"
                                    );
                                }
                                if must_be_unavailable(id) {
                                    assert_eq!(
                                        verdict, "rejected_unavailable",
                                        "{cell}: {id} cannot exist on this host, so its verdict is a host fact"
                                    );
                                    assert_eq!(
                                        m[&format!("backend_selection.considered.{n}.unmet_domain_count")],
                                        "0",
                                        "{cell}: an unavailable candidate must not be blamed on a property"
                                    );
                                    assert!(
                                        m[&format!("backend_selection.considered.{n}.detail")]
                                            .contains("cannot be selected on this host"),
                                        "{cell}: {preview_text}"
                                    );
                                }
                            }
                        } else {
                            let pinned = backend.unwrap_or(aa_isolation_sandlock::BACKEND_ID);
                            if must_be_unavailable(pinned) {
                                assert!(
                                    preview_text
                                        .contains(&format!("the `{pinned}` backend cannot be selected on this host")),
                                    "{cell}: the refusal is not {pinned}'s own unavailability:\n{preview_text}"
                                );
                            }
                        }

                        // Live: same refusal, program does not run.
                        let target = scratch
                            .root
                            .join(format!("ran-{intent}-{}-{domain}", backend.unwrap_or("auto")));
                        let err = launch(&args_for(
                            &policy,
                            intent_of(intent),
                            backend,
                            &["/bin/sh", "-c", &creates(&target)],
                        ))
                        .expect_err(&format!("{cell}: the preview refused but the live launch succeeded"));
                        let live = format!("{err:#}");
                        // The per-candidate / pinned-backend sentence, never the
                        // generic "There is no fallback" footer both refusals share.
                        if walk_applies {
                            for id in BACKENDS {
                                let line = live
                                    .lines()
                                    .find(|l| l.trim_start().starts_with(&format!("- {id}:")))
                                    .unwrap_or_else(|| {
                                        panic!("{cell}: the live refusal has no line for candidate {id}:\n{live}")
                                    });
                                if must_be_unavailable(id) {
                                    assert!(
                                        line.contains("the backend cannot be selected on this host"),
                                        "{cell}: {id} must be refused as unavailable live: {line}"
                                    );
                                }
                            }
                        } else {
                            let pinned = backend.unwrap_or(aa_isolation_sandlock::BACKEND_ID);
                            assert!(
                                live.contains(&format!("the `{pinned}` backend")),
                                "{cell}: the live refusal does not name the pinned backend {pinned}:\n{live}"
                            );
                            if must_be_unavailable(pinned) {
                                assert!(
                                    live.contains(&format!("the `{pinned}` backend cannot be selected on this host")),
                                    "{cell}: {live}"
                                );
                            }
                        }
                        assert!(!target.exists(), "{cell}: the program ran: {}", target.display());
                    }
                    Outcome::Selected(id) => {
                        selected += 1;
                        if let Some(pinned) = backend {
                            assert_eq!(id, pinned, "{cell}: a pin was replaced by another backend");
                        }
                        assert!(
                            !must_be_unavailable(id),
                            "{cell}: selected {id}, which this host cannot provide"
                        );
                        let target = scratch
                            .root
                            .join(format!("sel-{intent}-{}-{domain}", backend.unwrap_or("auto")));
                        let _ = launch(&args_for(
                            &policy,
                            intent_of(intent),
                            backend,
                            &["/bin/sh", "-c", &creates(&target)],
                        ));
                        if domain == "fs-write" {
                            assert!(
                                !target.exists(),
                                "{cell}: {id} was selected for a write-denying policy but the program wrote {}",
                                target.display()
                            );
                        }
                    }
                }
            }
        }
    }

    assert_eq!(cells, 24);
    let all_unavailable = BACKENDS.iter().all(|id| must_be_unavailable(id));
    if all_unavailable {
        assert_eq!(
            (selected, refused),
            (0, 24),
            "no backend exists on this host, so nothing can be selected"
        );
    }
    println!(
        "planner matrix: {cells} confining cells, {selected} selected, {refused} refused; all backends unavailable on this host: {all_unavailable}"
    );
}

/// `--isolation none` states that no boundary exists rather than leaving it to
/// be inferred; live it really launches unconfined (positive proof: the file is
/// created) while the preview says so, and naming a backend with it refuses
/// live with the program not run.
#[test]
fn isolation_none_states_it_launches_unconfined_and_a_named_backend_with_it_refuses() {
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

        let target = scratch.root.join(format!("none-{domain}"));
        launch(&args_for(
            &policy,
            IsolationIntent::None,
            None,
            &["/bin/sh", "-c", &creates(&target)],
        ))
        .unwrap_or_else(|e| panic!("{domain}: `--isolation none` live launch failed: {e:#}"));
        assert!(
            target.exists(),
            "{domain}: the preview said no boundary and the live run must really be unconfined, but {} is missing",
            target.display()
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

            let target = scratch.root.join(format!("none-{domain}-{backend}"));
            let err = launch(&args_for(
                &policy,
                IsolationIntent::None,
                Some(backend),
                &["/bin/sh", "-c", &creates(&target)],
            ))
            .expect_err("`--isolation none` with a named backend must refuse live");
            assert!(
                format!("{err:#}").contains("names a backend"),
                "{domain}/{backend}: {err:#}"
            );
            assert!(
                !target.exists(),
                "{domain}/{backend}: the program ran: {}",
                target.display()
            );
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
