//! Cross-process parent-to-child authority handoff, driven through **real
//! `aasm run` processes** (AAASM-6273, ADR 0038 §27/§29).
//!
//! # What these measure
//!
//! `aasm run exec` inside `aasm run exec` inside `aasm run exec`: three real OS
//! processes, each registering with a real gateway (`gateway_support::TestGateway`),
//! each under its own policy file. The claim is that a descendant gets only what
//! the tree-root `aasm run` that launched it can hand down, as decided in that root
//! by the kernel-established place of the descendant in the tree — never by
//! anything the descendant says.
//!
//! Every adversarial case below is paired with a control that moves with the
//! condition under test: the same invocation shape that is refused is admitted
//! once the single property under test changes (narrower, declared root, socket
//! left in place, no revocation, run as an independent root). A refusal test with
//! no such control would pass for any reason the launch can fail.
//!
//! # What is NOT claimed
//!
//! Every launch here is `--isolation none`, unprivileged, same uid. That is the
//! configuration whose limits are stated in `aa-cli/src/commands/run_supervisor.rs`:
//! the guarantee is about unmodified `aasm run` in an unreparented tree. None of
//! these tests shows containment of an adversarial agent, a double-forked
//! descendant, a patched `aasm`, a pid-namespaced or VM-confined descendant, or
//! ADR 0038 §28/§30 (registry write-protection, the B3 kernel evidence gate).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aa_cli::commands::run_supervisor::{admit, revoke_tree, Endpoint};
use aa_isolation::capability::CapabilityDomain;
use aa_isolation::lease::{CapabilityLease, DelegationRule, LeaseBasis, LeaseId};
use aa_isolation::spec::{ExecutionSpec, IdentityRef, RequirementScope};

mod gateway_support;
use gateway_support::TestGateway;

const AASM: &str = env!("CARGO_BIN_EXE_aasm");
const WAIT: Duration = Duration::from_secs(180);

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The registry directory a tree-root serves from. Mirrors the module under test on
/// purpose: the lookup must depend only on the uid, and this test is what notices
/// if that ever changes.
fn registry_dir() -> PathBuf {
    PathBuf::from("/tmp").join(format!("aa-sup-{}", euid()))
}

/// One scratch tree, one gateway, one set of per-generation policy and state dirs.
struct Fixture {
    dir: PathBuf,
    gateway: TestGateway,
    tag: String,
}

/// What a run of the whole tree produced.
struct Outcome {
    code: Option<i32>,
    stderr: String,
}

impl Fixture {
    async fn new(name: &str) -> Self {
        let tag = format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
                % 1_000_000
        );
        let dir = std::env::temp_dir().join(format!("aasm-tree-{tag}"));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self {
            dir,
            gateway: TestGateway::start().await.expect("start gateway"),
            tag,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn agent(&self, generation: &str) -> String {
        format!("tree-{generation}-{}", self.tag)
    }

    /// A policy that authors `leases` (YAML list items, already indented) or none.
    fn policy(&self, name: &str, leases: Option<&str>) -> PathBuf {
        let authority = leases
            .map(|items| format!("  authority:\n    leases:\n{items}"))
            .unwrap_or_default();
        let path = self.path(&format!("{name}.yaml"));
        std::fs::write(
            &path,
            format!(
                "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: {name}\nspec:\n  tools:\n    bash:\n      allow: false\n{authority}"
            ),
        )
        .expect("write policy");
        path
    }

    /// The leading part of one `aasm run exec` invocation, ending in `--`.
    ///
    /// Each generation gets its own `AASM_STATE_DIR` (its own durable identity key),
    /// set through `env`, which execs rather than forks, so the pid stays the one
    /// the process tree shows.
    fn layer(&self, generation: &str, policy: &Path, extra: &[&str]) -> Vec<String> {
        let state = self.path(&format!("state-{generation}"));
        let mut argv = vec![
            "/usr/bin/env".to_string(),
            format!("AASM_STATE_DIR={}", state.display()),
            AASM.to_string(),
            "run".to_string(),
            "exec".to_string(),
            "--no-proxy".to_string(),
            "--policy".to_string(),
            policy.display().to_string(),
            "--agent-id".to_string(),
            self.agent(generation),
        ];
        argv.extend(extra.iter().map(|s| (*s).to_string()));
        argv.push("--".to_string());
        argv
    }

    /// As [`layer`], but launched through `env -i` with a DIFFERENT home and state
    /// directory and no `--root-agent`: the omission an adversarial or merely
    /// careless descendant could make.
    fn scrubbed_layer(&self, generation: &str, policy: &Path) -> Vec<String> {
        vec![
            "/usr/bin/env".to_string(),
            "-i".to_string(),
            format!("HOME={}", self.path("some-other-home").display()),
            format!(
                "AASM_STATE_DIR={}",
                self.path(&format!("state-other-{generation}")).display()
            ),
            format!("AA_GATEWAY_ENDPOINT={}", self.gateway.endpoint()),
            AASM.to_string(),
            "run".to_string(),
            "exec".to_string(),
            "--no-proxy".to_string(),
            "--policy".to_string(),
            policy.display().to_string(),
            "--agent-id".to_string(),
            self.agent(generation),
            "--".to_string(),
        ]
    }

    /// `touch "$1"` as the innermost program.
    fn marker_tail(&self, marker: &Path) -> Vec<String> {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "touch \"$1\"".to_string(),
            "tree-test".to_string(),
            marker.display().to_string(),
        ]
    }

    fn command(&self, argv: &[String]) -> Command {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.path("home"))
            .env("AA_GATEWAY_ENDPOINT", self.gateway.endpoint())
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        cmd
    }

    /// Run the whole tree to completion.
    fn run(&self, argv: &[String]) -> Outcome {
        let mut spawned = self.spawn(argv);
        let code = wait(&mut spawned.child, WAIT);
        spawned.finish(code)
    }

    fn spawn(&self, argv: &[String]) -> Spawned {
        let stderr_path = self.path(&format!(
            "stderr-{}",
            self.dir.read_dir().map(|d| d.count()).unwrap_or(0)
        ));
        let stderr = std::fs::File::create(&stderr_path).expect("stderr file");
        let child = self
            .command(argv)
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn aasm");
        Spawned { child, stderr_path }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Spawned {
    child: std::process::Child,
    stderr_path: PathBuf,
}

impl Spawned {
    fn finish(self, code: Option<i32>) -> Outcome {
        Outcome {
            code,
            stderr: std::fs::read_to_string(&self.stderr_path).unwrap_or_default(),
        }
    }
}

fn wait(child: &mut std::process::Child, limit: Duration) -> Option<i32> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status.code();
        }
        if Instant::now() > deadline {
            // Only ever this test's own child.
            let _ = child.kill();
            let _ = child.wait();
            panic!("the process tree did not finish within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for(path: &Path, limit: Duration) {
    let deadline = Instant::now() + limit;
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} never appeared", path.display());
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One `filesystem_read` lease item for a policy, at 8-space indentation.
fn fs_read(selectors: &[&str], delegable: bool) -> String {
    let mut yaml = String::from("      - domain: filesystem_read\n        scope:\n");
    for selector in selectors {
        yaml.push_str(&format!("          - {selector}\n"));
    }
    yaml.push_str(&format!(
        "        delegable: {delegable}\n        reason: process tree test\n"
    ));
    yaml
}

/// The gateway registration DID an `aasm run` with this state directory registers as.
///
/// The gateway resolves `--root-agent` by DID, not by `--agent-id`, so a declared ancestor can
/// only reach the supervisor when named by the DID of an agent that is really registered.
/// `registration_did` reads (and on first use creates) the durable key in `AASM_STATE_DIR`,
/// so asking before the launch yields the DID the launch will register under.
fn did_of(state: &Path, agent: &str) -> String {
    let _lock = aa_cli::env_guard::lock();
    let prior = std::env::var_os("AASM_STATE_DIR");
    std::env::set_var("AASM_STATE_DIR", state);
    let did = aa_cli::commands::run_registration::registration_did(agent);
    match prior {
        Some(v) => std::env::set_var("AASM_STATE_DIR", v),
        None => std::env::remove_var("AASM_STATE_DIR"),
    }
    assert!(did.starts_with("did:key:"), "no durable identity key: {did}");
    did
}

fn endpoint_of(root_pid: u32) -> Endpoint {
    let index = registry_dir().join(format!("{root_pid}.idx"));
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index).expect("index entry")).expect("index is JSON");
    Endpoint {
        supervisor_pid: root_pid,
        socket: PathBuf::from(value["socket"].as_str().expect("socket path")),
    }
}

fn assert_refused(outcome: &Outcome, marker: &Path, kind: &str) {
    assert_ne!(outcome.code, Some(0), "the launch must fail:\n{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("refused by its governed ancestor's supervisor") && outcome.stderr.contains(kind),
        "expected the supervisor's `{kind}` refusal in:\n{}",
        outcome.stderr
    );
    assert!(!marker.exists(), "the refused program must never have started");
}

fn assert_ran(outcome: &Outcome, marker: &Path) {
    assert_eq!(outcome.code, Some(0), "the tree must run:\n{}", outcome.stderr);
    assert!(
        marker.exists(),
        "the innermost program must have run:\n{}",
        outcome.stderr
    );
}

// ---------------------------------------------------------------------------
// Three generations
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn three_generations_equal_then_narrower_are_admitted_and_widening_at_generation_two_is_refused() {
    let f = Fixture::new("three-gen").await;
    let root = f.policy("root", Some(&fs_read(&["/data"], true)));
    let equal = f.policy("gen2-equal", Some(&fs_read(&["/data"], true)));
    let narrower = f.policy("gen3-narrower", Some(&fs_read(&["/data/sub"], false)));
    let wider = f.policy("gen2-wider", Some(&fs_read(&["/data", "/etc"], true)));

    // Control: root -> equal -> narrower, three real processes.
    let marker = f.path("ran-3");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &equal, &[]),
        f.layer("g3", &narrower, &[]),
        f.marker_tail(&marker),
    ]
    .concat();
    assert_ran(&f.run(&argv), &marker);

    // Same shape, but generation two asks for more than the root holds.
    let marker = f.path("ran-wide");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &wider, &[]),
        f.layer("g3", &narrower, &[]),
        f.marker_tail(&marker),
    ]
    .concat();
    assert_refused(&f.run(&argv), &marker, "ChildExceedsParent");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broader_child_is_refused_but_the_same_shape_narrower_runs_and_an_independent_root_with_the_broad_policy_runs(
) {
    let f = Fixture::new("broader").await;
    let root = f.policy("root", Some(&fs_read(&["/data/a"], true)));
    let broad = f.policy("broad", Some(&fs_read(&["/data"], true)));
    let narrow = f.policy("narrow", Some(&fs_read(&["/data/a/b"], true)));

    let refused_marker = f.path("ran-broad");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &broad, &[]),
        f.marker_tail(&refused_marker),
    ]
    .concat();
    assert_refused(&f.run(&argv), &refused_marker, "ChildExceedsParent");

    let ok_marker = f.path("ran-narrow");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &narrow, &[]),
        f.marker_tail(&ok_marker),
    ]
    .concat();
    assert_ran(&f.run(&argv), &ok_marker);

    // Independent root launch, no ancestor: the broad policy is the launch's own authority.
    let independent_marker = f.path("ran-independent");
    let argv = [f.layer("g2", &broad, &[]), f.marker_tail(&independent_marker)].concat();
    assert_ran(&f.run(&argv), &independent_marker);
}

#[tokio::test(flavor = "multi_thread")]
async fn generation_three_cannot_regain_what_generation_two_dropped() {
    let f = Fixture::new("dropped").await;
    let root = f.policy("root", Some(&fs_read(&["/data"], true)));
    let keeps = f.policy("g2-keeps", Some(&fs_read(&["/data"], true)));
    let drops = f.policy("g2-drops", None);
    let asks = f.policy("g3-asks", Some(&fs_read(&["/data"], true)));

    let marker = f.path("ran-dropped");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &drops, &[]),
        f.layer("g3", &asks, &[]),
        f.marker_tail(&marker),
    ]
    .concat();
    assert_refused(&f.run(&argv), &marker, "ChildExceedsParent");

    // Control: generation two keeps the lease, generation three's request is unchanged.
    let marker = f.path("ran-kept");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &keeps, &[]),
        f.layer("g3", &asks, &[]),
        f.marker_tail(&marker),
    ]
    .concat();
    assert_ran(&f.run(&argv), &marker);
}

// ---------------------------------------------------------------------------
// Omission
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_child_that_omits_the_parent_declaration_and_scrubs_its_environment_is_still_capped() {
    let f = Fixture::new("omission").await;
    let root = f.policy("root", Some(&fs_read(&["/data/a"], true)));
    let broad = f.policy("broad", Some(&fs_read(&["/data"], true)));
    let narrow = f.policy("narrow", Some(&fs_read(&["/data/a/b"], true)));

    // `env -i`, a different HOME and AASM_STATE_DIR, and no `--root-agent`: nothing
    // the child could omit is left to omit.
    let capped_marker = f.path("ran-capped");
    let argv = [
        f.layer("g1", &root, &[]),
        f.scrubbed_layer("g2", &broad),
        f.marker_tail(&capped_marker),
    ]
    .concat();
    assert_refused(&f.run(&argv), &capped_marker, "ChildExceedsParent");

    // Control: the identical omission, narrower, is admitted — so the refusal above is
    // the ceiling, not the scrubbed environment.
    let ok_marker = f.path("ran-scrubbed-ok");
    let argv = [
        f.layer("g1", &root, &[]),
        f.scrubbed_layer("g2", &narrow),
        f.marker_tail(&ok_marker),
    ]
    .concat();
    assert_ran(&f.run(&argv), &ok_marker);

    // Control: the same scrubbed broad launch with no ancestor at all is an independent root.
    let independent_marker = f.path("ran-scrubbed-independent");
    let argv = [f.scrubbed_layer("g2", &broad), f.marker_tail(&independent_marker)].concat();
    assert_ran(&f.run(&argv), &independent_marker);
}

// ---------------------------------------------------------------------------
// Supervisor reachability
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_supervisor_socket_refuses_the_launch_and_the_same_launch_with_the_socket_runs() {
    let f = Fixture::new("socket").await;
    let root = f.policy("root", Some(&fs_read(&["/data"], true)));
    let child = f.policy("child", Some(&fs_read(&["/data"], true)));
    let script = format!(
        "{} exec \"$@\"",
        "if [ \"$1\" = delete ]; then rm -f \"/tmp/aa-sup-$(id -u)/$PPID-\"*.sock; fi; shift;"
    );

    for (mode, expect_run) in [("delete", false), ("keep", true)] {
        let marker = f.path(&format!("ran-{mode}"));
        let mut argv = f.layer("g1", &root, &[]);
        argv.extend([
            "/bin/sh".to_string(),
            "-c".to_string(),
            script.clone(),
            "t".to_string(),
            mode.to_string(),
        ]);
        argv.extend(f.layer("g2", &child, &[]));
        argv.extend(f.marker_tail(&marker));
        let outcome = f.run(&argv);
        if expect_run {
            assert_ran(&outcome, &marker);
        } else {
            assert_ne!(outcome.code, Some(0), "{}", outcome.stderr);
            assert!(outcome.stderr.contains("does not answer"), "{}", outcome.stderr);
            assert!(!marker.exists(), "the launch must be refused, not run as a root");
        }
    }
}

// ---------------------------------------------------------------------------
// Other trees
// ---------------------------------------------------------------------------

fn foreign_request(agent: &str) -> ExecutionSpec {
    let issued = std::time::SystemTime::now();
    let lease = CapabilityLease::new(
        LeaseId::new(format!("{agent}-fs")),
        IdentityRef::root(agent),
        CapabilityDomain::FilesystemRead,
        RequirementScope::Selectors(vec![aa_isolation::permit_only_selector("/data")]),
        issued,
        issued + Duration::from_secs(600),
        LeaseBasis::new(IdentityRef::root("aasm-run:policy"), "foreign request"),
    )
    .with_delegation(DelegationRule::DelegableWithNarrowerScope);
    ExecutionSpec::new("prog", IdentityRef::root(agent)).with_lease(lease)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_process_outside_the_tree_cannot_claim_its_authority_and_a_real_descendant_with_the_same_request_can() {
    let f = Fixture::new("sibling").await;
    let root = f.policy("root", Some(&fs_read(&["/data"], true)));
    let child = f.policy("child", Some(&fs_read(&["/data"], true)));
    let ready = f.path("ready");
    let go = f.path("go");
    let marker = f.path("ran-member");

    let mut argv = f.layer("g1", &root, &[]);
    argv.extend([
        "/bin/sh".to_string(),
        "-c".to_string(),
        "touch \"$1\"; shift; i=0; while [ ! -f \"$1\" ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done; shift; exec \"$@\""
            .to_string(),
        "t".to_string(),
        ready.display().to_string(),
        go.display().to_string(),
    ]);
    argv.extend(f.layer("g2", &child, &[]));
    argv.extend(f.marker_tail(&marker));

    let mut tree = f.spawn(&argv);
    wait_for(&ready, Duration::from_secs(120));

    // This test process is a same-uid process that is in no admitted hop's tree.
    let endpoint = endpoint_of(tree.child.id());
    let refused = admit(&endpoint, &foreign_request("intruder"), None, "did:key:intruder")
        .expect_err("a sibling must be refused");
    assert_eq!(refused.kind, "UnrecordedPeer", "{refused}");

    // Control: a real descendant of that tree, asking the same thing, is admitted.
    std::fs::write(&go, b"").expect("release the tool");
    let code = wait(&mut tree.child, WAIT);
    let outcome = tree.finish(code);
    assert_ran(&outcome, &marker);
}

#[tokio::test(flavor = "multi_thread")]
async fn declaring_an_agent_that_is_not_an_ancestor_is_refused_and_declaring_the_true_root_runs() {
    let f = Fixture::new("declared").await;
    let root = f.policy("root", Some(&fs_read(&["/data"], true)));
    let child = f.policy("child", Some(&fs_read(&["/data"], true)));
    let grandchild = f.policy("grandchild", Some(&fs_read(&["/data"], true)));

    // The gateway refuses a `parent_agent_id` it has never registered, so a claim can only
    // reach the supervisor when it names an agent that EXISTS: a second, real tree's root.
    let tree_b_ready = f.path("tree-b-ready");
    let tree_b_stop = f.path("tree-b-stop");
    let mut tree_b = f.layer("tb", &root, &[]);
    tree_b.extend([
        "/bin/sh".to_string(),
        "-c".to_string(),
        "touch \"$1\"; i=0; while [ ! -f \"$2\" ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done".to_string(),
        "t".to_string(),
        tree_b_ready.display().to_string(),
        tree_b_stop.display().to_string(),
    ]);
    let mut other_tree = f.spawn(&tree_b);
    wait_for(&tree_b_ready, Duration::from_secs(120));
    let foreign = did_of(&f.path("state-tb"), &f.agent("tb"));

    let marker = f.path("ran-foreign-claim");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &child, &["--root-agent", &foreign]),
        f.marker_tail(&marker),
    ]
    .concat();
    let outcome = f.run(&argv);
    std::fs::write(&tree_b_stop, b"").expect("release tree B");
    let _ = wait(&mut other_tree.child, WAIT);
    assert_refused(&outcome, &marker, "AncestryMismatch");

    // Control: naming the true root is accepted at generation two AND at generation three.
    let true_root = did_of(&f.path("state-g1"), &f.agent("g1"));
    let marker = f.path("ran-true-root");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &child, &["--root-agent", &true_root]),
        f.layer("g3", &grandchild, &["--root-agent", &true_root]),
        f.marker_tail(&marker),
    ]
    .concat();
    assert_ran(&f.run(&argv), &marker);
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn revoking_the_root_refuses_a_later_descendant_of_a_running_hop_and_without_revocation_it_runs() {
    let f = Fixture::new("revoke").await;
    let root = f.policy("root", Some(&fs_read(&["/data"], true)));
    let g2 = f.policy("g2", Some(&fs_read(&["/data"], true)));
    let g3 = f.policy("g3", Some(&fs_read(&["/data"], true)));

    for revoke in [false, true] {
        let tag = if revoke { "revoked" } else { "kept" };
        let ready = f.path(&format!("ready-{tag}"));
        let go = f.path(&format!("go-{tag}"));
        let marker = f.path(&format!("ran-{tag}"));

        // g1 (root) -> g2 (running, holds a derived lease) -> sh waits -> g3 launched afterwards.
        let mut argv = f.layer("g1", &root, &[]);
        argv.extend(f.layer("g2", &g2, &[]));
        argv.extend([
            "/bin/sh".to_string(),
            "-c".to_string(),
            "touch \"$1\"; shift; i=0; while [ ! -f \"$1\" ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done; shift; exec \"$@\""
                .to_string(),
            "t".to_string(),
            ready.display().to_string(),
            go.display().to_string(),
        ]);
        argv.extend(f.layer("g3", &g3, &[]));
        argv.extend(f.marker_tail(&marker));

        let mut tree = f.spawn(&argv);
        wait_for(&ready, Duration::from_secs(120));
        if revoke {
            let endpoint = endpoint_of(tree.child.id());
            let revoked = revoke_tree(&endpoint, "operator revoked the root lease").expect("revoke");
            assert_eq!(revoked, 1, "the root held exactly one lease");
        }
        std::fs::write(&go, b"").expect("release the tool");
        let code = wait(&mut tree.child, WAIT);
        let outcome = tree.finish(code);

        if revoke {
            assert_refused(&outcome, &marker, "ParentRevoked");
        } else {
            assert_ran(&outcome, &marker);
        }
    }
}

// ---------------------------------------------------------------------------
// What stays as it was
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_root_with_no_leases_hosts_no_supervisor_and_its_descendants_are_independent_roots() {
    let f = Fixture::new("no-leases").await;
    let root = f.policy("root", None);
    let child = f.policy("child", Some(&fs_read(&["/anything", "/at/all"], true)));
    let marker = f.path("ran-compat");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &child, &[]),
        f.marker_tail(&marker),
    ]
    .concat();
    assert_ran(&f.run(&argv), &marker);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_lease_the_ledger_cannot_track_still_runs_but_is_not_inheritable() {
    let f = Fixture::new("issuer").await;
    // An authored `issuer:` other than the policy issuer: the ledger trusts only its own.
    let authored_issuer = "      - domain: filesystem_read\n        scope:\n          - /data\n        delegable: true\n        issuer: someone-else\n        reason: process tree test\n";
    let root = f.policy("root", Some(authored_issuer));
    let child = f.policy("child", Some(&fs_read(&["/data"], true)));

    let root_alone = f.path("ran-root-alone");
    let argv = [f.layer("g1", &root, &[]), f.marker_tail(&root_alone)].concat();
    assert_ran(&f.run(&argv), &root_alone);

    let marker = f.path("ran-child-of-untracked");
    let argv = [
        f.layer("g1", &root, &[]),
        f.layer("g2", &child, &[]),
        f.marker_tail(&marker),
    ]
    .concat();
    assert_refused(&f.run(&argv), &marker, "LedgerUnverifiable");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_claiming_a_parent_with_no_governed_ancestor_is_still_refused() {
    let f = Fixture::new("claim").await;
    let child = f.policy("child", Some(&fs_read(&["/data"], true)));
    let marker = f.path("ran-claim");
    let argv = [
        f.layer("g2", &child, &["--root-agent", "nobody"]),
        f.marker_tail(&marker),
    ]
    .concat();
    let outcome = f.run(&argv);
    assert_ne!(outcome.code, Some(0), "{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("claims a parent") && outcome.stderr.contains("no governed `aasm run` ancestor"),
        "{}",
        outcome.stderr
    );
    assert!(!marker.exists());
}
