//! Adversarial scenarios that need a capable Linux host (AAASM-5712).
//!
//! # What "capable" means, and what happens without it
//!
//! Every scenario here is gated on [`adversarial::require_confining_backend`]:
//! Linux, the mechanism installed, a kernel at or above its protection floor,
//! and a discovery probe that watched a real denial. A host missing any of those
//! prints `SKIP [...]` and writes a record to the evidence ledger, which
//! `.ci/test-evidence-summary.sh` nets against the runner's pass count.
//!
//! That matters more here than anywhere else in this suite. `ci-success` counts
//! a **skipped** job as a pass, and a test runner counts a scenario that returned
//! early as a pass, so without the ledger a green mainline would be exactly what
//! a lane that measured nothing produces. The `isolation-backend-linux` job
//! therefore fails on *any* decline — on a runner that installs the mechanism
//! itself and chooses the kernel, both decline reasons are defects rather than
//! honest opt-outs.
//!
//! # What every scenario here asserts
//!
//! An **effect**: bytes that reached a listener this process owns, a file that
//! exists, a file whose content is byte-for-byte what it was. Never an exit
//! status — a denial before the effect and a kill after it are indistinguishable
//! by exit status and are different security postures.
//!
//! And a **control**, through [`adversarial::ControlledPair`]. A control that
//! produced no effect is recorded as
//! [`Measurement::NotMeasured`](adversarial::Measurement) and fails, because the
//! alternative is a broken fixture reading as a denial.
//!
//! # Two scenarios measure a gap instead of a protection
//!
//! `filesystem-backed unix sockets` and `credential values on the mechanism's
//! command line` are routes the backend does **not** claim to cover. Those
//! scenarios record what they observed and assert the truthfulness invariant
//! that holds either way: the domain must not report itself as preventing, and
//! its capability report must state the limitation. Papering the observation
//! into a passing protection assertion is what this Epic exists to stop; so is
//! quietly not looking.

// Used by `every_declared_attack_family_has_a_scenario`, which is Linux-gated
// for the reason stated on it.
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use aa_isolation::{CapabilityDomain, CredentialPosture, IsolationBackend, SupportLevel, CLOUD_METADATA_ENDPOINTS};

mod adversarial;

use adversarial::{
    accepted_payload_within, as_grandchild, assert_all_prevented, assert_no_prevention_claim, decline, egress_to,
    launch_confined, listener_on, listener_on_port, measured, quote, require_confining_backend, require_program,
    shell_spec, shell_spec_using, system_reads, system_reads_excluding, AttackFamily, ControlledPair, Effect,
    Measurement, Scratch,
};

/// Synthetic credential material. Fabricated, and deliberately unlike anything a
/// real key looks like: the acceptance criterion is that secret-directory and
/// metadata attempts are exercised **without** production credentials, and a
/// fixture that borrowed one would violate it however much it proved.
const SSH_KEY_MATERIAL: &str = "aa-adversarial-fake-ssh-key-3b91";
/// The same, for the second secret directory.
const AWS_KEY_MATERIAL: &str = "aa-adversarial-fake-aws-key-77de";

/// A python program as one argument of the inner shell.
///
/// Double-quoted at the shell level so the program's own literals can use single
/// quotes. Nothing here contains `$`, a backtick or a double quote, so the shell
/// passes the program through unchanged; the outer `as_grandchild` quoting
/// protects the whole command. No `2>/dev/null`, here or anywhere in this suite —
/// the null device is opened for *writing*, which a default-deny write policy
/// denies, so the redirection would fail before the command under test ran.
fn python(program: &str) -> String {
    assert!(
        !program.contains('"') && !program.contains('$') && !program.contains('`'),
        "this program would be re-read by the shell it is embedded in"
    );
    format!("python3 -c \"{program}\"")
}

/// A python literal list of `(host, port)` pairs.
fn destination_list(destinations: &[(String, u16)]) -> String {
    destinations
        .iter()
        .map(|(host, port)| format!("('{host}',{port})"))
        .collect::<Vec<_>>()
        .join(",")
}

/// A python program that attempts every destination, then reports what happened
/// to a destination the launch permits.
///
/// The report channel is the in-run control: it establishes that this process
/// started, that python can open a socket here, and that a permitted destination
/// is reachable. Without it, "no connection arrived at the forbidden listener"
/// would be equally consistent with a program that never ran.
fn connect_and_report(destinations: &[(String, u16)], report_port: u16) -> String {
    python(&format!(
        "import socket
out=[]
for host,port in [{}]:
    try:
        s=socket.create_connection((host,port),2)
        s.close()
        out.append('REACHED:'+host+':'+str(port))
    except Exception:
        out.append('BLOCKED:'+host+':'+str(port))
r=socket.create_connection(('127.0.0.1',{report_port}),3)
r.sendall(('|'.join(out)).encode())
r.close()",
        destination_list(destinations)
    ))
}

/// The report a `connect_and_report` run sent, or a recorded failed measurement.
///
/// A missing report is never "nothing got through": it means the probe did not
/// run, and a scenario that read it as a denial would be reporting a broken
/// fixture as a boundary.
fn require_report(scenario: &str, listener: &std::net::TcpListener, run: &str) -> String {
    match accepted_payload_within(listener, Duration::from_secs(3)) {
        Some(report) => report,
        None => {
            let reason = format!(
                "the {run} run sent no report to the destination the launch permitted, so nothing it did \
                 or did not reach is known"
            );
            adversarial::evidence::record(scenario, Measurement::NotMeasured, &reason);
            panic!("NOT MEASURED: {reason}");
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem: secret directories, path representations, symlinked writes.
// ---------------------------------------------------------------------------

/// AC: forbidden filesystem reads of the directories an agent would enumerate
/// first, through every representation of the same path.
///
/// Four routes to two synthetic secrets: the path itself, a `..` traversal that
/// starts inside a granted directory, and a symlink *placed* in a granted
/// directory. An agent that has read the boundary's grant list will try all
/// three, and a boundary that resolves paths before deciding stops all three.
///
/// The control is the identical script with one grant different — the whole
/// scratch tree readable instead of half of it — so each of the four absences is
/// attributable to that grant rather than to a `cat` that never ran.
#[test]
fn secret_directories_are_unreadable_through_every_path_representation() {
    let scenario = "adversarial: secret directories unreadable through every path representation";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("secret-dirs");

    // A synthetic home, in the half of the tree the launch withholds.
    let home = scratch.forbidden().join("home");
    std::fs::create_dir_all(home.join(".ssh")).expect("fixture");
    std::fs::create_dir_all(home.join(".aws")).expect("fixture");
    std::fs::write(home.join(".ssh/id_rsa"), SSH_KEY_MATERIAL).expect("fixture");
    std::fs::write(home.join(".aws/credentials"), AWS_KEY_MATERIAL).expect("fixture");

    // A working directory the launch *does* grant, holding the two alternate
    // routes into the half it does not.
    let workspace = scratch.permitted().join("workspace");
    std::fs::create_dir_all(&workspace).expect("fixture");
    let symlink = workspace.join("innocuous-config");
    std::os::unix::fs::symlink(home.join(".ssh/id_rsa"), &symlink).expect("fixture");
    let traversal = format!("{}/../../forbidden/home/.aws/credentials", workspace.display());

    let routes: [(&str, String, &str); 4] = [
        (
            "SSH-DIRECT",
            home.join(".ssh/id_rsa").to_string_lossy().into_owned(),
            SSH_KEY_MATERIAL,
        ),
        (
            "AWS-DIRECT",
            home.join(".aws/credentials").to_string_lossy().into_owned(),
            AWS_KEY_MATERIAL,
        ),
        ("AWS-TRAVERSAL", traversal, AWS_KEY_MATERIAL),
        ("SSH-SYMLINK", symlink.to_string_lossy().into_owned(), SSH_KEY_MATERIAL),
    ];

    let script = as_grandchild(
        &routes
            .iter()
            .map(|(tag, path, _)| format!("printf '{tag}='; cat {}; printf ';'", quote(path)))
            .collect::<Vec<_>>()
            .join("; "),
    );

    let (attack, evidence) = launch_confined(
        &backend,
        &shell_spec(&script, vec![scratch.permitted_selector()], Vec::new()),
    );
    let (control, _) = launch_confined(
        &backend,
        &shell_spec(&script, vec![scratch.whole_tree_selector()], Vec::new()),
    );

    let pairs: Vec<ControlledPair> = routes
        .iter()
        .map(|(tag, path, material)| {
            let needle = format!("{tag}={material}");
            ControlledPair::new(
                AttackFamily::ForbiddenFilesystemRead,
                Effect::new(
                    format!("read {path} as `{tag}` under the boundary"),
                    attack.stdout.contains(&needle),
                    format!("stdout: {:?} | stderr: {:?}", attack.stdout, attack.stderr),
                ),
                Effect::new(
                    "the same read with the withheld half granted",
                    control.stdout.contains(&needle),
                    format!("stdout: {:?}", control.stdout),
                ),
            )
        })
        .collect();
    let detail = assert_all_prevented(scenario, &pairs);

    assert_no_prevention_claim("sandlock, after a measured read denial", &evidence);
    measured(scenario, AttackFamily::ForbiddenFilesystemRead, &detail);
}

/// AC: a forbidden write through a symlink whose target is outside the grant
/// never takes effect — and the file it aimed at is byte-for-byte unchanged.
///
/// The unchanged content is the whole point. A control that stopped the write
/// *after* it landed would leave the file truncated or rewritten, and a scenario
/// that only checked the exit status could not tell the two apart.
#[test]
fn a_forbidden_write_through_a_symlink_never_takes_effect() {
    let scenario = "adversarial: a symlinked write outside the grant never takes effect";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("symlink-write");

    let victim = scratch.forbidden().join("existing");
    std::fs::write(&victim, "original").expect("fixture");
    let symlink = scratch.permitted().join("output");
    std::os::unix::fs::symlink(&victim, &symlink).expect("fixture");
    // Written on the same line, to a path the launch *does* grant. If this is
    // absent the script did not run, and the victim's unchanged content would
    // mean nothing.
    let proof = scratch.permitted().join("the-script-ran");

    let script = as_grandchild(&format!(
        "printf x > {}; printf tampered > {}",
        quote(&proof.to_string_lossy()),
        quote(&symlink.to_string_lossy())
    ));

    launch_confined(
        &backend,
        &shell_spec(
            &script,
            vec![scratch.whole_tree_selector()],
            vec![scratch.permitted_selector()],
        ),
    );
    assert!(
        proof.exists(),
        "the confined script did not run at all, so the victim's contents establish nothing"
    );
    let after_attack = std::fs::read_to_string(&victim).expect("the victim file must still be readable");
    std::fs::remove_file(&proof).expect("reset between runs");

    let (_, evidence) = launch_confined(
        &backend,
        &shell_spec(
            &script,
            vec![scratch.whole_tree_selector()],
            vec![scratch.whole_tree_selector()],
        ),
    );
    let after_control = std::fs::read_to_string(&victim).expect("readable");

    let detail = assert_all_prevented(
        scenario,
        &[ControlledPair::new(
            AttackFamily::ForbiddenFilesystemWrite,
            Effect::new(
                "write through a symlink pointing outside the write grant",
                after_attack != "original",
                format!("the victim held {after_attack:?} after the attack run"),
            ),
            Effect::new(
                "the same write with the symlink's target granted",
                after_control != "original",
                format!("the victim held {after_control:?} after the control run"),
            ),
        )],
    );

    assert_no_prevention_claim("sandlock, after a measured write denial", &evidence);
    measured(scenario, AttackFamily::ForbiddenFilesystemWrite, &detail);
}

// ---------------------------------------------------------------------------
// Process inspection.
// ---------------------------------------------------------------------------

/// AC: `/proc` inspection is available to the confined program only where the
/// launch granted it — and the credential domain does not claim otherwise.
///
/// `/proc` is on the default read grant of every other scenario in this crate,
/// because the loader and the interpreter are happier with it. That makes it the
/// most important thing to measure: it is simultaneously a routine grant and the
/// route by which one process reads another's environment. The pair is the same
/// read with and without the grant.
///
/// The **finding probe** rides along in the granted run: it sweeps
/// `/proc/*/environ` for a marker this test put in its own environment, which is
/// the environment the supervisor outside the boundary inherited. Its result is
/// recorded rather than asserted — the backend claims nothing about the
/// supervisor process, and asserting either outcome would be asserting something
/// nobody promised. What *is* asserted is the invariant that holds either way:
/// the credential domain must not report itself as preventing. Anyone wiring a
/// controlled pair into `capability::credential()` to close that hole has to get
/// past this assertion, and the ledger detail tells them what they have to close
/// first.
#[test]
fn process_inspection_is_available_only_where_the_launch_granted_it() {
    let scenario = "adversarial: process inspection only where the launch granted it";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    if require_program(scenario, "grep").is_none() {
        return;
    }
    let scratch = Scratch::new("proc");

    // A marker in *this* process's environment, which the supervisor inherits.
    // Synthetic, and named so a reader of a leaked `/proc` dump can trace it.
    let marker = format!("aa-adversarial-supervisor-marker-{}", std::process::id());
    std::env::set_var("X_AA5712_SUPERVISOR_MARKER", &marker);
    // The same string in a file the launch grants, so the sweep below has a
    // positive control: if `grep` cannot match this, it could not have matched
    // anything, and the sweep's silence means nothing.
    let bait = scratch.permitted().join("bait");
    std::fs::write(&bait, &marker).expect("fixture");

    let script = as_grandchild(&format!(
        "printf 'PROC='; cat /proc/sys/kernel/ostype; \
         grep -q {marker} {bait} && printf 'GREP-WORKS;'; \
         for f in /proc/[0-9]*/environ; do grep -q {marker} \"$f\" && {{ printf 'ENVIRON-LEAK;'; break; }}; done",
        marker = quote(&marker),
        bait = quote(&bait.to_string_lossy())
    ));

    // Attack: every system read grant except `/proc`.
    let (attack, evidence) = launch_confined(
        &backend,
        &adversarial::shell_spec_with_system_reads(
            &script,
            system_reads_excluding(&["/proc"]),
            vec![scratch.permitted_selector()],
            Vec::new(),
        ),
    );
    // Control: the identical script with `/proc` back on the list.
    let (control, _) = launch_confined(
        &backend,
        &adversarial::shell_spec_with_system_reads(
            &script,
            system_reads(),
            vec![scratch.permitted_selector()],
            Vec::new(),
        ),
    );

    let detail = assert_all_prevented(
        scenario,
        &[ControlledPair::new(
            AttackFamily::ProcessInspection,
            Effect::new(
                "read /proc with the grant withheld",
                attack.stdout.contains("PROC=Linux"),
                format!("stdout: {:?} | stderr: {:?}", attack.stdout, attack.stderr),
            ),
            Effect::new(
                "the same read with /proc granted",
                control.stdout.contains("PROC=Linux"),
                format!("stdout: {:?}", control.stdout),
            ),
        )],
    );

    // The finding probe. Recorded, never asserted — see the doc comment.
    let sweep_ran = control.stdout.contains("GREP-WORKS");
    let leaked = control.stdout.contains("ENVIRON-LEAK");
    let finding = if !sweep_ran {
        "FINDING PROBE INCONCLUSIVE: the environment sweep's own positive control did not fire, so its \
         silence about other processes' environments establishes nothing"
            .to_string()
    } else if leaked {
        "FINDING: with `/proc` granted — which every other scenario in this crate grants by default — \
         the confined program read a marker out of another process's environment. Replacing the child's \
         environment is therefore not a credential boundary while `/proc` is readable"
            .to_string()
    } else {
        "the environment sweep's positive control fired and no other process's environment matched, so \
         this route was closed on this host"
            .to_string()
    };
    println!("PROBE [{scenario}]: {finding}");

    // The invariant that holds whichever way the probe went.
    let credential = backend
        .capabilities()
        .report_for(CapabilityDomain::Credential)
        .cloned()
        .expect("every domain is reported");
    assert!(
        !credential.can_prevent(),
        "the credential domain reports that it prevents, on a backend whose only credential control is \
         replacing the child's environment — a control this scenario's probe says nothing can be \
         concluded from while `/proc` is a routine grant. {finding}"
    );
    assert_no_prevention_claim("sandlock, after a measured /proc denial", &evidence);

    std::env::remove_var("X_AA5712_SUPERVISOR_MARKER");
    measured(
        scenario,
        AttackFamily::ProcessInspection,
        &format!("{detail}. {finding}"),
    );
}

// ---------------------------------------------------------------------------
// Network: the direct path, alternate addresses, metadata services.
// ---------------------------------------------------------------------------

/// AC: a direct outbound connection is tested separately from the one the launch
/// routes through, and the direct one never arrives.
///
/// Two listeners this process owns: one stands for the configured proxy and is
/// the only permitted destination, the other stands for the origin an agent
/// would rather reach directly. Both are loopback, so the measurement needs no
/// DNS, no route and no third party, and cannot pass because something remote
/// was down.
///
/// The proxy listener receiving its payload in the same run is the in-run
/// control: egress works, python works, the program ran.
#[test]
fn a_direct_connection_bypassing_the_configured_route_never_arrives() {
    let scenario = "adversarial: a direct connection bypassing the configured route never arrives";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    if require_program(scenario, "python3").is_none() {
        return;
    }
    let (Some((proxy, proxy_port)), Some((origin, origin_port))) = (listener_on("127.0.0.1"), listener_on("127.0.0.1"))
    else {
        decline::<()>(
            scenario,
            Measurement::UnsupportedPlatform,
            "no loopback listener could be bound on this host",
        );
        return;
    };

    let script = as_grandchild(&connect_and_report(
        &[("127.0.0.1".to_string(), origin_port)],
        proxy_port,
    ));
    let permitted_route = vec![format!("127.0.0.1:{proxy_port}")];

    let (_, evidence) = launch_confined(
        &backend,
        &shell_spec(&script, Vec::new(), Vec::new()).with_requirement(egress_to(&permitted_route)),
    );
    let attack_report = require_report(scenario, &proxy, "attack");
    let attack_arrived = accepted_payload_within(&origin, Duration::from_secs(1)).is_some();

    // Control: the identical script and the identical grant, plus the origin.
    let both = vec![format!("127.0.0.1:{proxy_port}"), format!("127.0.0.1:{origin_port}")];
    launch_confined(
        &backend,
        &shell_spec(&script, Vec::new(), Vec::new()).with_requirement(egress_to(&both)),
    );
    let control_report = require_report(scenario, &proxy, "control");
    let control_arrived = accepted_payload_within(&origin, Duration::from_secs(1)).is_some();

    let detail = assert_all_prevented(
        scenario,
        &[ControlledPair::new(
            AttackFamily::DirectEgressBypass,
            Effect::new(
                "connect directly to an origin the launch did not permit",
                attack_arrived,
                format!("the confined program reported: {attack_report}"),
            ),
            Effect::new(
                "the same connection with the origin permitted",
                control_arrived,
                format!("the confined program reported: {control_report}"),
            ),
        )],
    );

    assert_no_prevention_claim("sandlock, after a measured egress denial", &evidence);
    measured(scenario, AttackFamily::DirectEgressBypass, &detail);
}

/// AC: DNS and address-representation edge cases, where the backend claims
/// network control.
///
/// The backend's own capability report says the permitted set is *the address
/// set* observed when the launch starts. This measures that claim, which is the
/// only honest thing to measure: a permitted destination that scoped the port and
/// not the address would let every other service on that port through, and the
/// report would be false rather than merely coarse.
///
/// Three spellings of one withheld address, all resolving to the same 32 bits —
/// dotted, decimal and octal — plus a permitted destination on the *same port*,
/// so the port cannot be what distinguishes them.
///
/// Name resolution is deliberately absent: this backend redirects it rather than
/// deciding about it and reports the domain unsupported by construction, so a
/// hostname destination here would measure the resolver rather than the boundary.
/// `adversarial_negotiation.rs` asserts the refusal that fact produces.
#[test]
fn a_permitted_destination_does_not_permit_a_different_address_on_the_same_port() {
    let scenario = "adversarial: a permitted destination does not permit another address on its port";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    if require_program(scenario, "python3").is_none() {
        return;
    }
    let Some((permitted, port)) = listener_on("127.0.0.1") else {
        decline::<()>(
            scenario,
            Measurement::UnsupportedPlatform,
            "no loopback listener could be bound on this host",
        );
        return;
    };
    let Some(withheld) = listener_on_port("127.0.0.2", port) else {
        decline::<()>(
            scenario,
            Measurement::UnsupportedPlatform,
            "this host does not route the whole 127.0.0.0/8 block, so two addresses cannot share a port \
             and the address half of a destination cannot be measured separately from the port half",
        );
        return;
    };

    // Every spelling of 127.0.0.2 the C resolver accepts. They are the same 32
    // bits by the time `connect` sees them, which is the point: a boundary that
    // decided on the text rather than the address would disagree between them.
    let spellings = [
        ("127.0.0.2", "dotted"),
        ("2130706434", "decimal"),
        ("0177.0.0.2", "octal"),
    ];
    let destinations: Vec<(String, u16)> = spellings.iter().map(|(host, _)| ((*host).to_string(), port)).collect();
    let script = as_grandchild(&connect_and_report(&destinations, port));

    let (_, evidence) = launch_confined(
        &backend,
        &shell_spec(&script, Vec::new(), Vec::new()).with_requirement(egress_to(&[format!("127.0.0.1:{port}")])),
    );
    let attack_report = require_report(scenario, &permitted, "attack");
    let attack_arrivals = drain(&withheld, spellings.len());

    // Control: the identical script with the withheld address permitted too.
    launch_confined(
        &backend,
        &shell_spec(&script, Vec::new(), Vec::new())
            .with_requirement(egress_to(&[format!("127.0.0.1:{port}"), format!("127.0.0.2:{port}")])),
    );
    let control_report = require_report(scenario, &permitted, "control");
    let control_arrivals = drain(&withheld, spellings.len());

    let detail = assert_all_prevented(
        scenario,
        &[ControlledPair::new(
            AttackFamily::AddressRepresentation,
            Effect::new(
                format!(
                    "connect to 127.0.0.2:{port} — a withheld address on a permitted port — spelled {} \
                     different ways",
                    spellings.len()
                ),
                attack_arrivals > 0,
                format!(
                    "{attack_arrivals} connection(s) arrived at the withheld address. The confined program \
                     reported: {attack_report}. If this is non-zero, the capability report's claim that \
                     the permitted set is an *address* set is false on this host and the destination is \
                     scoped by port alone — a finding for a follow-up Bug, not something to relax here",
                ),
            ),
            Effect::new(
                "the same connections with 127.0.0.2 permitted",
                control_arrivals > 0,
                format!("{control_arrivals} connection(s) arrived. Reported: {control_report}"),
            ),
        )],
    );

    assert_no_prevention_claim("sandlock, after a measured address denial", &evidence);
    measured(scenario, AttackFamily::AddressRepresentation, &detail);
}

/// How many connections arrived at a listener, up to `limit`.
fn drain(listener: &std::net::TcpListener, limit: usize) -> usize {
    let mut arrivals = 0;
    while arrivals < limit {
        match accepted_payload_within(listener, Duration::from_millis(400)) {
            Some(_) => arrivals += 1,
            None => break,
        }
    }
    arrivals
}

/// AC: instance-metadata endpoints are attempted and refused, and the launch
/// says which of them its grants leave reachable.
///
/// The metadata service mints cloud credentials for anything that can reach it,
/// so this is credential authority arriving over the network domain. Nothing here
/// touches a real credential: the attempt stops at the TCP connection, and the
/// control is a stand-in listener on loopback rather than a real service.
///
/// The far end cannot be observed — nobody here owns 169.254.169.254 — so the
/// confined program reports its own outcome down a channel the launch permits.
/// The control is the same program pointed at a permitted stand-in, which must
/// report `REACHED`: without it, "no endpoint was reached" would be equally
/// consistent with a program that cannot emit `REACHED` at all.
#[test]
fn cloud_metadata_endpoints_are_refused_and_the_launch_states_their_reachability() {
    let scenario = "adversarial: cloud metadata endpoints refused and stated";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    if require_program(scenario, "python3").is_none() {
        return;
    }
    let (Some((report, report_port)), Some((standin, standin_port))) =
        (listener_on("127.0.0.1"), listener_on("127.0.0.1"))
    else {
        decline::<()>(
            scenario,
            Measurement::UnsupportedPlatform,
            "no loopback listener could be bound on this host",
        );
        return;
    };

    // Derived from the product's own list, so an endpoint added there is attacked
    // here without anyone remembering to. The hostname entries are excluded: this
    // backend redirects name resolution rather than deciding about it, so a name
    // would measure the resolver. IPv6 is excluded for the same class of reason —
    // a runner with no IPv6 route produces a timeout, not a decision.
    let endpoints: Vec<(String, u16)> = CLOUD_METADATA_ENDPOINTS
        .iter()
        .filter(|e| e.parse::<Ipv4Addr>().is_ok())
        .map(|e| ((*e).to_string(), 80u16))
        .collect();
    assert!(
        endpoints.len() >= 3,
        "the product's metadata endpoint list no longer contains the addresses this scenario attacks"
    );

    let (_, evidence) = launch_confined(
        &backend,
        &shell_spec(
            &as_grandchild(&connect_and_report(&endpoints, report_port)),
            Vec::new(),
            Vec::new(),
        )
        .with_requirement(egress_to(&[format!("127.0.0.1:{report_port}")])),
    );
    let attack_report = require_report(scenario, &report, "attack");

    // Control: the same program shape against a stand-in the launch permits.
    launch_confined(
        &backend,
        &shell_spec(
            &as_grandchild(&connect_and_report(
                &[("127.0.0.1".to_string(), standin_port)],
                report_port,
            )),
            Vec::new(),
            Vec::new(),
        )
        .with_requirement(egress_to(&[
            format!("127.0.0.1:{report_port}"),
            format!("127.0.0.1:{standin_port}"),
        ])),
    );
    let control_report = require_report(scenario, &report, "control");
    let _ = accepted_payload_within(&standin, Duration::from_secs(1));

    let detail = assert_all_prevented(
        scenario,
        &[ControlledPair::new(
            AttackFamily::CloudMetadata,
            Effect::new(
                format!("connect to {} well-known metadata addresses", endpoints.len()),
                attack_report.contains("REACHED:"),
                format!("the confined program reported: {attack_report}"),
            ),
            Effect::new(
                "the same program against a permitted stand-in",
                control_report.contains("REACHED:"),
                format!("the confined program reported: {control_report}"),
            ),
        )],
    );

    // And the launch says so in evidence, in both directions. A launch whose
    // grants *do* name a metadata address must say that too, or an auditor
    // reading a clean record cannot tell which kind of launch it was.
    let stated = metadata_sentence(&evidence);
    assert!(
        stated.contains("no permitted egress destination names any"),
        "a launch permitting only loopback did not state that no metadata address was reachable: {stated}"
    );
    let (_, permissive) = launch_confined(
        &backend,
        &shell_spec("exit 0", Vec::new(), Vec::new()).with_requirement(egress_to(&[
            format!("127.0.0.1:{report_port}"),
            "169.254.169.254".to_string(),
        ])),
    );
    let permissive_sentence = metadata_sentence(&permissive);
    assert!(
        permissive_sentence.contains("169.254.169.254"),
        "a launch that permits a metadata address did not name it: {permissive_sentence}"
    );

    assert_no_prevention_claim("sandlock, after a measured metadata denial", &evidence);
    measured(scenario, AttackFamily::CloudMetadata, &detail);
}

/// The evidence record stating what this launch's grants leave reachable.
fn metadata_sentence(evidence: &aa_isolation::EnforcementEvidence) -> String {
    evidence
        .records_for(CapabilityDomain::NetworkEgress)
        .find(|r| r.detail.starts_with("instance-metadata reachability"))
        .map(|r| r.detail.clone())
        .unwrap_or_else(|| panic!("no metadata reachability record: {:?}", evidence.records()))
}

// ---------------------------------------------------------------------------
// Sockets and descriptors.
// ---------------------------------------------------------------------------

/// AC: an inherited socket does not carry egress authority across the boundary.
///
/// A descriptor is the one piece of ambient authority no environment plan can
/// touch, and a *connected socket* is the sharpest case: it carries a destination
/// the egress policy never permitted, with no name attached, and needs no
/// `connect` call to use. If it survives `exec`, every egress grant in the launch
/// is advisory.
///
/// **The control runs first and is load-bearing.** The identical write, from
/// outside the boundary, against a descriptor made inheritable by construction,
/// establishes that the descriptor can be written across an `exec` on this host.
/// Without it the confined run's silence would be equally consistent with a shell
/// that does not support the redirection.
#[cfg(target_os = "linux")]
#[test]
fn an_inherited_socket_does_not_carry_egress_authority_across_the_boundary() {
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    let scenario = "adversarial: an inherited socket carries no egress authority across the boundary";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let address = listener.local_addr().expect("addr");
    let client = TcpStream::connect(address).expect("a loopback connection this process owns");
    let (mut server, _) = listener.accept().expect("accept");
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");

    // `dup` returns a descriptor without the close-on-exec flag whatever the
    // original carried, so the control's premise is true by construction rather
    // than by assuming what `TcpStream::connect` did.
    //
    // SAFETY: `dup` acts on a descriptor owned by the live `TcpStream` above and
    // returns a new one or -1; it dereferences nothing.
    let inheritable = unsafe { libc::dup(client.as_raw_fd()) };
    assert!(inheritable >= 0, "the descriptor could not be duplicated");

    adversarial::unconfined(&format!("printf CONTROL >&{inheritable}"));
    let control_arrived = read_marker(&mut server, "CONTROL");

    let (_, evidence) = launch_confined(
        &backend,
        &shell_spec(
            &as_grandchild(&format!("printf ATTACK >&{inheritable}")),
            Vec::new(),
            Vec::new(),
        ),
    );
    let attack_arrived = read_marker(&mut server, "ATTACK");

    let detail = assert_all_prevented(
        scenario,
        &[ControlledPair::new(
            AttackFamily::UnixSocketsAndDescriptors,
            Effect::new(
                "write to an inherited connected socket from inside the boundary",
                attack_arrived,
                "nothing tagged ATTACK reached the socket's other end".to_string(),
            ),
            Effect::new(
                "the identical write from outside the boundary",
                control_arrived,
                "the socket's other end received the control payload".to_string(),
            ),
        )],
    );

    // The inventory behind the claim must be in evidence, with the completeness
    // of the enumeration attached: an inventory nobody could take must never read
    // like one that came back clean.
    let inventory = evidence
        .records_for(CapabilityDomain::Ipc)
        .find(|r| r.detail.starts_with("inherited descriptors"))
        .unwrap_or_else(|| panic!("no descriptor inventory in evidence: {:?}", evidence.records()));
    assert!(
        inventory.detail.contains("every one accounted for"),
        "the boundary was clean and the evidence does not say so: {}",
        inventory.detail
    );

    assert_no_prevention_claim("sandlock, after a measured descriptor denial", &evidence);
    measured(scenario, AttackFamily::UnixSocketsAndDescriptors, &detail);
}

/// Whether `marker` arrived on `stream` within its read timeout.
#[cfg(target_os = "linux")]
fn read_marker(stream: &mut std::net::TcpStream, marker: &str) -> bool {
    use std::io::Read;
    let mut buffer = [0u8; 64];
    match stream.read(&mut buffer) {
        Ok(0) | Err(_) => false,
        Ok(n) => String::from_utf8_lossy(&buffer[..n]).contains(marker),
    }
}

/// AC: unix sockets — the scoped kind is scoped, and the kind the backend says it
/// does not cover is measured and declared rather than assumed.
///
/// The mechanism scopes abstract-namespace unix sockets and applies that scoping
/// unconditionally, so the controlled pair `crate::capability` says cannot be
/// built — the same command with one flag different — really cannot be. A pair
/// *can* be built the other way, against the same command outside the boundary,
/// and that is what runs here.
///
/// Filesystem-backed unix sockets are the declared gap. This measures what
/// actually happens on the host and records it; the assertion is the invariant
/// that holds whichever way the measurement goes — the domain must state the
/// limitation and must not report itself as preventing.
#[cfg(target_os = "linux")]
#[test]
fn an_abstract_unix_socket_is_scoped_and_the_pathname_socket_gap_is_declared() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};

    let scenario = "adversarial: abstract unix sockets are scoped and the pathname gap is declared";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    if require_program(scenario, "python3").is_none() {
        return;
    }
    let scratch = Scratch::new("unix-sockets");

    let name = format!("aa-adversarial-{}", std::process::id());
    let Ok(address) = SocketAddr::from_abstract_name(name.as_bytes()) else {
        decline::<()>(
            scenario,
            Measurement::UnsupportedPlatform,
            "this host has no abstract unix socket namespace",
        );
        return;
    };
    let Ok(abstract_listener) = UnixListener::bind_addr(&address) else {
        decline::<()>(
            scenario,
            Measurement::UnsupportedPlatform,
            "an abstract unix socket could not be bound on this host",
        );
        return;
    };
    abstract_listener.set_nonblocking(true).expect("non-blocking");

    let connect_abstract = python(&format!(
        "import socket
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('\\0{name}')
s.sendall(b'ABSTRACT')"
    ));

    // Control first, outside the boundary: the socket is connectable here.
    adversarial::unconfined(&connect_abstract);
    let control_arrived = unix_connection_arrived(&abstract_listener);

    let (_, evidence) = launch_confined(
        &backend,
        &shell_spec(&as_grandchild(&connect_abstract), Vec::new(), Vec::new()),
    );
    let attack_arrived = unix_connection_arrived(&abstract_listener);

    let detail = assert_all_prevented(
        scenario,
        &[ControlledPair::new(
            AttackFamily::UnixSocketsAndDescriptors,
            Effect::new(
                "connect to an abstract-namespace unix socket from inside the boundary",
                attack_arrived,
                "no connection arrived at the abstract socket".to_string(),
            ),
            Effect::new(
                "the identical connection from outside the boundary",
                control_arrived,
                "a connection arrived at the abstract socket".to_string(),
            ),
        )],
    );

    // The declared gap, measured rather than assumed.
    let pathname = scratch.forbidden().join("socket");
    let pathname_listener = UnixListener::bind(&pathname).expect("a pathname socket in the withheld half");
    pathname_listener.set_nonblocking(true).expect("non-blocking");
    let connect_pathname = python(&format!(
        "import socket
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('{}')
s.sendall(b'PATHNAME')",
        pathname.display()
    ));
    launch_confined(
        &backend,
        &shell_spec(
            &as_grandchild(&connect_pathname),
            vec![scratch.permitted_selector()],
            vec![scratch.permitted_selector()],
        ),
    );
    let pathname_reached = unix_connection_arrived(&pathname_listener);
    let finding = if pathname_reached {
        "FINDING: a filesystem-backed unix socket in a directory the launch granted neither read nor \
         write access to was still connectable from inside the boundary. The path grants do not cover \
         `connect`, which is the gap the ipc domain declares — measured here rather than assumed"
    } else {
        "a filesystem-backed unix socket outside the grants was not connectable on this host, which is \
         stronger than the ipc domain claims"
    };
    println!("PROBE [{scenario}]: {finding}");

    let ipc = backend
        .capabilities()
        .report_for(CapabilityDomain::Ipc)
        .cloned()
        .expect("every domain is reported");
    match ipc.support() {
        SupportLevel::Partial { limitations } => assert!(
            limitations.iter().any(|l| l.contains("filesystem-backed unix sockets")),
            "the ipc domain does not state the pathname-socket limitation this scenario measured: \
             {limitations:?}. {finding}"
        ),
        other => panic!("the ipc domain stopped stating its limitations: {other:?}. {finding}"),
    }
    assert!(
        !ipc.can_prevent(),
        "the ipc domain reports that it prevents, while the only measurement of it in this repository is \
         the out-of-boundary pair in this scenario. {finding}"
    );
    assert_no_prevention_claim("sandlock, after a measured abstract socket denial", &evidence);

    measured(
        scenario,
        AttackFamily::UnixSocketsAndDescriptors,
        &format!("{detail}. {finding}"),
    );
}

/// Whether a connection arrived at a non-blocking unix listener.
#[cfg(target_os = "linux")]
fn unix_connection_arrived(listener: &std::os::unix::net::UnixListener) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok(_) => return true,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return false,
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Process tree and alternate executables.
// ---------------------------------------------------------------------------

/// AC: descendant confinement holds for a descendant that detaches, and the
/// boundary is not keyed on the path the program was reached by.
///
/// Two escapes an agent would actually try. `setsid` leaves the session, which
/// is how a daemon survives its launcher; a second name for the same binary is
/// how a program avoids a rule written against a path. Neither is a filesystem
/// question, so neither is covered by the filesystem scenarios above.
///
/// The detached child writes a marker to a *granted* path on its way out, which
/// both synchronises the assertion and proves it existed at all.
#[test]
fn a_detached_descendant_and_an_alternate_executable_path_are_confined_alike() {
    let scenario = "adversarial: a detached descendant and an alternate executable path are confined alike";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    if require_program(scenario, "python3").is_none() {
        return;
    }
    // A second absolute path to a POSIX shell. `/bin/sh` is excluded by
    // construction: the point is that the boundary is not keyed on the path the
    // program was reached by, and a list containing the usual path could not
    // show that.
    let Some(alternate) = ["/usr/bin/sh", "/bin/dash", "/usr/bin/dash"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
    else {
        decline::<()>(
            scenario,
            Measurement::UnsupportedPlatform,
            "this host offers no second path to a POSIX shell, so an alternate executable path cannot be \
             distinguished from the first one",
        );
        return;
    };
    let scratch = Scratch::new("detached");

    let forbidden = scratch.forbidden().join("written-after-detaching");
    let marker = scratch.permitted().join("the-detached-child-ran");
    let detach = python(&format!(
        "import os
pid=os.fork()
if pid==0:
    try:
        os.setsid()
    except Exception:
        pass
    try:
        open('{forbidden}','w').write('x')
    except Exception:
        pass
    open('{marker}','w').write('ran')
    os._exit(0)
os.waitpid(pid,0)",
        forbidden = forbidden.display(),
        marker = marker.display()
    ));

    // (1) the detached descendant, launched through the alternate path to the
    // shell, so both escapes are exercised by the same run.
    let (_, evidence) = launch_confined(
        &backend,
        &shell_spec_using(
            alternate,
            &as_grandchild(&detach),
            system_reads(),
            vec![scratch.whole_tree_selector()],
            vec![scratch.permitted_selector()],
        ),
    );
    assert!(
        marker.exists(),
        "the detached child never ran, so the absence of its forbidden write establishes nothing"
    );
    let attack_wrote = forbidden.exists();
    std::fs::remove_file(&marker).expect("reset between runs");

    // Control: the identical program through the identical path, with the
    // withheld half writable.
    launch_confined(
        &backend,
        &shell_spec_using(
            alternate,
            &as_grandchild(&detach),
            system_reads(),
            vec![scratch.whole_tree_selector()],
            vec![scratch.whole_tree_selector()],
        ),
    );
    assert!(marker.exists(), "the control run's detached child never ran either");
    let control_wrote = forbidden.exists();

    let detail = assert_all_prevented(
        scenario,
        &[ControlledPair::new(
            AttackFamily::ProcessTreeAndAlternateExecutables,
            Effect::new(
                format!("a descendant that called setsid, under a shell reached as {alternate}"),
                attack_wrote,
                format!("{} exists: {attack_wrote}", forbidden.display()),
            ),
            Effect::new(
                "the same descendant with the withheld half writable",
                control_wrote,
                format!("{} exists: {control_wrote}", forbidden.display()),
            ),
        )],
    );

    assert_eq!(
        backend
            .capabilities()
            .report_for(CapabilityDomain::FilesystemWrite)
            .expect("reported")
            .descendants(),
        aa_isolation::DescendantCoverage::ProcessTree,
        "descendant coverage was observed at a depth the probe does not reach and is not reported"
    );
    assert_no_prevention_claim("sandlock, after a measured descendant denial", &evidence);
    measured(scenario, AttackFamily::ProcessTreeAndAlternateExecutables, &detail);
}

// ---------------------------------------------------------------------------
// Credential enumeration.
// ---------------------------------------------------------------------------

/// AC: an agent enumerating its environment for credentials finds only what the
/// launch delegated — through every route it would use.
///
/// `env` is the obvious one. `/proc/self/environ` is the one an agent reaches for
/// when `env` is missing, and it is a different kernel interface reading the same
/// memory, so a control that filtered one and not the other would be a boundary
/// in name only.
///
/// The control is the identical launch with one name moved from `removed` to
/// `delegated`, which is the smallest possible difference between "this variable
/// is withheld" and "this variable is given".
///
/// The **finding probe** looks for the delegated *value* on the mechanism's own
/// command line, which the lowering passes as `--env NAME=VALUE`. Recorded rather
/// than asserted, for the same reason as the `/proc` sweep: the backend claims
/// nothing about the supervisor process. What is asserted is that the credential
/// domain does not report itself as preventing.
#[test]
fn an_agent_enumerating_its_environment_finds_only_what_the_launch_delegated() {
    let scenario = "adversarial: environment enumeration finds only what the launch delegated";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let Some(env_program) = ["/usr/bin/env", "/bin/env"]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
    else {
        decline::<()>(
            scenario,
            Measurement::ToolAbsent,
            "no `env` binary was found, and nothing else prints the child's whole environment",
        );
        return;
    };

    let scratch = Scratch::new("enumeration");
    let withheld_value = format!("aa-adversarial-withheld-{}", std::process::id());
    let delegated_value = format!("aa-adversarial-delegated-{}", std::process::id());
    std::env::set_var("X_AA5712_ENUM_SECRET_TOKEN", &withheld_value);
    std::env::set_var("X_AA5712_ENUM_CORRELATION_ID", &delegated_value);

    // The delegated value goes in a pattern file rather than on `grep`'s command
    // line, and the sweep below is what would otherwise read it there: a scanner
    // whose own invocation carries the string it hunts for matches itself and
    // reports a leak on every host. The bait file is the sweep's positive
    // control — without it, "nothing matched" and "grep could not match" are the
    // same observation.
    let pattern = scratch.permitted().join("pattern");
    std::fs::write(&pattern, format!("{delegated_value}\n")).expect("fixture");
    let bait = scratch.permitted().join("bait");
    std::fs::write(&bait, &delegated_value).expect("fixture");

    // Three routes, in one script: the tool, the kernel interface reading the
    // same memory, and every command line on the host this process can read.
    let script = as_grandchild(&format!(
        "printf 'ENV='; {env}; printf ';ENVIRON='; cat /proc/self/environ; printf ';PROBE='; \
         grep -q -f {pattern} {bait} && printf 'GREP-WORKS,'; \
         for f in /proc/[0-9]*/cmdline; do grep -q -f {pattern} \"$f\" && {{ printf 'CMDLINE-LEAK,'; break; }}; done",
        env = env_program,
        pattern = quote(&pattern.to_string_lossy()),
        bait = quote(&bait.to_string_lossy())
    ));

    let posture = |delegated: Vec<&str>, removed: Vec<&str>| CredentialPosture {
        removed: removed.into_iter().map(str::to_string).collect(),
        delegated: delegated.into_iter().map(str::to_string).collect(),
        ambient_unremoved: Vec::new(),
    };

    let (attack, evidence) = launch_confined(
        &backend,
        &shell_spec(&script, vec![scratch.permitted_selector()], Vec::new()).with_credentials(posture(
            vec!["X_AA5712_ENUM_CORRELATION_ID"],
            vec!["X_AA5712_ENUM_SECRET_TOKEN"],
        )),
    );
    // Control: one name moved from `removed` to `delegated`. Nothing else about
    // the two launches differs.
    let (control, _) = launch_confined(
        &backend,
        &shell_spec(&script, vec![scratch.permitted_selector()], Vec::new()).with_credentials(posture(
            vec!["X_AA5712_ENUM_CORRELATION_ID", "X_AA5712_ENUM_SECRET_TOKEN"],
            Vec::new(),
        )),
    );

    let routes = ["ENV", "ENVIRON"];
    let pairs: Vec<ControlledPair> = routes
        .iter()
        .map(|route| {
            ControlledPair::new(
                AttackFamily::CredentialEnumeration,
                Effect::new(
                    format!("recover the withheld secret through `{route}`"),
                    section(&attack.stdout, route).contains(&withheld_value),
                    format!("attack `{route}` section: {:?}", section(&attack.stdout, route)),
                ),
                Effect::new(
                    format!("the same enumeration with that one name delegated, through `{route}`"),
                    section(&control.stdout, route).contains(&withheld_value),
                    format!("control `{route}` section: {:?}", section(&control.stdout, route)),
                ),
            )
        })
        .collect();
    let detail = assert_all_prevented(scenario, &pairs);

    // The delegated name did arrive, through both routes. Without this the
    // absences above would be consistent with a launch that delegated nothing.
    for route in routes {
        assert!(
            section(&attack.stdout, route).contains(&delegated_value),
            "a delegated variable did not reach the child through `{route}`, so the withheld one's \
             absence is not attributable to the posture: {:?}",
            section(&attack.stdout, route)
        );
    }

    // The finding probe.
    let probe = section(&attack.stdout, "PROBE");
    let finding = if !probe.contains("GREP-WORKS") {
        "FINDING PROBE INCONCLUSIVE: the command-line sweep's own positive control did not fire, so its \
         silence establishes nothing"
    } else if probe.contains("CMDLINE-LEAK") {
        "FINDING: the value of a delegated credential is recoverable from a command line in /proc. The \
         lowering passes it as `--env NAME=VALUE`, and /proc/<pid>/cmdline is readable by every process \
         of the same user on the host — so delegating a credential to a confined child also discloses \
         it outside the boundary"
    } else {
        "the command-line sweep's positive control fired and no command line carried the delegated \
         value, so this route was closed on this host"
    };
    println!("PROBE [{scenario}]: {finding}");

    let credential = backend
        .capabilities()
        .report_for(CapabilityDomain::Credential)
        .cloned()
        .expect("reported");
    assert!(
        !credential.can_prevent(),
        "the credential domain reports that it prevents. {finding}"
    );
    assert!(
        matches!(credential.support(), SupportLevel::Partial { .. }),
        "the credential domain stopped stating its limitations: {credential:?}"
    );

    // Removed means removed, and the evidence must not report residue that is
    // not there — the pair that keeps "was removed" and "could not be removed"
    // apart.
    let residual = evidence
        .records_for(CapabilityDomain::Credential)
        .find(|r| r.detail.starts_with("residual authority"))
        .unwrap_or_else(|| panic!("no residual-authority record: {:?}", evidence.records()));
    assert!(
        residual.detail.contains("none beyond the three standard descriptors"),
        "a launch that replaced the environment reported residue it does not have: {}",
        residual.detail
    );
    assert_no_prevention_claim("sandlock, after a measured environment replacement", &evidence);

    std::env::remove_var("X_AA5712_ENUM_SECRET_TOKEN");
    std::env::remove_var("X_AA5712_ENUM_CORRELATION_ID");
    measured(
        scenario,
        AttackFamily::CredentialEnumeration,
        &format!("{detail}. {finding}"),
    );
}

/// The `TAG=`-prefixed segment of a script's `;`-separated output.
///
/// Returns `""` when the tag is absent, which every caller reads as "this route
/// produced nothing" — the honest answer, and the one that makes an attack read
/// as *not* having landed rather than as having landed with empty content.
///
/// Matched on the whole tag rather than as a prefix: `ENV` is a prefix of
/// `ENVIRON`, and a prefix match would hand the second route's output to the
/// first one's assertion the moment the first route produced nothing.
fn section<'a>(stdout: &'a str, tag: &str) -> &'a str {
    stdout
        .split(';')
        .find_map(|segment| segment.split_once('=').filter(|(key, _)| *key == tag))
        .map_or("", |(_, value)| value)
}

// ---------------------------------------------------------------------------
// Coverage of the families themselves.
// ---------------------------------------------------------------------------

/// Every attack family this suite declares is represented by a scenario in one
/// of the two files.
///
/// A **set**, not a count: "twelve families" is equally consistent with the
/// twelve that exist and with eleven plus a duplicate. The list below is written
/// out so that adding a family to `AttackFamily` without adding a scenario fails
/// here, rather than leaving a family that reads as covered because it is in the
/// enum.
///
/// **What it cannot catch, and what does.** Both sides are hand-written
/// constants, so deleting a scenario leaves this green: the `covered` list keeps
/// saying a family is represented whether or not a scenario for it still exists.
/// The `isolation-backend-linux` job closes that half from the other direction,
/// by diffing the scenario names the ledger carries *after a run* against
/// `.ci/isolation-lane-scenarios.txt` — a second artifact, which reddens on a
/// deletion.
///
/// **Gated to Linux**, because the two `UnixSocketsAndDescriptors` scenarios
/// both carry `#[cfg(target_os = "linux")]`. Off Linux that family is absent
/// from the binary, so making this claim there would state coverage the build
/// does not contain.
#[cfg(target_os = "linux")]
#[test]
fn every_declared_attack_family_has_a_scenario() {
    let scenario = "adversarial: every declared attack family has a scenario";
    let covered: BTreeSet<AttackFamily> = [
        // adversarial_boundary_linux.rs
        AttackFamily::ForbiddenFilesystemRead,
        AttackFamily::ForbiddenFilesystemWrite,
        AttackFamily::ProcessInspection,
        AttackFamily::DirectEgressBypass,
        AttackFamily::CloudMetadata,
        AttackFamily::AddressRepresentation,
        AttackFamily::UnixSocketsAndDescriptors,
        AttackFamily::ProcessTreeAndAlternateExecutables,
        AttackFamily::CredentialEnumeration,
        // adversarial_negotiation.rs
        AttackFamily::SyscallAndResource,
        AttackFamily::BackendPosture,
        AttackFamily::ObserveAndDegradedTruthfulness,
    ]
    .into_iter()
    .collect();
    assert_eq!(
        covered,
        AttackFamily::ALL.iter().copied().collect::<BTreeSet<_>>(),
        "a declared attack family has no scenario, or a scenario claims a family that is not declared"
    );
    measured(
        scenario,
        AttackFamily::ObserveAndDegradedTruthfulness,
        "all twelve declared attack families are represented by a scenario",
    );
}
