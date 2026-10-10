//! The backend planner evaluated against the three REAL backends' own
//! capability-reporting logic (AAASM-6296, QA ST-9, journey J88).
//!
//! `aa-isolation`'s planner tests use synthetic candidates, and the only
//! pre-existing real-backend control (`aa-isolation-macos-vm/tests/
//! planner_positive_control.rs`) covers one backend and one domain. This file
//! closes the gap on a host that has none of the kernels: each backend's pure
//! `capability::discover` is the same function its live `discover()` calls once
//! a probe has run, so feeding it a *measured-shape* probe (`Denied` /
//! `Permitted` / `Inconclusive`) exercises the real reporting logic with no
//! Linux kernel or VM needed. What this does NOT prove is that a live probe
//! returns `Denied` on a Linux kernel — that is the Linux real-kernel lane, not
//! measured here.
//!
//! **FIXTURES:** every probe and `HostFacts` below is a fabricated, labelled
//! fixture (`for_test`); nothing here is a live measurement of a kernel or VM.
//!
//! The probes are fabricated inputs by design, so the expectations below are
//! stated as consequences of each backend's *documented* mechanism coverage
//! (sandlock: filesystem + network + process ceiling, no syscall allow-list;
//! native: filesystem + syscall + descriptor ceiling, no network; macOS VM:
//! filesystem only) AND paired with controls that move the probe and watch the
//! verdict move, so a planner that ignored the report could not pass.

use aa_isolation::planner::{evaluate_candidate, select, Candidate, Selection};
use aa_isolation::{
    BackendIdentity, CandidateVerdict, CapabilityDomain, ControlRequirement, Provenance, RuntimeRequirements,
};

const FS: CapabilityDomain = CapabilityDomain::FilesystemWrite;
const NET: CapabilityDomain = CapabilityDomain::NetworkEgress;
const SYS: CapabilityDomain = CapabilityDomain::Syscall;

fn identity(id: &str) -> BackendIdentity {
    BackendIdentity {
        id: id.to_string(),
        version: "qa".to_string(),
        provenance: Provenance {
            source: "aa-cli planner_real_backend_matrix".to_string(),
            license: "Apache-2.0".to_string(),
            modified: false,
        },
    }
}

// --- Real reporting logic, driven by measured-shape probes -----------------

fn sandlock(fs_write: aa_isolation_sandlock::Observation) -> Candidate {
    use aa_isolation_sandlock::{ConfinementProbe, HostFacts, KernelVersion, Observation};
    let facts = HostFacts::for_test("/qa/sandlock", "qa", KernelVersion::parse("6.8")).with_landlock_abi(Some(4));
    let probe = ConfinementProbe {
        filesystem_read: Observation::Denied,
        filesystem_write: fs_write,
        process_ceiling: Observation::Denied,
        network_egress: Observation::Denied,
    };
    Candidate::new(
        identity(aa_isolation_sandlock::BACKEND_ID),
        aa_isolation_sandlock::capability::discover(&facts, &probe, &[]),
    )
}

fn native(fs_write: aa_isolation_native::Observation) -> Candidate {
    use aa_isolation_native::{AbiFloor, ConfinementProbe, HostFacts, Observation};
    let facts = HostFacts::for_test("/qa/launcher", AbiFloor::Met { measured: 5 });
    let probe = ConfinementProbe {
        filesystem_read: Observation::Denied,
        filesystem_write: fs_write,
        syscall: Observation::Denied,
        descriptor_ceiling: Observation::Denied,
    };
    Candidate::new(
        identity(aa_isolation_native::BACKEND_ID),
        aa_isolation_native::capability::discover(&facts, &probe),
    )
}

fn macos_vm() -> Candidate {
    use aa_isolation_macos_vm::probe::{GuestProbe, Observation};
    Candidate::new(
        identity(aa_isolation_macos_vm::BACKEND_ID),
        aa_isolation_macos_vm::capability::discover(&GuestProbe {
            filesystem_read: Observation::Denied,
            filesystem_write: Observation::Denied,
        }),
    )
}

/// The CLI's own fixed walk order (`auto_select`'s `CANDIDATES`).
fn walk() -> Vec<Candidate> {
    vec![
        sandlock(aa_isolation_sandlock::Observation::Denied),
        native(aa_isolation_native::Observation::Denied),
        macos_vm(),
    ]
}

fn prevent(domains: &[CapabilityDomain]) -> RuntimeRequirements {
    domains.iter().fold(RuntimeRequirements::new(), |r, d| {
        r.with_confinement(ControlRequirement::prevent(*d))
    })
}

fn selected(selection: &Selection) -> Option<String> {
    match selection {
        Selection::Selected { identity, .. } => Some(identity.id.clone()),
        Selection::Refused => None,
    }
}

// --- The matrix: backend x domain ------------------------------------------

/// Which (backend, domain) pairs the real reporting logic says can be
/// prevented, given a probe that observed every measured action denied.
#[test]
fn each_real_backend_can_plan_only_the_domains_its_mechanism_covers() {
    let sandlock_id = aa_isolation_sandlock::BACKEND_ID;
    let native_id = aa_isolation_native::BACKEND_ID;
    let vm_id = aa_isolation_macos_vm::BACKEND_ID;

    // (backend id, domain, expected eligible)
    let expected = [
        (sandlock_id, FS, true),
        (sandlock_id, NET, true),
        (sandlock_id, SYS, false),
        (native_id, FS, true),
        (native_id, NET, false),
        (native_id, SYS, true),
        (vm_id, FS, true),
        (vm_id, NET, false),
        (vm_id, SYS, false),
    ];

    for candidate in walk() {
        for (id, domain, eligible) in expected.iter().filter(|(id, _, _)| *id == candidate.identity.id) {
            let verdict = evaluate_candidate(&prevent(&[*domain]), &candidate);
            assert_eq!(
                verdict.is_ok(),
                *eligible,
                "{id} x {domain:?}: expected eligible={eligible}, got {:?}",
                verdict.as_ref().err().map(|r| r.to_string())
            );
        }
    }
}

/// The walk picks the first backend that covers what was asked, and when no
/// single backend covers the combination it refuses and names all three with
/// the exact domain each is missing — it never grants "the closest" backend.
#[test]
fn the_walk_selects_the_covering_backend_and_refuses_an_uncoverable_combination() {
    let cases: [(&[CapabilityDomain], Option<&str>); 5] = [
        (&[FS], Some(aa_isolation_sandlock::BACKEND_ID)),
        (&[NET], Some(aa_isolation_sandlock::BACKEND_ID)),
        (&[SYS], Some(aa_isolation_native::BACKEND_ID)),
        (&[FS, SYS], Some(aa_isolation_native::BACKEND_ID)),
        // Sandlock lacks syscall, native lacks network, the VM has neither.
        (&[NET, SYS], None),
    ];
    for (domains, expected) in cases {
        let (selection, record) = select(&prevent(domains), &walk());
        assert_eq!(
            selected(&selection).as_deref(),
            expected,
            "domains {domains:?}: {record:?}"
        );
    }

    let (selection, record) = select(&prevent(&[NET, SYS]), &walk());
    assert_eq!(selection, Selection::Refused);
    let by_id = |id: &str| {
        record
            .considered
            .iter()
            .find(|c| c.id == id)
            .expect("every backend is named")
    };
    assert_eq!(record.considered.len(), 3);
    assert_eq!(by_id(aa_isolation_sandlock::BACKEND_ID).unmet_domains, vec![SYS]);
    assert_eq!(by_id(aa_isolation_native::BACKEND_ID).unmet_domains, vec![NET]);
    assert_eq!(by_id(aa_isolation_macos_vm::BACKEND_ID).unmet_domains, vec![NET, SYS]);
    assert!(record
        .considered
        .iter()
        .all(|c| c.verdict == CandidateVerdict::RejectedRequirementsUnmet && !c.detail.trim().is_empty()));
}

// --- Controls: the verdict follows the measurement -------------------------

/// Moving only the filesystem-write observation on sandlock moves the
/// selection from sandlock to native: `Permitted` (the probe watched the write
/// succeed) and `Inconclusive` (nobody could tell) both disqualify, so a
/// backend is never selected on the strength of a mechanism that was not seen
/// to work.
#[test]
fn the_selection_follows_the_probe_observation_not_the_backends_name() {
    let request = prevent(&[FS]);
    let build = |sandlock_fs| {
        vec![
            sandlock(sandlock_fs),
            native(aa_isolation_native::Observation::Denied),
            macos_vm(),
        ]
    };

    let (denied, _) = select(&request, &build(aa_isolation_sandlock::Observation::Denied));
    assert_eq!(selected(&denied).as_deref(), Some(aa_isolation_sandlock::BACKEND_ID));

    for observation in [
        aa_isolation_sandlock::Observation::Permitted,
        aa_isolation_sandlock::Observation::Inconclusive {
            detail: "control run produced no effect".to_string(),
        },
    ] {
        let (selection, record) = select(&request, &build(observation.clone()));
        assert_eq!(
            selected(&selection).as_deref(),
            Some(aa_isolation_native::BACKEND_ID),
            "sandlock observed as {observation:?} must not be selected: {record:?}"
        );
        assert_eq!(
            record.considered[0].verdict,
            CandidateVerdict::RejectedRequirementsUnmet
        );
    }
}

/// With both Linux backends' filesystem observation not `Denied`, only the VM
/// can plan filesystem writes, and when the VM is also absent from the walk the
/// request is refused outright.
#[test]
fn when_no_backend_was_seen_to_deny_the_request_is_refused() {
    let request = prevent(&[FS]);
    let weak = |sandlock_fs, native_fs| vec![sandlock(sandlock_fs), native(native_fs)];

    let (selection, record) = select(
        &request,
        &weak(
            aa_isolation_sandlock::Observation::Permitted,
            aa_isolation_native::Observation::Permitted,
        ),
    );
    assert_eq!(selection, Selection::Refused);
    assert_eq!(record.considered.len(), 2);
    assert!(record
        .considered
        .iter()
        .all(|c| c.verdict == CandidateVerdict::RejectedRequirementsUnmet && c.unmet_domains == vec![FS]));
}

/// Same request, same capabilities, rebuilt from scratch each time: identical
/// selection and identical considered record.
#[test]
fn real_backend_selection_is_deterministic() {
    let request = prevent(&[FS, SYS]);
    let (first, first_record) = select(&request, &walk());
    for _ in 0..50 {
        let (again, record) = select(&request, &walk());
        assert_eq!(again, first);
        assert_eq!(record.considered, first_record.considered);
    }
    assert_eq!(selected(&first).as_deref(), Some(aa_isolation_native::BACKEND_ID));
}

// --- One test per prevention layer ------------------------------------------
//
// `CapabilityReport::can_prevent` is defended in depth by THREE independent
// layers (an unsatisfied prerequisite, the support level, and descendant
// coverage), and a probe that watched a write succeed flips all three. A test
// that only checks the combined verdict cannot notice one layer regressing: the
// other two still refuse (QA found exactly that -- a single-layer mutation left
// every combined-verdict test green). Each test below therefore asserts ONE
// layer directly on the report a real backend produced, so a one-line
// regression of that layer reddens its own test.
//
// Masking, stated explicitly: mutating exactly ONE of these layers in the
// backend crate leaves the COMBINED `can_prevent` / `evaluate_candidate` verdict
// unchanged, because the other two layers still refuse (verified by mutation
// against sandlock: single-layer edits did not redden the combined-verdict
// tests above, and the three-layers-together edit did). That redundancy is
// intentional defence in depth in production, so these tests observe each
// layer on the report itself and do not go through `can_prevent`.

fn report_of(candidate: &Candidate) -> &aa_isolation::CapabilityReport {
    candidate
        .capabilities
        .report_for(FS)
        .expect("the backend reports filesystem_write")
}

fn fs_write_candidates(observation: &str) -> Vec<Candidate> {
    match observation {
        "permitted" => vec![
            sandlock(aa_isolation_sandlock::Observation::Permitted),
            native(aa_isolation_native::Observation::Permitted),
        ],
        "inconclusive" => vec![
            sandlock(aa_isolation_sandlock::Observation::Inconclusive { detail: "qa".into() }),
            native(aa_isolation_native::Observation::Inconclusive { detail: "qa".into() }),
        ],
        _ => vec![
            sandlock(aa_isolation_sandlock::Observation::Denied),
            native(aa_isolation_native::Observation::Denied),
        ],
    }
}

/// Layer 1: a probe that did not see a denial leaves the prerequisite
/// unsatisfied, whatever the other layers say. Control: a `Denied` probe leaves
/// none unsatisfied.
#[test]
fn layer_prerequisite_is_unsatisfied_unless_the_probe_saw_a_denial() {
    for c in fs_write_candidates("denied") {
        assert!(report_of(&c).unsatisfied_prerequisite().is_none(), "{}", c.identity.id);
    }
    for observation in ["permitted", "inconclusive"] {
        for c in fs_write_candidates(observation) {
            assert!(
                report_of(&c).unsatisfied_prerequisite().is_some(),
                "{} / {observation}: a probe that did not see a denial must leave a prerequisite unsatisfied",
                c.identity.id
            );
        }
    }
}

/// Layer 2: a probe that watched the action succeed makes the domain
/// `Unsupported`; one that merely could not tell does not (it is the other
/// layers' job). Control: `Denied` is available.
#[test]
fn layer_support_is_unsupported_when_the_action_was_seen_to_succeed() {
    for c in fs_write_candidates("denied") {
        assert!(report_of(&c).support().is_available(), "{}", c.identity.id);
    }
    for c in fs_write_candidates("permitted") {
        assert!(
            matches!(report_of(&c).support(), aa_isolation::SupportLevel::Unsupported { .. }),
            "{}: a write watched succeeding must be reported Unsupported, was {:?}",
            c.identity.id,
            report_of(&c).support()
        );
    }
}

/// Layer 3: descendant coverage is `ProcessTree` only when a grandchild was
/// observed denied. Control: `Denied` reports `ProcessTree`.
#[test]
fn layer_descendant_coverage_is_process_tree_only_when_a_grandchild_was_denied() {
    for c in fs_write_candidates("denied") {
        assert_eq!(
            report_of(&c).descendants(),
            aa_isolation::DescendantCoverage::ProcessTree,
            "{}",
            c.identity.id
        );
    }
    for observation in ["permitted", "inconclusive"] {
        for c in fs_write_candidates(observation) {
            assert_ne!(
                report_of(&c).descendants(),
                aa_isolation::DescendantCoverage::ProcessTree,
                "{} / {observation}: process-tree coverage must not be claimed without a denial",
                c.identity.id
            );
        }
    }
}

// --- Changing exactly one requested property changes the result -------------

/// Otherwise-identical request, candidates and probes; only the set of demanded
/// domains changes, one domain at a time, so each flip is attributable to the
/// single property that moved.
#[test]
fn changing_exactly_one_demanded_property_flips_the_selected_backend() {
    let (base, _) = select(&prevent(&[FS]), &walk());
    assert_eq!(selected(&base).as_deref(), Some(aa_isolation_sandlock::BACKEND_ID));

    // Adding NET: sandlock still covers FS+NET, so no flip (control).
    let (with_net, _) = select(&prevent(&[FS, NET]), &walk());
    assert_eq!(selected(&with_net).as_deref(), Some(aa_isolation_sandlock::BACKEND_ID));

    // Adding SYS instead: sandlock cannot, so the result flips to native.
    let (with_sys, _) = select(&prevent(&[FS, SYS]), &walk());
    assert_eq!(selected(&with_sys).as_deref(), Some(aa_isolation_native::BACKEND_ID));

    // NET+SYS together: no single backend covers both, success flips to
    // refusal; dropping SYS flips it back.
    let (refused, _) = select(&prevent(&[NET, SYS]), &walk());
    assert_eq!(refused, Selection::Refused);
    let (back, _) = select(&prevent(&[NET]), &walk());
    assert_eq!(selected(&back).as_deref(), Some(aa_isolation_sandlock::BACKEND_ID));
}
