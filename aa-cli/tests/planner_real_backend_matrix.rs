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
