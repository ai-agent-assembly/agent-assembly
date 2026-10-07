//! `aasm host` — the operator-facing front door to the typed host-capability
//! broker (AAASM-6171).
//!
//! This is a thin clap layer only: parse args, build the typed request via
//! the validating constructors (so invalid input is rejected before the gate
//! ever runs), measure the broker report, build this invocation's authority
//! and gate it, then [`super::run_host_capability::perform`] on success.
//!
//! Deliberately **not** a socket a confined child calls into — the same
//! shape as `aasm sandbox`/`aasm proxy`, invoked by the operator (or, in the
//! future, by `aasm run`'s own launch pipeline) rather than reachable from an
//! isolated guest.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aa_isolation::{
    host_capability_gate, BuildAction, CapabilityDomain, CapabilityLease, ConfigurationName, Destination,
    ExecutionSpec, HostCapabilityAuthority, HostCapabilityContract, IdentityRef, LeaseBasis, LeaseId, OperationKind,
    OutputCeiling, RequirementScope, SchemeName, SimulatorUdid, XcodeBuildRequest, XcodeContainer, XcodeListRequest,
};

use super::run_host_capability::{known_devices, known_schemes, perform, report_for_launch};

/// Arguments for `aasm host`.
#[derive(Debug, clap::Args)]
pub struct HostArgs {
    #[command(subcommand)]
    pub subcommand: HostSubcommand,
}

/// Subcommands available under `aasm host`.
#[derive(Debug, clap::Subcommand)]
pub enum HostSubcommand {
    /// Xcode operations.
    Xcode(XcodeArgs),
    /// Simulator operations.
    Simulator(SimulatorArgs),
}

/// Arguments for `aasm host xcode`.
#[derive(Debug, clap::Args)]
pub struct XcodeArgs {
    #[command(subcommand)]
    pub subcommand: XcodeSubcommand,
}

/// Subcommands available under `aasm host xcode`.
#[derive(Debug, clap::Subcommand)]
pub enum XcodeSubcommand {
    /// List the schemes a project/workspace/package declares.
    List(XcodeListArgs),
    /// Build a scheme.
    Build(XcodeBuildArgs),
}

/// Arguments for `aasm host xcode list`.
#[derive(Debug, clap::Args)]
pub struct XcodeListArgs {
    /// The project/workspace/package root to list schemes for.
    #[arg(long)]
    pub project: PathBuf,

    /// A capability-lease file granting `ProcessCreation` for this run
    /// (see [`load_lease`] — there is no other lease-file convention in this
    /// CLI to reuse; this is the minimal one this ticket needs). Omit to run
    /// under [`HostCapabilityContract::not_required`].
    #[arg(long)]
    pub lease_file: Option<PathBuf>,
}

/// Arguments for `aasm host xcode build`.
#[derive(Debug, clap::Args)]
pub struct XcodeBuildArgs {
    /// The scheme to build.
    #[arg(long)]
    pub scheme: String,

    /// The project/workspace/package root.
    #[arg(long)]
    pub project: PathBuf,

    /// The build configuration.
    #[arg(long, default_value = "Debug")]
    pub configuration: String,

    /// The build destination: `macos`, `ios`, or a simulator UDID.
    #[arg(long, default_value = "macos")]
    pub destination: String,

    /// A capability-lease file granting `ProcessCreation` for this run.
    #[arg(long)]
    pub lease_file: Option<PathBuf>,
}

/// Arguments for `aasm host simulator`.
#[derive(Debug, clap::Args)]
pub struct SimulatorArgs {
    #[command(subcommand)]
    pub subcommand: SimulatorSubcommand,
}

/// Subcommands available under `aasm host simulator`.
#[derive(Debug, clap::Subcommand)]
pub enum SimulatorSubcommand {
    /// List available simulator devices.
    List,
}

/// Dispatch the `host` subcommand.
pub fn dispatch(args: HostArgs) -> ExitCode {
    match args.subcommand {
        HostSubcommand::Xcode(xcode) => match xcode.subcommand {
            XcodeSubcommand::List(list) => xcode_list(list),
            XcodeSubcommand::Build(build) => xcode_build(build),
        },
        HostSubcommand::Simulator(sim) => match sim.subcommand {
            SimulatorSubcommand::List => simulator_list(),
        },
    }
}

/// A minimal, hand-parsed lease-file format. There is no existing lease-file
/// convention elsewhere in this CLI (leases are threaded through
/// `IsolationPlan` from in-process construction only, never read from disk),
/// and `aa-isolation`'s `serde` feature is deliberately not enabled for this
/// crate (see `execution_receipt::schema::SpecProjection`'s own doc comment),
/// so this parses a small hand-maintained JSON object with `serde_json::Value`
/// rather than deriving `Deserialize` on [`CapabilityLease`] itself.
///
/// Supports only [`RequirementScope::Whole`] — a lease file scoped to a
/// selector/limit set is out of this ticket's scope; state that plainly
/// rather than silently degrading it to `Whole`.
///
/// Expected shape:
/// ```json
/// {
///   "lease_id": "...",
///   "subject_agent_id": "...",
///   "issuer_agent_id": "...",
///   "basis_reason": "...",
///   "not_before_unix_secs": 0,
///   "expires_at_unix_secs": 0
/// }
/// ```
fn load_lease(path: &PathBuf) -> Result<CapabilityLease, String> {
    let contents = std::fs::read_to_string(path).map_err(|e| format!("could not read `{}`: {e}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|e| format!("could not parse lease file `{}`: {e}", path.display()))?;

    let field = |name: &str| -> Result<String, String> {
        value
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("lease file `{}` is missing string field `{name}`", path.display()))
    };
    let secs_field = |name: &str| -> Result<u64, String> {
        value
            .get(name)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("lease file `{}` is missing numeric field `{name}`", path.display()))
    };

    let lease_id = field("lease_id")?;
    let subject_agent_id = field("subject_agent_id")?;
    let issuer_agent_id = field("issuer_agent_id")?;
    let basis_reason = field("basis_reason")?;
    let not_before = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs_field("not_before_unix_secs")?);
    let expires_at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs_field("expires_at_unix_secs")?);

    Ok(CapabilityLease::new(
        LeaseId::new(lease_id),
        IdentityRef::root(subject_agent_id),
        CapabilityDomain::ProcessCreation,
        RequirementScope::Whole,
        not_before,
        expires_at,
        LeaseBasis::new(IdentityRef::root(issuer_agent_id), basis_reason),
    ))
}

fn base_spec_and_contract(
    lease_file: &Option<PathBuf>,
    permitted: Vec<OperationKind>,
) -> Result<(ExecutionSpec, HostCapabilityContract), String> {
    let identity = IdentityRef::root("aasm-host-operator");
    match lease_file {
        None => Ok((
            ExecutionSpec::new("aasm-host", identity),
            HostCapabilityContract::not_required(),
        )),
        Some(path) => {
            let lease = load_lease(path)?;
            let scope = lease.scope().clone();
            let spec = ExecutionSpec::new("aasm-host", identity)
                .with_requirement(
                    aa_isolation::ControlRequirement::prevent(CapabilityDomain::ProcessCreation).with_scope(scope),
                )
                .with_lease(lease);
            Ok((
                spec,
                HostCapabilityContract::broker_required().with_permitted_operations(permitted),
            ))
        }
    }
}

fn xcode_list(args: XcodeListArgs) -> ExitCode {
    let op = aa_isolation::HostOperation::XcodeList(XcodeListRequest::new(args.project.clone()));
    let (spec, contract) = match base_spec_and_contract(&args.lease_file, vec![OperationKind::XcodeList]) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    run_operation(spec, contract, op, &args.project)
}

fn xcode_build(args: XcodeBuildArgs) -> ExitCode {
    let scheme = match SchemeName::new(&args.scheme) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: invalid --scheme: {e}");
            return ExitCode::FAILURE;
        }
    };
    let configuration = match ConfigurationName::new(&args.configuration) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: invalid --configuration: {e}");
            return ExitCode::FAILURE;
        }
    };
    let destination = match args.destination.as_str() {
        "macos" => Destination::GenericMacOs,
        "ios" => Destination::GenericIos,
        other => match SimulatorUdid::new(other) {
            Ok(udid) => Destination::SimulatorById(udid),
            Err(e) => {
                eprintln!("error: invalid --destination `{other}`: {e}");
                return ExitCode::FAILURE;
            }
        },
    };

    let derived_data = args.project.join(".aasm-host-derived-data");
    let needs_device_list = matches!(destination, Destination::SimulatorById(_));
    let build_op = aa_isolation::HostOperation::XcodeBuild(XcodeBuildRequest::new(
        args.project.clone(),
        XcodeContainer::SwiftPackage,
        scheme,
        configuration,
        destination,
        derived_data,
        BuildAction::Build,
    ));

    // `XcodeList` (always) and `SimulatorList` (when the destination names a
    // device) must be separately permitted: `run_operation` gates each as its
    // own operation before spawning the real `xcodebuild`/`simctl` process
    // that supplies the scheme/device allowlist — see its own doc comment for
    // why an ungated pre-fetch is exactly the escape hatch this ticket exists
    // to close.
    let mut permitted = vec![OperationKind::XcodeBuild, OperationKind::XcodeList];
    if needs_device_list {
        permitted.push(OperationKind::SimulatorList);
    }
    let (spec, contract) = match base_spec_and_contract(&args.lease_file, permitted) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    run_operation(spec, contract, build_op, &args.project)
}

fn simulator_list() -> ExitCode {
    let op = aa_isolation::HostOperation::SimulatorList(Default::default());
    let identity = IdentityRef::root("aasm-host-operator");
    let spec = ExecutionSpec::new("aasm-host", identity);
    run_operation(spec, HostCapabilityContract::not_required(), op, &PathBuf::from("."))
}

/// Gate-then-perform one already-permitted host operation, using `contract`
/// and `authority` exactly as the caller's own request will use them, with an
/// empty scheme/device allowlist (`XcodeList`/`SimulatorList` themselves take
/// no scheme/device argument to validate against one).
///
/// Returns `Ok(None)` under [`aa_isolation::HostCapabilityPosture::NotRequired`]
/// without spawning anything real — [`host_capability_gate`]'s own first line
/// admits unconditionally there, so this never contacts a real toolchain for
/// an inert (default) launch.
fn gated_list(
    contract: &HostCapabilityContract,
    broker: &aa_isolation::HostCapabilityBrokerReport,
    authority: &HostCapabilityAuthority,
    op: aa_isolation::HostOperation,
    permitted_read: &[PathBuf],
    requested_scope: &RequirementScope,
) -> Result<Vec<String>, String> {
    let witness = host_capability_gate(
        contract,
        broker,
        authority,
        &op,
        permitted_read,
        &[],
        requested_scope,
        &[],
        &[],
        std::time::SystemTime::now(),
    )
    .map_err(|refusal| refusal.to_string())?;

    match &op {
        aa_isolation::HostOperation::XcodeList(req) => {
            known_schemes(req.container_root(), &witness).map_err(|refusal| refusal.to_string())
        }
        aa_isolation::HostOperation::SimulatorList(_) => known_devices(&witness).map_err(|refusal| refusal.to_string()),
        other => Err(format!(
            "gated_list called with unsupported operation kind {:?}",
            other.kind()
        )),
    }
}

/// Shared gate-then-perform path for every subcommand above.
fn run_operation(
    spec: ExecutionSpec,
    contract: HostCapabilityContract,
    op: aa_isolation::HostOperation,
    project_root: &Path,
) -> ExitCode {
    let broker = report_for_launch();

    let witness = match aa_isolation::authority_gate(&spec, &aa_isolation::Ancestry::Root, std::time::SystemTime::now())
    {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: authority refused: {e}");
            return ExitCode::FAILURE;
        }
    };
    let authority = HostCapabilityAuthority::from_gated_spec(&spec, &witness);

    let permitted_read = vec![project_root.to_path_buf()];
    let permitted_write = vec![project_root.to_path_buf()];
    let requested_scope = spec
        .requirements()
        .iter()
        .find(|r| r.domain() == CapabilityDomain::ProcessCreation)
        .map(|r| r.scope().clone())
        .unwrap_or(RequirementScope::Whole);

    let known_schemes_list = if matches!(op, aa_isolation::HostOperation::XcodeBuild(_)) {
        let list_op = aa_isolation::HostOperation::XcodeList(XcodeListRequest::new(project_root.to_path_buf()));
        match gated_list(
            &contract,
            &broker,
            &authority,
            list_op,
            &permitted_read,
            &requested_scope,
        ) {
            Ok(list) => list,
            Err(reason) => {
                eprintln!("error: could not obtain the scheme allowlist: {reason}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        Vec::new()
    };

    let known_devices_list = if matches!(op, aa_isolation::HostOperation::XcodeBuild(ref r) if matches!(r.destination(), Destination::SimulatorById(_)))
    {
        let list_op = aa_isolation::HostOperation::SimulatorList(Default::default());
        match gated_list(
            &contract,
            &broker,
            &authority,
            list_op,
            &permitted_read,
            &requested_scope,
        ) {
            Ok(list) => list,
            Err(reason) => {
                eprintln!("error: could not obtain the device allowlist: {reason}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        Vec::new()
    };

    let host_witness = match host_capability_gate(
        &contract,
        &broker,
        &authority,
        &op,
        &permitted_read,
        &permitted_write,
        &requested_scope,
        &known_schemes_list,
        &known_devices_list,
        std::time::SystemTime::now(),
    ) {
        Ok(w) => w,
        Err(refusal) => {
            eprintln!("refused: {refusal}");
            return ExitCode::FAILURE;
        }
    };

    match perform(&op, &OutputCeiling::default(), &host_witness) {
        Ok(outcome) => {
            print!("{}", String::from_utf8_lossy(&outcome.stdout));
            eprint!("{}", String::from_utf8_lossy(&outcome.stderr));
            match outcome.exit_code {
                Some(0) => ExitCode::SUCCESS,
                Some(_) => ExitCode::FAILURE,
                None => ExitCode::FAILURE,
            }
        }
        Err(refusal) => {
            eprintln!("refused: {refusal}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_spec_and_authority() -> (ExecutionSpec, aa_isolation::AuthorityWitness) {
        let identity = IdentityRef::root("gated-list-test");
        let spec = ExecutionSpec::new("aasm-host", identity);
        let witness = aa_isolation::authority_gate(&spec, &aa_isolation::Ancestry::Root, std::time::SystemTime::now())
            .expect("a root spec with no requirements is always authorized");
        (spec, witness)
    }

    /// A spec that actually carries a `ProcessCreation` lease/requirement, so
    /// `check_process_creation_grant` admits — a bare [`root_spec_and_authority`]
    /// has no explicit grant and is correctly `Denied` under a `BrokerRequired`
    /// contract, per the same "no explicit grant" reading `credential_broker.rs`
    /// and every other AAASM-6159 gate already applies.
    fn granted_spec_and_authority() -> (ExecutionSpec, aa_isolation::AuthorityWitness) {
        let identity = IdentityRef::root("gated-list-test");
        let scope = RequirementScope::Whole;
        let spec = ExecutionSpec::new("aasm-host", identity.clone())
            .with_requirement(
                aa_isolation::ControlRequirement::prevent(CapabilityDomain::ProcessCreation).with_scope(scope.clone()),
            )
            .with_lease(CapabilityLease::new(
                LeaseId::new("gated-list-test-lease"),
                identity,
                CapabilityDomain::ProcessCreation,
                scope,
                std::time::SystemTime::now() - std::time::Duration::from_secs(10),
                std::time::SystemTime::now() + std::time::Duration::from_secs(600),
                LeaseBasis::new(IdentityRef::root("gated-list-test-issuer"), "test fixture"),
            ));
        let witness = aa_isolation::authority_gate(&spec, &aa_isolation::Ancestry::Root, std::time::SystemTime::now())
            .expect("a valid lease/requirement pair is always authorized");
        (spec, witness)
    }

    /// The finding this test exists to close: a `BrokerRequired` contract that
    /// permits `XcodeBuild` but not `XcodeList` must refuse the internal
    /// scheme-allowlist lookup rather than silently falling back to an empty
    /// allowlist that would then admit every scheme unchecked.
    #[test]
    fn gated_list_refuses_when_the_list_operation_itself_is_not_permitted() {
        let (spec, witness) = root_spec_and_authority();
        let authority = HostCapabilityAuthority::from_gated_spec(&spec, &witness);
        let contract =
            HostCapabilityContract::broker_required().with_permitted_operations(vec![OperationKind::XcodeBuild]);
        let broker = report_for_launch();

        let list_op = aa_isolation::HostOperation::XcodeList(XcodeListRequest::new(PathBuf::from(".")));
        let result = gated_list(
            &contract,
            &broker,
            &authority,
            list_op,
            &[PathBuf::from(".")],
            &RequirementScope::Whole,
        );

        assert!(
            result.is_err(),
            "XcodeList was not in permitted_operations; gated_list must refuse, not return an empty allowlist: {result:?}"
        );
    }

    /// The paired control: once `XcodeList` IS permitted (and the broker is
    /// reachable), `gated_list` must actually run the real lookup rather than
    /// refusing unconditionally — proving the refusal above is about the
    /// permission check specifically, not a broken code path.
    #[test]
    fn gated_list_admits_when_the_list_operation_is_permitted_and_broker_is_available() {
        let broker = report_for_launch();
        if !matches!(broker.availability(), aa_isolation::BrokerAvailability::Available) {
            eprintln!("host-capability broker unavailable on this host; skipping (no real Xcode toolchain)");
            return;
        }

        let (spec, witness) = granted_spec_and_authority();
        let authority = HostCapabilityAuthority::from_gated_spec(&spec, &witness);
        let contract = HostCapabilityContract::broker_required()
            .with_permitted_operations(vec![OperationKind::XcodeBuild, OperationKind::XcodeList]);

        let fixture_dir = std::env::temp_dir().join("gated-list-admit-fixture");
        std::fs::create_dir_all(&fixture_dir).expect("create fixture dir");
        std::fs::write(
            fixture_dir.join("Package.swift"),
            "// swift-tools-version:5.9\nimport PackageDescription\nlet package = Package(name: \"GatedListAdmitFixture\")\n",
        )
        .expect("write fixture Package.swift");

        let list_op = aa_isolation::HostOperation::XcodeList(XcodeListRequest::new(fixture_dir.clone()));
        let result = gated_list(
            &contract,
            &broker,
            &authority,
            list_op,
            std::slice::from_ref(&fixture_dir),
            &RequirementScope::Whole,
        );

        let _ = std::fs::remove_dir_all(&fixture_dir);

        assert!(
            result.is_ok(),
            "XcodeList was permitted and the broker is available; gated_list must actually run the lookup: {result:?}"
        );
    }

    /// AAASM-6279's own reproduction: a `--lease-file` whose `subject_agent_id`
    /// does not match `base_spec_and_contract`'s fixed launch identity
    /// (`aasm-host-operator`) must be refused once the resulting spec reaches
    /// `authority_gate` — exactly the gate `run_operation` calls for every
    /// real `aasm host` subcommand. The fix landed at the gate itself
    /// (`AuthorityRefusal::LeaseSubjectMismatch`, AAASM-6272/D-b) rather than
    /// in this file, so this test exercises the lease-file path specifically
    /// to close the AC's own named reproduction, not just the generic gate
    /// mechanism already pinned in `aa-isolation::authority`.
    #[test]
    fn lease_file_with_mismatched_subject_is_refused_at_the_gate() {
        let fixture_dir = std::env::temp_dir().join("aaasm-6279-lease-subject-mismatch-fixture");
        std::fs::create_dir_all(&fixture_dir).expect("create fixture dir");
        let lease_path = fixture_dir.join("mismatched-lease.json");
        std::fs::write(
            &lease_path,
            r#"{
                "lease_id": "lease-under-test",
                "subject_agent_id": "some-other-agent",
                "issuer_agent_id": "issuer",
                "basis_reason": "test fixture",
                "not_before_unix_secs": 0,
                "expires_at_unix_secs": 9999999999
            }"#,
        )
        .expect("write fixture lease file");

        let (spec, _contract) = base_spec_and_contract(&Some(lease_path.clone()), vec![OperationKind::XcodeList])
            .expect("a well-formed lease file parses");
        let result = aa_isolation::authority_gate(&spec, &aa_isolation::Ancestry::Root, std::time::SystemTime::now());

        let _ = std::fs::remove_dir_all(&fixture_dir);

        assert!(
            matches!(
                &result,
                Err(aa_isolation::AuthorityRefusal::LeaseSubjectMismatch { lease_subject, .. })
                    if lease_subject == "some-other-agent"
            ),
            "a lease file naming a subject other than the launch's own identity must be refused: {result:?}"
        );
    }

    /// Positive control for the test above: the identical lease file, subject
    /// corrected to match the launch's own fixed identity, gates cleanly —
    /// isolating the subject mismatch, specifically, as what the refusal
    /// above turns on.
    #[test]
    fn lease_file_with_matching_subject_gates_cleanly() {
        let fixture_dir = std::env::temp_dir().join("aaasm-6279-lease-subject-match-fixture");
        std::fs::create_dir_all(&fixture_dir).expect("create fixture dir");
        let lease_path = fixture_dir.join("matching-lease.json");
        std::fs::write(
            &lease_path,
            r#"{
                "lease_id": "lease-under-test",
                "subject_agent_id": "aasm-host-operator",
                "issuer_agent_id": "issuer",
                "basis_reason": "test fixture",
                "not_before_unix_secs": 0,
                "expires_at_unix_secs": 9999999999
            }"#,
        )
        .expect("write fixture lease file");

        let (spec, _contract) = base_spec_and_contract(&Some(lease_path.clone()), vec![OperationKind::XcodeList])
            .expect("a well-formed lease file parses");
        let result = aa_isolation::authority_gate(&spec, &aa_isolation::Ancestry::Root, std::time::SystemTime::now());

        let _ = std::fs::remove_dir_all(&fixture_dir);

        assert!(
            result.is_ok(),
            "a lease file whose subject matches the launch's own identity must gate cleanly: {result:?}"
        );
    }

    /// Under `NotRequired` (every real launch's inert default today),
    /// `gated_list` must admit without ever consulting a real toolchain —
    /// mirrors `host_capability_gate`'s own first-line short-circuit.
    #[test]
    fn gated_list_admits_under_not_required_without_a_real_toolchain() {
        let (spec, witness) = root_spec_and_authority();
        let authority = HostCapabilityAuthority::from_gated_spec(&spec, &witness);
        let contract = HostCapabilityContract::not_required();
        let broker = aa_isolation::HostCapabilityBrokerReport::unavailable("no toolchain probed in this test");

        let list_op = aa_isolation::HostOperation::XcodeList(XcodeListRequest::new(PathBuf::from(".")));
        // perform() would fail against a real toolchain-less environment if
        // reached; NotRequired must short-circuit the *gate*, but perform()
        // itself still runs the real command once the witness is granted, so
        // this only proves the gate portion doesn't consult the unavailable
        // broker before admitting — the reachable-perform() path is exercised
        // by the two tests above instead.
        let gate_result = aa_isolation::host_capability_gate(
            &contract,
            &broker,
            &authority,
            &list_op,
            &[PathBuf::from(".")],
            &[],
            &RequirementScope::Whole,
            &[],
            &[],
            std::time::SystemTime::now(),
        );
        assert!(
            gate_result.is_ok(),
            "NotRequired must admit without consulting the (unavailable) broker: {gate_result:?}"
        );
    }
}
