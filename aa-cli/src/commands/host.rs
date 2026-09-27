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
    run_operation(spec, contract, op, &args.project, &[])
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
    let build_op = aa_isolation::HostOperation::XcodeBuild(XcodeBuildRequest::new(
        args.project.clone(),
        XcodeContainer::SwiftPackage,
        scheme,
        configuration,
        destination,
        derived_data,
        BuildAction::Build,
    ));

    let (spec, contract) = match base_spec_and_contract(&args.lease_file, vec![OperationKind::XcodeBuild]) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let known_devices_list = if matches!(build_op, aa_isolation::HostOperation::XcodeBuild(ref r) if matches!(r.destination(), Destination::SimulatorById(_)))
    {
        known_devices().unwrap_or_default()
    } else {
        Vec::new()
    };

    run_operation(spec, contract, build_op, &args.project, &known_devices_list)
}

fn simulator_list() -> ExitCode {
    let op = aa_isolation::HostOperation::SimulatorList(Default::default());
    let identity = IdentityRef::root("aasm-host-operator");
    let spec = ExecutionSpec::new("aasm-host", identity);
    run_operation(
        spec,
        HostCapabilityContract::not_required(),
        op,
        &PathBuf::from("."),
        &[],
    )
}

/// Shared gate-then-perform path for every subcommand above.
fn run_operation(
    spec: ExecutionSpec,
    contract: HostCapabilityContract,
    op: aa_isolation::HostOperation,
    project_root: &Path,
    known_devices_list: &[String],
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

    let known_schemes_list = if matches!(op, aa_isolation::HostOperation::XcodeBuild(_)) {
        known_schemes(project_root).unwrap_or_default()
    } else {
        Vec::new()
    };

    let permitted_read = vec![project_root.to_path_buf()];
    let permitted_write = vec![project_root.to_path_buf()];
    let requested_scope = spec
        .requirements()
        .iter()
        .find(|r| r.domain() == CapabilityDomain::ProcessCreation)
        .map(|r| r.scope().clone())
        .unwrap_or(RequirementScope::Whole);

    let host_witness = match host_capability_gate(
        &contract,
        &broker,
        &authority,
        &op,
        &permitted_read,
        &permitted_write,
        &requested_scope,
        &known_schemes_list,
        known_devices_list,
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
