//! Measure this host's Xcode/Simulator toolchain and perform a gated host
//! operation (AAASM-6171).
//!
//! [`report_for_launch`] never asserts availability from `cfg!(target_os =
//! "macos")` alone — it runs `xcode-select`/`xcrun`/`xcodebuild` as real
//! subprocess calls and reports [`aa_isolation::HostCapabilityBrokerReport::unavailable`]
//! on any failure. [`perform`] is the **only** place in this crate that spawns
//! a `Command` for a [`aa_isolation::HostOperation`] — it requires a
//! [`aa_isolation::HostCapabilityWitness`] to do so, which only
//! [`aa_isolation::host_capability_gate`] can construct.
//!
//! # Privilege posture
//!
//! This repository has no setuid/entitlement/XPC privilege separation
//! relevant to this ticket. The broker runs as the caller's own UID
//! (required — `xcodebuild` needs that UID's own Xcode/DerivedData access).
//! "Least host privilege practical" is satisfied by: [`std::process::Command::env_clear`]
//! plus the fixed three-variable [`broker_environment`], a null stdin, no
//! inherited fds beyond piped stdio, `current_dir` pinned to the already
//! scope-checked project root, an argv built exclusively by
//! [`aa_isolation::to_argv`], and no shell invocation ever. This is **not** a
//! privilege drop — there is no lower-privileged identity this process could
//! drop to and still let `xcodebuild` read the caller's own Xcode installation.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aa_isolation::{
    to_argv, HostCapabilityBrokerReport, HostCapabilityRefusal, HostCapabilityWitness, HostOperation, OperationKind,
    OutputCeiling, ToolchainFact,
};

/// Run a subprocess to completion under a fully cleared environment except
/// for `PATH`, and return trimmed stdout on success.
fn probe(program: &str, args: &[&str], path: &str) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to spawn `{program}`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{program} {}` exited with {:?}: {}",
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Measure this host's Xcode/Simulator toolchain via real subprocess calls.
/// Never assumed from `cfg!(target_os = "macos")` alone. Any measurement
/// failure yields [`HostCapabilityBrokerReport::unavailable`] with the actual
/// reason.
pub fn report_for_launch() -> HostCapabilityBrokerReport {
    let bootstrap_path = "/usr/bin:/bin";

    let developer_dir = match probe("xcode-select", &["-p"], bootstrap_path) {
        Ok(dir) => dir,
        Err(reason) => return HostCapabilityBrokerReport::unavailable(format!("`xcode-select -p` failed: {reason}")),
    };

    let path =
        format!("{developer_dir}/usr/bin:{developer_dir}/Toolchains/XcodeDefault.xctoolchain/usr/bin:/usr/bin:/bin");

    let xcodebuild_path = match probe("xcrun", &["--find", "xcodebuild"], &path) {
        Ok(p) => p,
        Err(reason) => {
            return HostCapabilityBrokerReport::unavailable(format!("`xcrun --find xcodebuild` failed: {reason}"))
        }
    };
    let simctl_path = match probe("xcrun", &["--find", "simctl"], &path) {
        Ok(p) => p,
        Err(reason) => {
            return HostCapabilityBrokerReport::unavailable(format!("`xcrun --find simctl` failed: {reason}"))
        }
    };
    let version_output = match probe("xcodebuild", &["-version"], &path) {
        Ok(v) => v,
        Err(reason) => {
            return HostCapabilityBrokerReport::unavailable(format!("`xcodebuild -version` failed: {reason}"))
        }
    };
    let version = version_output.lines().next().unwrap_or("unknown").to_string();

    HostCapabilityBrokerReport::new(aa_isolation::capability::FailurePosture::FailClosed)
        .with_toolchain_fact(ToolchainFact {
            tool: "xcodebuild".to_string(),
            version: version.clone(),
            resolved_path: xcodebuild_path.clone(),
        })
        .with_toolchain_fact(ToolchainFact {
            tool: "simctl".to_string(),
            version: version.clone(),
            resolved_path: simctl_path,
        })
        .with_operation(aa_isolation::BrokeredOperation {
            kind: OperationKind::XcodeList,
            mechanism_detail: format!("measured `xcodebuild -list -json` via {xcodebuild_path}"),
        })
        .with_operation(aa_isolation::BrokeredOperation {
            kind: OperationKind::XcodeBuild,
            mechanism_detail: format!("measured `xcodebuild build` via {xcodebuild_path} ({version})"),
        })
        .with_operation(aa_isolation::BrokeredOperation {
            kind: OperationKind::SimulatorList,
            mechanism_detail: "measured `simctl list devices available -j`".to_string(),
        })
}

/// This launch's `DEVELOPER_DIR`, from `xcode-select -p`.
pub fn developer_dir() -> Result<PathBuf, String> {
    probe("xcode-select", &["-p"], "/usr/bin:/bin").map(PathBuf::from)
}

/// The exact three-variable environment every host-broker invocation runs
/// under: nothing else survives `env_clear()`. See the module documentation's
/// "Privilege posture" for why this, and only this, is the claim this build
/// makes.
fn broker_environment(developer_dir: &Path) -> BTreeMap<String, String> {
    let dd = developer_dir.display().to_string();
    let mut env = BTreeMap::new();
    env.insert(
        "PATH".to_string(),
        format!("{dd}/usr/bin:{dd}/Toolchains/XcodeDefault.xctoolchain/usr/bin:/usr/bin:/bin"),
    );
    env.insert("HOME".to_string(), std::env::var("HOME").unwrap_or_default());
    env.insert("DEVELOPER_DIR".to_string(), dd);
    env
}

/// The outcome of a performed [`HostOperation`].
#[derive(Debug, Clone)]
pub struct HostOutcome {
    /// The operation kind that was performed.
    pub kind: OperationKind,
    /// The process's exit code, when one was observed.
    pub exit_code: Option<i32>,
    /// Captured stdout, truncated at the ceiling.
    pub stdout: Vec<u8>,
    /// Captured stderr, truncated at the ceiling.
    pub stderr: Vec<u8>,
    /// Whether stdout or stderr was truncated at the ceiling.
    pub output_truncated: bool,
    /// A digest of the argv actually invoked. Never the argv values
    /// themselves.
    pub argv_digest: String,
}

/// Perform a gated host operation.
///
/// `_witness` is not read beyond proving [`aa_isolation::host_capability_gate`]
/// already admitted this call — this is the **only** function in this crate
/// that spawns a `Command` for a [`HostOperation`].
///
/// Uses `env_clear()` + [`broker_environment`], `current_dir` pinned to the
/// operation's own project/container root, argv from [`to_argv`] only, a null
/// stdin, piped stdout/stderr truncated at `ceiling`'s byte limits, and a
/// wall-clock bound enforced via a `try_wait()` poll loop (no timeout crate).
pub fn perform(
    op: &HostOperation,
    ceiling: &OutputCeiling,
    _witness: &HostCapabilityWitness,
) -> Result<HostOutcome, HostCapabilityRefusal> {
    let dd = developer_dir().map_err(|reason| HostCapabilityRefusal::ToolchainUnavailable { reason })?;
    let env = broker_environment(&dd);

    // Resolve the real program via `xcrun --find` rather than assuming a
    // fixed absolute path — the toolchain path is versioned per Xcode
    // install.
    let resolved = resolve_program(op.kind(), &env["PATH"])?;

    let argv = to_argv(op, &resolved).map_err(HostCapabilityRefusal::ArgumentRejected)?;

    let cwd = current_dir_for(op);

    let mut command = Command::new(&argv.program);
    command.args(&argv.args).env_clear();
    for (k, v) in &env {
        command.env(k, v);
    }
    if let Some(dir) = &cwd {
        command.current_dir(dir);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| HostCapabilityRefusal::ToolchainUnavailable {
            reason: format!("failed to spawn `{}`: {e}", argv.program.display()),
        })?;

    let deadline = ceiling
        .wall_clock_secs
        .map(|secs| Instant::now() + Duration::from_secs(secs));
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut truncated = false;
    if let Some(mut out) = child.stdout.take() {
        truncated |= read_truncated(&mut out, ceiling.max_stdout_bytes, &mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        truncated |= read_truncated(&mut err, ceiling.max_stderr_bytes, &mut stderr);
    }

    let argv_digest = digest_argv(&argv);

    Ok(HostOutcome {
        kind: op.kind(),
        exit_code: exit_status.and_then(|s| s.code()),
        stdout,
        stderr,
        output_truncated: truncated,
        argv_digest,
    })
}

fn read_truncated(reader: &mut impl Read, max_bytes: usize, out: &mut Vec<u8>) -> bool {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return false,
            Ok(n) => {
                let remaining = max_bytes.saturating_sub(out.len());
                if remaining == 0 {
                    return true;
                }
                let take = remaining.min(n);
                out.extend_from_slice(&buf[..take]);
                if take < n {
                    return true;
                }
            }
            Err(_) => return out.len() >= max_bytes,
        }
    }
}

fn digest_argv(argv: &aa_isolation::HostArgv) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    argv.program.hash(&mut hasher);
    argv.args.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn program_name(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::XcodeList | OperationKind::XcodeBuild => "xcodebuild",
        OperationKind::SimulatorList => "simctl",
        OperationKind::Codesign => "codesign",
        // `OperationKind` is `#[non_exhaustive]` — a future variant added in
        // `aa-isolation` without a matching program name here fails loudly at
        // `resolve_program` time (`xcrun --find <unknown>`) rather than
        // silently, since there is no sensible default program to fall back
        // to.
        _ => "unknown-host-operation",
    }
}

fn resolve_program(kind: OperationKind, path: &str) -> Result<PathBuf, HostCapabilityRefusal> {
    let name = program_name(kind);
    probe("xcrun", &["--find", name], path)
        .map(PathBuf::from)
        .map_err(|reason| HostCapabilityRefusal::ToolchainUnavailable {
            reason: format!("could not resolve `{name}`: {reason}"),
        })
}

fn current_dir_for(op: &HostOperation) -> Option<PathBuf> {
    match op {
        HostOperation::XcodeList(req) => Some(req.container_root().to_path_buf()),
        HostOperation::XcodeBuild(req) => Some(req.project_root().to_path_buf()),
        HostOperation::SimulatorList(_) | HostOperation::Codesign(_) => None,
        _ => None,
    }
}

/// Parse `xcodebuild -list -json` run against `container_root`. A SwiftPM
/// package reports schemes under a `"workspace"` JSON key (empirically
/// confirmed on this build's toolchain); an `.xcodeproj` reports under a
/// `"project"` key. Both are handled.
pub fn known_schemes(container_root: &Path) -> Result<Vec<String>, HostCapabilityRefusal> {
    let dd = developer_dir().map_err(|reason| HostCapabilityRefusal::ToolchainUnavailable { reason })?;
    let env = broker_environment(&dd);
    let resolved = resolve_program(OperationKind::XcodeList, &env["PATH"])?;

    let mut command = Command::new(&resolved);
    command.args(["-list", "-json"]).env_clear();
    for (k, v) in &env {
        command.env(k, v);
    }
    command.current_dir(container_root);
    command.stdin(Stdio::null());

    let output = command
        .output()
        .map_err(|e| HostCapabilityRefusal::ToolchainUnavailable {
            reason: format!("failed to run `xcodebuild -list -json`: {e}"),
        })?;
    if !output.status.success() {
        return Err(HostCapabilityRefusal::ToolchainUnavailable {
            reason: format!(
                "`xcodebuild -list -json` exited with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
        });
    }

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| HostCapabilityRefusal::ToolchainUnavailable {
            reason: format!("could not parse `xcodebuild -list -json` output: {e}"),
        })?;

    let container = parsed
        .get("workspace")
        .or_else(|| parsed.get("project"))
        .ok_or_else(|| HostCapabilityRefusal::ToolchainUnavailable {
            reason: "`xcodebuild -list -json` reported neither a `workspace` nor a `project` key".to_string(),
        })?;

    let schemes = container
        .get("schemes")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    Ok(schemes)
}

/// Parse `simctl list devices available -j` for known device UDIDs.
pub fn known_devices() -> Result<Vec<String>, HostCapabilityRefusal> {
    let dd = developer_dir().map_err(|reason| HostCapabilityRefusal::ToolchainUnavailable { reason })?;
    let env = broker_environment(&dd);
    let resolved = resolve_program(OperationKind::SimulatorList, &env["PATH"])?;

    let mut command = Command::new(&resolved);
    command.args(["list", "devices", "available", "-j"]).env_clear();
    for (k, v) in &env {
        command.env(k, v);
    }
    command.stdin(Stdio::null());

    let output = command
        .output()
        .map_err(|e| HostCapabilityRefusal::ToolchainUnavailable {
            reason: format!("failed to run `simctl list devices available -j`: {e}"),
        })?;
    if !output.status.success() {
        return Err(HostCapabilityRefusal::ToolchainUnavailable {
            reason: format!(
                "`simctl list devices available -j` exited with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
        });
    }

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| HostCapabilityRefusal::ToolchainUnavailable {
            reason: format!("could not parse `simctl list devices` output: {e}"),
        })?;

    let mut udids = Vec::new();
    if let Some(devices_by_runtime) = parsed.get("devices").and_then(|v| v.as_object()) {
        for devices in devices_by_runtime.values() {
            if let Some(arr) = devices.as_array() {
                for device in arr {
                    if let Some(udid) = device.get("udid").and_then(|v| v.as_str()) {
                        udids.push(udid.to_string());
                    }
                }
            }
        }
    }
    Ok(udids)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether a real Xcode toolchain is available on this machine. Every
    /// host-gated test below checks this first and returns early with a
    /// clear reason rather than silently passing or failing the whole binary.
    fn xcode_available() -> Option<HostCapabilityBrokerReport> {
        let report = report_for_launch();
        match report.availability() {
            aa_isolation::BrokerAvailability::Available => Some(report),
            aa_isolation::BrokerAvailability::Unavailable { .. } => None,
        }
    }

    #[test]
    fn report_for_launch_never_asserts_availability_without_a_real_probe() {
        // This is itself the no-Xcode-required control: whatever this host
        // reports, it must be backed by an actual subprocess result, not a
        // `cfg!(target_os = "macos")` shortcut. We can't observe the probe
        // directly from here, but we can assert the report is internally
        // consistent: unavailable never carries toolchain facts or operations.
        let report = report_for_launch();
        if matches!(
            report.availability(),
            aa_isolation::BrokerAvailability::Unavailable { .. }
        ) {
            assert!(report.toolchain().is_empty());
            assert!(report.operations().is_empty());
        }
    }

    #[test]
    fn end_to_end_swiftpm_build_succeeds_when_xcode_is_available() {
        let Some(_report) = xcode_available() else {
            eprintln!("SKIP: no real Xcode toolchain is available on this host (xcode-select -p failed)");
            return;
        };

        let fixture_dir = std::env::temp_dir().join(format!("aa-hc-fixture-{}", std::process::id()));
        let src_dir = fixture_dir.join("Sources").join("HCFixture");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(
            fixture_dir.join("Package.swift"),
            "// swift-tools-version:5.9\nimport PackageDescription\n\nlet package = Package(\n    name: \"HCFixture\",\n    targets: [\n        .executableTarget(name: \"HCFixture\")\n    ]\n)\n",
        )
        .unwrap();
        std::fs::write(src_dir.join("main.swift"), "print(\"hcfixture ok\")\n").unwrap();

        let derived_data = fixture_dir.join("dd");

        let op = aa_isolation::HostOperation::XcodeBuild(aa_isolation::XcodeBuildRequest::new(
            fixture_dir.clone(),
            aa_isolation::XcodeContainer::SwiftPackage,
            aa_isolation::SchemeName::new("HCFixture").unwrap(),
            aa_isolation::ConfigurationName::new("Debug").unwrap(),
            aa_isolation::Destination::GenericMacOs,
            derived_data.clone(),
            aa_isolation::BuildAction::Build,
        ));

        // Drive the full pipeline: contract -> broker -> authority -> gate ->
        // perform, rather than calling `perform` directly, so this test
        // exercises the same path a real `aasm host xcode build` invocation
        // does.
        let contract = aa_isolation::HostCapabilityContract::broker_required()
            .with_permitted_operations(vec![OperationKind::XcodeBuild]);
        let broker = report_for_launch();

        let identity = aa_isolation::IdentityRef::root("hc-fixture-test");
        let scope = aa_isolation::RequirementScope::Whole;
        let spec = aa_isolation::ExecutionSpec::new("xcodebuild", identity.clone())
            .with_requirement(
                aa_isolation::ControlRequirement::prevent(aa_isolation::CapabilityDomain::ProcessCreation)
                    .with_scope(scope.clone()),
            )
            .with_lease(aa_isolation::CapabilityLease::new(
                aa_isolation::LeaseId::new("hc-fixture-lease"),
                identity,
                aa_isolation::CapabilityDomain::ProcessCreation,
                scope.clone(),
                std::time::SystemTime::now() - Duration::from_secs(10),
                std::time::SystemTime::now() + Duration::from_secs(600),
                aa_isolation::LeaseBasis::new(aa_isolation::IdentityRef::root("test-issuer"), "test fixture"),
            ));

        let witness = aa_isolation::authority_gate(&spec, &aa_isolation::Ancestry::Root, std::time::SystemTime::now())
            .expect("spec authorized in this fixture");
        let authority = aa_isolation::HostCapabilityAuthority::from_gated_spec(&spec, &witness);

        let known = known_schemes(&fixture_dir).expect("known_schemes should succeed against the fixture");
        assert!(known.contains(&"HCFixture".to_string()), "known schemes: {known:?}");

        let host_witness = aa_isolation::host_capability_gate(
            &contract,
            &broker,
            &authority,
            &op,
            std::slice::from_ref(&fixture_dir),
            std::slice::from_ref(&fixture_dir),
            &scope,
            &known,
            &[],
            std::time::SystemTime::now(),
        )
        .expect("gate should admit this build");

        let outcome = perform(&op, &OutputCeiling::default(), &host_witness).expect("build should succeed");
        std::fs::remove_dir_all(&fixture_dir).ok();

        assert_eq!(
            outcome.exit_code,
            Some(0),
            "stdout: {}",
            String::from_utf8_lossy(&outcome.stdout)
        );
        let stdout = String::from_utf8_lossy(&outcome.stdout);
        assert!(stdout.contains("BUILD SUCCEEDED"), "stdout: {stdout}");
    }

    #[test]
    fn unauthorized_scheme_is_refused_when_xcode_is_available() {
        if xcode_available().is_none() {
            eprintln!("SKIP: no real Xcode toolchain is available on this host");
            return;
        }
        let known = vec!["ARealScheme".to_string()];
        let op = aa_isolation::HostOperation::XcodeBuild(aa_isolation::XcodeBuildRequest::new(
            PathBuf::from("/tmp"),
            aa_isolation::XcodeContainer::SwiftPackage,
            aa_isolation::SchemeName::new("NotARealScheme").unwrap(),
            aa_isolation::ConfigurationName::new("Debug").unwrap(),
            aa_isolation::Destination::GenericMacOs,
            PathBuf::from("/tmp/dd"),
            aa_isolation::BuildAction::Build,
        ));
        assert!(matches!(
            aa_isolation::check_host_capability_arguments(&op, &known, &[]),
            Err(HostCapabilityRefusal::UnknownScheme { .. })
        ));
    }

    #[test]
    fn unauthorized_simulator_device_is_refused() {
        let known_devices = vec!["11111111-1111-1111-1111-111111111111".to_string()];
        let op = aa_isolation::HostOperation::XcodeBuild(aa_isolation::XcodeBuildRequest::new(
            PathBuf::from("/tmp"),
            aa_isolation::XcodeContainer::SwiftPackage,
            aa_isolation::SchemeName::new("AnyScheme").unwrap(),
            aa_isolation::ConfigurationName::new("Debug").unwrap(),
            aa_isolation::Destination::SimulatorById(
                aa_isolation::SimulatorUdid::new("22222222-2222-2222-2222-222222222222").unwrap(),
            ),
            PathBuf::from("/tmp/dd"),
            aa_isolation::BuildAction::Build,
        ));
        assert!(matches!(
            aa_isolation::check_host_capability_arguments(&op, &[], &known_devices),
            Err(HostCapabilityRefusal::UnknownDevice { .. })
        ));
    }

    #[test]
    fn positive_control_raw_key_value_argument_would_take_effect_if_not_blocked() {
        let Some(_report) = xcode_available() else {
            eprintln!("SKIP: no real Xcode toolchain is available on this host");
            return;
        };
        let dd = developer_dir().unwrap();
        let env = broker_environment(&dd);
        let resolved = resolve_program(OperationKind::XcodeBuild, &env["PATH"]).unwrap();

        let fixture_dir = std::env::temp_dir().join(format!("aa-hc-injectfixture-{}", std::process::id()));
        let src_dir = fixture_dir.join("Sources").join("InjFixture");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(
            fixture_dir.join("Package.swift"),
            "// swift-tools-version:5.9\nimport PackageDescription\n\nlet package = Package(\n    name: \"InjFixture\",\n    targets: [\n        .executableTarget(name: \"InjFixture\")\n    ]\n)\n",
        )
        .unwrap();
        std::fs::write(src_dir.join("main.swift"), "print(\"inj ok\")\n").unwrap();
        let derived_data = fixture_dir.join("dd");

        // Bypass the newtypes deliberately: a raw positional `KEY=value`
        // element, proving the injection vector this module's `=`-rejection
        // exists to close is real.
        let mut command = Command::new(&resolved);
        command
            .args([
                "-scheme",
                "InjFixture",
                "-destination",
                "generic/platform=macOS",
                "-derivedDataPath",
                &derived_data.display().to_string(),
                "-configuration",
                "Debug",
                "SWIFT_ACTIVE_COMPILATION_CONDITIONS=INJECTED_MARKER",
                "-showBuildSettings",
            ])
            .env_clear();
        for (k, v) in &env {
            command.env(k, v);
        }
        command.current_dir(&fixture_dir);
        command.stdin(Stdio::null());
        let output = command.output().unwrap();
        std::fs::remove_dir_all(&fixture_dir).ok();

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("INJECTED_MARKER"),
            "the injected build setting override did not take effect — positive control failed: {stdout}"
        );
    }
}
