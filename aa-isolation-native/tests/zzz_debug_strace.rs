//! TEMPORARY diagnostic — not for merge. Prints the real `probe::measure`
//! syscall Observation's diagnostic detail (which embeds the launcher's own
//! stderr/diagnostic output) so we can see exactly which syscall the real
//! control run (via `NativeBackend::discover_with_launcher`) still dies on,
//! now that STARTUP_BASELINE includes vfork. AAASM-5803.

use aa_isolation_native::{NativeBackend, Observation};

#[test]
fn zzz_print_syscall_observation() {
    let launcher = std::path::PathBuf::from(env!("CARGO_BIN_EXE_aa-isolation-launch"));
    let backend = NativeBackend::discover_with_launcher(launcher).with_captured_output(true);
    let probe = backend.probe_result();
    eprintln!("=== SYSCALL OBSERVATION ===");
    match &probe.syscall {
        Observation::Denied => eprintln!("Denied (expected — this should already pass)"),
        Observation::Permitted => eprintln!("Permitted (control+test both succeeded — no denial observed)"),
        Observation::Inconclusive { detail } => eprintln!("Inconclusive: {detail}"),
    }
    eprintln!("=== HOST ===");
    if let Some(host) = backend.host() {
        eprintln!("{}", host.describe());
    }
    panic!("diagnostic dump above");
}
