//! TEMPORARY diagnostic — not part of AAASM-5803's real test suite. Traces the
//! exact syscall that kills the confined shell under the probe's control
//! allowlist, so the real STARTUP_BASELINE/probe-baseline gap can be fixed with
//! data instead of guesses. Delete before merge.

use std::path::PathBuf;
use std::process::Command;

use aa_isolation_native::{Grants, SyscallFilter};

fn launcher() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aa-isolation-launch"))
}

#[test]
fn zzz_trace_the_control_invocation() {
    let syscalls: std::collections::BTreeSet<aa_security::policy::syscall::Syscall> = [
        aa_security::policy::syscall::Syscall::Read,
        aa_security::policy::syscall::Syscall::Openat,
        aa_security::policy::syscall::Syscall::Close,
        aa_security::policy::syscall::Syscall::Fstat,
        aa_security::policy::syscall::Syscall::Lseek,
        aa_security::policy::syscall::Syscall::Mmap,
        aa_security::policy::syscall::Syscall::Munmap,
        aa_security::policy::syscall::Syscall::Brk,
        aa_security::policy::syscall::Syscall::Getrandom,
        aa_security::policy::syscall::Syscall::ExitGroup,
        aa_security::policy::syscall::Syscall::RtSigaction,
        aa_security::policy::syscall::Syscall::RtSigprocmask,
        aa_security::policy::syscall::Syscall::ClockGettime,
        aa_security::policy::syscall::Syscall::Write,
    ]
    .into_iter()
    .collect();

    let grants = Grants {
        read: ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev"]
            .iter()
            .filter(|p| std::path::Path::new(p).exists())
            .map(|p| (*p).to_string())
            .collect(),
        write: Default::default(),
    };

    let target = std::env::temp_dir().join("zzz-debug-target");
    let script = format!("exec /bin/sh -c \"printf x > {}\"", target.to_string_lossy());

    let argv = aa_isolation_native::launch::build(
        &grants,
        &SyscallFilter::Allow(syscalls),
        "/bin/sh",
        &["-c".to_string(), script],
    );

    let trace_out = std::env::temp_dir().join("zzz-strace-out.log");
    let mut cmd = Command::new("strace");
    cmd.arg("-f").arg("-o").arg(&trace_out).arg(launcher());
    for a in &argv {
        cmd.arg(a);
    }
    let output = cmd.output().expect("strace must be runnable on this CI image");

    eprintln!("=== exit status: {:?} ===", output.status);
    eprintln!("=== stdout ===\n{}", String::from_utf8_lossy(&output.stdout));
    eprintln!("=== stderr ===\n{}", String::from_utf8_lossy(&output.stderr));
    eprintln!("=== target exists: {} ===", target.exists());
    if let Ok(trace) = std::fs::read_to_string(&trace_out) {
        eprintln!("=== strace (last 200 lines) ===");
        for line in trace.lines().rev().take(200).collect::<Vec<_>>().into_iter().rev() {
            eprintln!("{line}");
        }
    } else {
        eprintln!("=== no strace output file ===");
    }

    panic!("diagnostic only — see stderr above");
}
