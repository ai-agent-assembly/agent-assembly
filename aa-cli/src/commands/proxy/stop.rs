//! `aasm proxy stop` — terminate a running aa-proxy sidecar via PID file.

use std::process::ExitCode;

use super::pid::{self, KillOutcome};

pub fn dispatch() -> ExitCode {
    let Some((proxy_pid, addr)) = pid::read_pid() else {
        println!("No running proxy found.");
        return ExitCode::SUCCESS;
    };

    #[cfg(unix)]
    {
        match pid::kill_process(proxy_pid) {
            KillOutcome::AlreadyGone => {
                let _ = pid::remove_pid();
                println!("Proxy (PID {proxy_pid}) was already not running.");
                ExitCode::SUCCESS
            }
            KillOutcome::Terminated => {
                let _ = pid::remove_pid();
                println!("Proxy stopped (was listening on {addr}).");
                ExitCode::SUCCESS
            }
            KillOutcome::Killed => {
                eprintln!("warning: proxy did not exit cleanly within 5s; sending SIGKILL");
                let _ = pid::remove_pid();
                println!("Proxy killed.");
                ExitCode::SUCCESS
            }
            KillOutcome::Failed(err) => {
                eprintln!("error: could not stop PID {proxy_pid}: {err}");
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = addr;
        eprintln!("error: `aasm proxy stop` is only supported on Unix");
        ExitCode::FAILURE
    }
}
