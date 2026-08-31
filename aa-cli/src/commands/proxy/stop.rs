//! `aasm proxy stop` — terminate a running aa-proxy sidecar via PID file.

use std::process::ExitCode;

use super::pid;

pub fn dispatch() -> ExitCode {
    let Some((proxy_pid, addr)) = pid::read_pid() else {
        println!("No running proxy found.");
        return ExitCode::SUCCESS;
    };

    #[cfg(unix)]
    {
        let killed = pid::kill_process(proxy_pid);
        let _ = pid::remove_pid();
        if killed {
            println!("Proxy stopped (was listening on {addr}).");
            ExitCode::SUCCESS
        } else {
            eprintln!("error: could not stop proxy (PID {proxy_pid})");
            ExitCode::FAILURE
        }
    }

    #[cfg(not(unix))]
    {
        let _ = addr;
        eprintln!("error: `aasm proxy stop` is only supported on Unix");
        ExitCode::FAILURE
    }
}
