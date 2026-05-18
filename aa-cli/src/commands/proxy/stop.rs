//! `aasm proxy stop` — terminate a running aa-proxy sidecar via PID file.

use std::process::ExitCode;
use std::time::Duration;

use super::pid;

pub fn dispatch() -> ExitCode {
    let Some((proxy_pid, addr)) = pid::read_pid() else {
        println!("No running proxy found.");
        return ExitCode::SUCCESS;
    };

    #[cfg(unix)]
    {
        // Send SIGTERM.
        let ret = unsafe { libc::kill(proxy_pid as libc::pid_t, libc::SIGTERM) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // ESRCH means the process no longer exists — treat as already stopped.
            if err.kind() == std::io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH) {
                let _ = pid::remove_pid();
                println!("Proxy (PID {proxy_pid}) was already not running.");
                return ExitCode::SUCCESS;
            }
            eprintln!("error: could not send SIGTERM to PID {proxy_pid}: {err}");
            return ExitCode::FAILURE;
        }

        // Poll for up to 5s for a clean exit.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            let still_alive = unsafe { libc::kill(proxy_pid as libc::pid_t, 0) } == 0;
            if !still_alive {
                let _ = pid::remove_pid();
                println!("Proxy stopped (was listening on {addr}).");
                return ExitCode::SUCCESS;
            }
        }

        // Still alive after 5s — escalate to SIGKILL.
        eprintln!("warning: proxy did not exit cleanly within 5s; sending SIGKILL");
        unsafe { libc::kill(proxy_pid as libc::pid_t, libc::SIGKILL) };
        let _ = pid::remove_pid();
        println!("Proxy killed.");
        ExitCode::SUCCESS
    }

    #[cfg(not(unix))]
    {
        let _ = addr;
        eprintln!("error: `aasm proxy stop` is only supported on Unix");
        ExitCode::FAILURE
    }
}
