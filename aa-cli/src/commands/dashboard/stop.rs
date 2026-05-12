//! `aasm dashboard stop` — terminate a running dashboard server via PID file.

use std::process::ExitCode;

use super::pid;

pub fn dispatch() -> ExitCode {
    let Some((server_pid, _port)) = pid::read_pid() else {
        println!("No running dashboard found.");
        return ExitCode::SUCCESS;
    };

    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(server_pid as libc::pid_t, libc::SIGTERM) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("error: could not send SIGTERM to PID {server_pid}: {err}");
            return ExitCode::FAILURE;
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::FromRawHandle;
        let handle = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_TERMINATE,
                0,
                server_pid,
            )
        };
        if handle.is_null() {
            eprintln!("error: could not open process {server_pid}");
            return ExitCode::FAILURE;
        }
        let ok = unsafe { windows_sys::Win32::System::Threading::TerminateProcess(handle, 1) };
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        if ok == 0 {
            eprintln!("error: TerminateProcess failed for PID {server_pid}");
            return ExitCode::FAILURE;
        }
    }

    if let Err(e) = pid::remove_pid() {
        eprintln!("warning: could not remove PID file: {e}");
    }

    println!("Dashboard stopped.");
    ExitCode::SUCCESS
}
