//! `aasm proxy install-ca` / `uninstall-ca` — manage the proxy CA in the OS trust store.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

/// Arguments shared by `install-ca` and `uninstall-ca`.
#[derive(Debug, Args)]
pub struct CaArgs {
    /// Directory where the CA certificate and key are stored.
    #[arg(long, env = "AA_CA_DIR")]
    pub ca_dir: Option<PathBuf>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

fn default_ca_dir() -> PathBuf {
    dirs::home_dir()
        .expect("cannot determine home directory")
        .join(".aa")
        .join("ca")
}

fn confirm(prompt: &str) -> bool {
    use std::io::{self, BufRead, Write};
    print!("{prompt} [y/N] ");
    io::stdout().flush().ok();
    let stdin = io::stdin();
    let line = stdin.lock().lines().next().and_then(|l| l.ok()).unwrap_or_default();
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

pub fn install(args: CaArgs) -> ExitCode {
    let ca_dir = args.ca_dir.unwrap_or_else(default_ca_dir);

    if !args.yes && !confirm("This will modify the system trust store. Continue?") {
        println!("Aborted.");
        return ExitCode::SUCCESS;
    }

    #[cfg(target_os = "macos")]
    {
        use aa_proxy::tls::CaStore;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");

        match rt.block_on(CaStore::load_or_create(&ca_dir)) {
            Err(e) => {
                eprintln!("error: failed to load/create CA: {e}");
                ExitCode::FAILURE
            }
            Ok(ca) => match ca.is_installed() {
                Ok(true) => {
                    println!("CA is already installed and trusted.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: could not check keychain: {e}");
                    ExitCode::FAILURE
                }
                Ok(false) => match ca.install() {
                    Ok(()) => {
                        println!("CA installed successfully into the macOS System Keychain.");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("error: CA installation failed: {e}");
                        ExitCode::FAILURE
                    }
                },
            },
        }
    }

    #[cfg(target_os = "linux")]
    {
        install_linux(&ca_dir)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = ca_dir;
        eprintln!("error: `aasm proxy install-ca` is not supported on this platform");
        ExitCode::FAILURE
    }
}

pub fn uninstall(args: CaArgs) -> ExitCode {
    let ca_dir = args.ca_dir.unwrap_or_else(default_ca_dir);

    if !args.yes && !confirm("This will remove the proxy CA from the system trust store. Continue?") {
        println!("Aborted.");
        return ExitCode::SUCCESS;
    }

    #[cfg(target_os = "macos")]
    {
        use aa_proxy::tls::CaStore;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");

        match rt.block_on(CaStore::load_or_create(&ca_dir)) {
            Err(e) => {
                eprintln!("error: failed to load CA: {e}");
                ExitCode::FAILURE
            }
            Ok(ca) => match ca.is_installed() {
                Ok(false) => {
                    println!("CA is not currently installed — nothing to remove.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: could not check keychain: {e}");
                    ExitCode::FAILURE
                }
                Ok(true) => match ca.uninstall() {
                    Ok(()) => {
                        println!("CA removed from the macOS System Keychain.");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("error: CA removal failed: {e}");
                        ExitCode::FAILURE
                    }
                },
            },
        }
    }

    #[cfg(target_os = "linux")]
    {
        uninstall_linux(&ca_dir)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = ca_dir;
        eprintln!("error: `aasm proxy uninstall-ca` is not supported on this platform");
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "linux")]
fn install_linux(ca_dir: &PathBuf) -> ExitCode {
    // Require root.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("error: `aasm proxy install-ca` requires root on Linux.\nRe-run with sudo.");
        return ExitCode::FAILURE;
    }

    let cert_path = ca_dir.join("ca-cert.pem");
    if !cert_path.exists() {
        eprintln!(
            "error: CA certificate not found at {}.\n\
             Run `aasm proxy start` first to generate the CA.",
            cert_path.display()
        );
        return ExitCode::FAILURE;
    }

    let dest = std::path::Path::new("/usr/local/share/ca-certificates/aa-proxy.crt");
    if let Err(e) = std::fs::copy(&cert_path, dest) {
        eprintln!("error: could not copy CA cert to {}: {e}", dest.display());
        return ExitCode::FAILURE;
    }

    let status = std::process::Command::new("update-ca-certificates").status();
    match status {
        Ok(s) if s.success() => {
            println!("CA installed successfully (update-ca-certificates ran).");
            ExitCode::SUCCESS
        }
        Ok(_) => {
            eprintln!("error: update-ca-certificates failed");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: could not run update-ca-certificates: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn uninstall_linux(_ca_dir: &PathBuf) -> ExitCode {
    if unsafe { libc::getuid() } != 0 {
        eprintln!("error: `aasm proxy uninstall-ca` requires root on Linux.\nRe-run with sudo.");
        return ExitCode::FAILURE;
    }

    let dest = std::path::Path::new("/usr/local/share/ca-certificates/aa-proxy.crt");
    if !dest.exists() {
        println!("CA certificate not present — nothing to remove.");
        return ExitCode::SUCCESS;
    }

    if let Err(e) = std::fs::remove_file(dest) {
        eprintln!("error: could not remove {}: {e}", dest.display());
        return ExitCode::FAILURE;
    }

    let status = std::process::Command::new("update-ca-certificates").status();
    match status {
        Ok(s) if s.success() => {
            println!("CA removed (update-ca-certificates ran).");
            ExitCode::SUCCESS
        }
        Ok(_) => {
            eprintln!("error: update-ca-certificates failed");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: could not run update-ca-certificates: {e}");
            ExitCode::FAILURE
        }
    }
}
