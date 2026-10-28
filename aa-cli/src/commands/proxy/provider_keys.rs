//! How `aasm` handles the operator's brokered provider credentials
//! (`AA_PROXY_PROVIDER_KEYS`, AAASM-6395).
//!
//! An environment variable is readable by every process of the same user:
//! `ps -Eww` on macOS and `/proc/<pid>/environ` on Linux both return the bytes
//! the process was exec'd with, and a governed agent is such a process. Left
//! alone, the variable reached the proxy's environment, the supervisor's, and
//! the governed tool's own environment. This module closes that passive
//! disclosure in three steps:
//!
//! 1. [`capture_and_scrub`] copies the value into process memory and overwrites
//!    the exec-time bytes in place. `remove_var` alone is not enough: it only
//!    edits the `environ` pointer table, while `ps` and `/proc` read the
//!    original bytes.
//! 2. The proxy command is built without the variable ([`configure`]).
//! 3. The value reaches `aa-proxy` over its stdin, written once and closed
//!    ([`deliver`]), which is not visible to other processes.
//!
//! What this does **not** do, and must not be described as doing: it does not
//! stop an active attacker of the same user. `aasm` still holds the value in
//! memory and stays debuggable, the proxy can be killed or replaced, and the
//! operator's own shell still exports the variable. The boundary against that is
//! a separate UID or a sandbox backend (ADR 0038), not a file or a pipe.

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

use aa_proxy::credentials::{parse_provider_keys, MAX_PROVIDER_KEYS_BYTES, PROVIDER_KEYS_STDIN_FLAG};

const VAR: &str = "AA_PROXY_PROVIDER_KEYS";

/// The value captured by [`capture_and_scrub`]. `None` inside means "was unset".
static CAPTURED: OnceLock<Option<String>> = OnceLock::new();

/// Capture the provider keys from the process environment and destroy the
/// exec-time copy.
///
/// Must run before any thread exists and before anything calls `set_var`:
/// the overwrite relies on `environ` still pointing at the strings the kernel
/// handed to this process. Idempotent; later calls change nothing.
pub fn capture_and_scrub() {
    CAPTURED.get_or_init(take_from_process_env);
}

/// The provider keys for this launch, or `None` when none are configured.
///
/// After [`capture_and_scrub`] this is the captured value; otherwise (library
/// callers, tests) it falls back to the environment variable.
pub fn provider_keys() -> Option<String> {
    match CAPTURED.get() {
        Some(value) => value.clone(),
        None => std::env::var(VAR).ok().filter(|v| !v.is_empty()),
    }
}

#[cfg(unix)]
fn take_from_process_env() -> Option<String> {
    use std::ffi::CStr;

    let value = std::env::var(VAR).ok().filter(|v| !v.is_empty());
    let prefix = format!("{VAR}=");
    // SAFETY: called from `main` before any other thread starts and before any
    // `setenv`, so `environ` is the kernel-provided array of NUL-terminated
    // strings, each writable stack memory owned by this process. Only the bytes
    // after `NAME=` of a matching entry are overwritten, with zeros, within the
    // entry's own length.
    unsafe {
        let mut cursor = environ_array();
        while !cursor.is_null() && !(*cursor).is_null() {
            let entry = *cursor;
            let bytes = CStr::from_ptr(entry).to_bytes();
            if bytes.starts_with(prefix.as_bytes()) {
                for offset in prefix.len()..bytes.len() {
                    std::ptr::write_volatile(entry.cast::<u8>().add(offset), 0);
                }
            }
            cursor = cursor.add(1);
        }
    }
    std::env::remove_var(VAR);
    value
}

#[cfg(target_os = "macos")]
unsafe fn environ_array() -> *mut *mut libc::c_char {
    *libc::_NSGetEnviron()
}

#[cfg(all(unix, not(target_os = "macos")))]
unsafe fn environ_array() -> *mut *mut libc::c_char {
    extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }
    environ
}

#[cfg(not(unix))]
fn take_from_process_env() -> Option<String> {
    let value = std::env::var(VAR).ok().filter(|v| !v.is_empty());
    std::env::remove_var(VAR);
    value
}

/// Refuse a launch whose provider keys the proxy would refuse, before anything
/// is spawned.
///
/// # Errors
///
/// A sentence naming the problem (never any part of the value).
pub fn preflight() -> Result<(), String> {
    let Some(raw) = provider_keys() else {
        return Ok(());
    };
    if raw.len() > MAX_PROVIDER_KEYS_BYTES {
        return Err(format!(
            "AA_PROXY_PROVIDER_KEYS is longer than the {MAX_PROVIDER_KEYS_BYTES}-byte limit the proxy accepts"
        ));
    }
    parse_provider_keys(&raw)
        .map(|_| ())
        .map_err(|e| format!("AA_PROXY_PROVIDER_KEYS is not usable: {e}"))
}

/// Whether the proxy about to be spawned will be given keys on stdin.
pub fn delivering() -> bool {
    provider_keys().is_some()
}

/// Set the provider-key wiring on a proxy `Command`.
///
/// The variable is always removed from the child's environment, and the stdin
/// flag is set or removed explicitly rather than inherited, so an ambient value
/// can never choose how the proxy loads its credentials. Call after any other
/// `stdin(...)` setting: a launch that delivers keys needs the pipe.
pub fn configure(cmd: &mut Command) {
    cmd.env_remove(VAR);
    if delivering() {
        cmd.env(PROVIDER_KEYS_STDIN_FLAG, "1");
        cmd.stdin(Stdio::piped());
    } else {
        cmd.env_remove(PROVIDER_KEYS_STDIN_FLAG);
    }
}

/// Write the provider keys to the spawned proxy's stdin and close it.
///
/// A no-op when no keys are configured. The payload is bounded by
/// [`preflight`] below the pipe buffer, so this write cannot block on a reader
/// that has not started.
///
/// # Errors
///
/// The write failed (for example the proxy already exited); the caller must
/// terminate the child and refuse the launch, because a proxy without its keys
/// would forward the agent's own credential header unchanged.
pub fn deliver(child: &mut Child) -> std::io::Result<()> {
    let Some(raw) = provider_keys() else {
        return Ok(());
    };
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("proxy stdin was not piped"))?;
    stdin.write_all(raw.as_bytes())?;
    stdin.flush()
    // `stdin` drops here, which closes the pipe and delivers EOF.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that mutate the process environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn envs(cmd: &Command) -> Vec<(String, Option<String>)> {
        cmd.get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    #[test]
    fn with_keys_the_variable_is_removed_the_flag_set_and_no_value_is_in_the_command() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(VAR, "api.anthropic.com=sk-ant-QA6395-synth");
        let mut cmd = Command::new("true");
        configure(&mut cmd);
        std::env::remove_var(VAR);
        let envs = envs(&cmd);
        assert!(envs.contains(&(VAR.to_string(), None)), "{envs:?}");
        assert!(
            envs.contains(&(PROVIDER_KEYS_STDIN_FLAG.to_string(), Some("1".into()))),
            "{envs:?}"
        );
        assert!(
            !format!("{envs:?}{cmd:?}").contains("QA6395"),
            "the command carries the value"
        );
    }

    #[test]
    fn without_keys_the_flag_is_removed_even_when_set_ambiently() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var(VAR);
        std::env::set_var(PROVIDER_KEYS_STDIN_FLAG, "1");
        let mut cmd = Command::new("true");
        configure(&mut cmd);
        std::env::remove_var(PROVIDER_KEYS_STDIN_FLAG);
        let envs = envs(&cmd);
        assert!(envs.contains(&(PROVIDER_KEYS_STDIN_FLAG.to_string(), None)), "{envs:?}");
        assert!(envs.contains(&(VAR.to_string(), None)), "{envs:?}");
    }

    #[test]
    fn a_real_child_receives_the_payload_on_stdin_and_not_in_its_environment() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(VAR, "api.anthropic.com=sk-ant-QA6395-synth");
        // The stub prints whether its own environment holds the value, then echoes stdin.
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "env | grep -c QA6395; cat"]).stdout(Stdio::piped());
        configure(&mut cmd);
        let mut child = cmd.spawn().expect("sh must spawn");
        deliver(&mut child).expect("write to a live child");
        std::env::remove_var(VAR);
        let out = child.wait_with_output().expect("wait");
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some("0"),
            "the child's environment held the value: {text}"
        );
        assert_eq!(lines.next(), Some("api.anthropic.com=sk-ant-QA6395-synth"), "{text}");
    }

    #[test]
    fn preflight_refuses_what_the_proxy_would_refuse_without_quoting_it() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(VAR, "api.x.com=ok,SECRETMARK6395");
        let malformed = preflight();
        std::env::set_var(VAR, format!("h={}", "a".repeat(MAX_PROVIDER_KEYS_BYTES)));
        let oversize = preflight();
        std::env::set_var(VAR, "api.x.com=fine");
        let good = preflight();
        std::env::remove_var(VAR);
        let malformed = malformed.unwrap_err();
        assert!(!malformed.contains("SECRETMARK6395"), "{malformed}");
        assert!(oversize.is_err());
        assert!(good.is_ok(), "positive control");
        assert!(preflight().is_ok(), "unset is fine");
    }
}
