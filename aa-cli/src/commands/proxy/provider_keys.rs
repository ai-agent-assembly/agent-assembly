//! How `aasm` handles the operator's brokered provider credentials
//! (`AA_PROXY_PROVIDER_KEYS`, AAASM-6395).
//!
//! An environment variable is readable by every process of the same user:
//! `ps -Eww` on macOS and `/proc/<pid>/environ` on Linux both return the bytes
//! the process was exec'd with, and a governed agent is such a process. Left
//! alone, the variable reached the proxy's environment, the supervisor's, and
//! the governed tool's own environment. For `aasm run` and `aasm proxy ...` this
//! module closes that passive disclosure in three steps:
//!
//! 1. [`capture_and_scrub`] copies the value into process memory and overwrites
//!    the exec-time bytes in place. `remove_var` alone is not enough: it only
//!    edits the `environ` pointer table, while `ps` and `/proc` read the
//!    original bytes.
//! 2. The proxy command is built without the variable ([`configure`]).
//! 3. The value reaches `aa-proxy` over its stdin, written once and closed
//!    ([`deliver`]), which other processes cannot passively read.
//!
//! What this does **not** do, and must not be described as doing: it does not
//! stop an active attacker of the same user. `aasm` still holds the value in
//! memory and stays debuggable, the proxy can be killed or replaced, and the
//! operator's own shell still exports the variable. Other `aasm` commands do not
//! scrub, so an exported variable stays visible to them and their children. The
//! boundary against all of that is a separate UID or a sandbox backend
//! (ADR 0038), not a file or a pipe.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use aa_proxy::credentials::{
    parse_provider_keys, MAX_PROVIDER_KEYS_BYTES, PROVIDER_KEYS_STDIN_CAPABILITY, PROVIDER_KEYS_STDIN_FLAG,
};

const VAR: &str = "AA_PROXY_PROVIDER_KEYS";

/// How long to wait for `aa-proxy --capabilities`. It only prints a line.
const CAPABILITY_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// What the environment held for [`VAR`] when it was captured.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Captured {
    /// Unset, or blank (nothing but whitespace): no keys are configured.
    Unset,
    Keys(String),
    /// Set but not valid UTF-8. Treating this as unset would start a proxy with no
    /// credentials, so it is carried as a refusal instead.
    NotUtf8,
}

impl Captured {
    fn from_os(value: Option<std::ffi::OsString>) -> Self {
        match value {
            None => Self::Unset,
            Some(v) => match v.into_string() {
                Ok(s) if s.trim().is_empty() => Self::Unset,
                Ok(s) => Self::Keys(s),
                Err(_) => Self::NotUtf8,
            },
        }
    }
}

/// The value captured by [`capture_and_scrub`].
static CAPTURED: OnceLock<Captured> = OnceLock::new();

fn current() -> Captured {
    match CAPTURED.get() {
        Some(captured) => captured.clone(),
        None => Captured::from_os(std::env::var_os(VAR)),
    }
}

/// Capture the provider keys from the process environment and destroy the
/// exec-time copy.
///
/// Must run before anything mutates the environment (`set_var`): the overwrite
/// relies on `environ` still pointing at the strings the kernel handed to this
/// process. Idempotent; later calls change nothing.
pub fn capture_and_scrub() {
    CAPTURED.get_or_init(|| Captured::from_os(take_from_process_env()));
}

/// The provider keys for this launch, or `None` when none are configured.
///
/// After [`capture_and_scrub`] this is the captured value; otherwise (library
/// callers, tests) it reads the environment variable.
pub fn provider_keys() -> Option<String> {
    match current() {
        Captured::Keys(keys) => Some(keys),
        Captured::Unset | Captured::NotUtf8 => None,
    }
}

#[cfg(unix)]
fn take_from_process_env() -> Option<std::ffi::OsString> {
    use std::ffi::CStr;

    let value = std::env::var_os(VAR);
    let prefix = format!("{VAR}=");
    // SAFETY: called from `main` before anything mutates the environment, so
    // `environ` is still the kernel-provided array of NUL-terminated strings, each
    // writable memory owned by this process. Only the bytes after `NAME=` of a
    // matching entry are overwritten with zeros, within the entry's own length,
    // and the borrowed slice is dropped before any write.
    unsafe {
        let mut cursor = environ_array();
        while !cursor.is_null() && !(*cursor).is_null() {
            let entry = *cursor;
            let len = {
                let bytes = CStr::from_ptr(entry).to_bytes();
                bytes.starts_with(prefix.as_bytes()).then_some(bytes.len())
            };
            if let Some(len) = len {
                for offset in prefix.len()..len {
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
fn take_from_process_env() -> Option<std::ffi::OsString> {
    let value = std::env::var_os(VAR);
    std::env::remove_var(VAR);
    value
}

/// Refuse a launch whose provider keys cannot be delivered, before anything is
/// spawned.
///
/// Refuses a value the proxy would refuse, a value that is not UTF-8, and a
/// proxy binary that cannot consume stdin delivery: such a binary would ignore
/// the payload and start with no credentials, forwarding the agent's own header.
///
/// # Errors
///
/// A sentence naming the problem (never any part of the value).
pub fn preflight(proxy_binary: &Path) -> Result<(), String> {
    match current() {
        Captured::Unset => Ok(()),
        Captured::NotUtf8 => Err(format!("{VAR} is not valid UTF-8, so it cannot be delivered")),
        Captured::Keys(raw) => {
            if raw.len() > MAX_PROVIDER_KEYS_BYTES {
                return Err(format!(
                    "{VAR} is longer than the {MAX_PROVIDER_KEYS_BYTES}-byte limit the proxy accepts"
                ));
            }
            parse_provider_keys(&raw).map_err(|e| format!("{VAR} is not usable: {e}"))?;
            if probe_stdin_delivery(proxy_binary, CAPABILITY_PROBE_TIMEOUT) {
                Ok(())
            } else {
                Err(format!(
                    "{} cannot receive provider keys on stdin (it predates that delivery); \
                     install the aa-proxy that matches this aasm",
                    proxy_binary.display()
                ))
            }
        }
    }
}

/// Whether `binary --capabilities` reports stdin delivery, within `timeout`.
fn probe_stdin_delivery(binary: &Path, timeout: Duration) -> bool {
    let Ok(mut child) = Command::new(binary)
        .arg("--capabilities")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return false,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut out = String::new();
    child
        .stdout
        .take()
        .is_some_and(|s| s.take(4096).read_to_string(&mut out).is_ok())
        && out.lines().any(|l| l.trim() == PROVIDER_KEYS_STDIN_CAPABILITY)
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
/// The proxy has no stdin pipe or the write failed (for example the proxy
/// already exited); the caller must terminate the child and refuse the launch,
/// because a proxy without its keys would forward the agent's own credential
/// header unchanged.
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
    use std::os::unix::fs::PermissionsExt;

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

    /// A stub `aa-proxy` shell script that answers `--capabilities` with `body`.
    fn stub_proxy(dir: &Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("aa-proxy-stub");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn with_keys_the_variable_is_removed_the_flag_set_and_no_value_is_in_the_command() {
        let _lock = crate::test_support::env_guard();
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
        let _lock = crate::test_support::env_guard();
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
        let _lock = crate::test_support::env_guard();
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
    fn keys_with_no_stdin_pipe_are_a_delivery_error_not_a_silent_no_op() {
        let _lock = crate::test_support::env_guard();
        std::env::set_var(VAR, "api.x.com=sk-QA6395");
        let mut child = Command::new("true")
            .stdin(Stdio::null())
            .spawn()
            .expect("true must spawn");
        let outcome = deliver(&mut child);
        std::env::remove_var(VAR);
        child.wait().expect("exit");
        assert!(
            outcome.is_err(),
            "a proxy spawned without the pipe must not be treated as delivered"
        );
    }

    #[test]
    fn preflight_refuses_what_cannot_be_delivered_without_quoting_it() {
        let _lock = crate::test_support::env_guard();
        let dir = tempfile::tempdir().unwrap();
        let capable = stub_proxy(dir.path(), "echo provider-keys-stdin");

        std::env::set_var(VAR, "api.x.com=ok,SECRETMARK6395");
        let malformed = preflight(&capable);
        std::env::set_var(VAR, format!("h={}", "a".repeat(MAX_PROVIDER_KEYS_BYTES)));
        let oversize = preflight(&capable);
        std::env::set_var(VAR, "api.x.com=fine");
        let good = preflight(&capable);
        std::env::remove_var(VAR);

        let malformed = malformed.unwrap_err();
        assert!(!malformed.contains("SECRETMARK6395"), "{malformed}");
        assert!(oversize.is_err());
        assert!(good.is_ok(), "positive control: a capable proxy and a good payload");
        assert!(preflight(&capable).is_ok(), "unset is fine");
        std::env::set_var(VAR, "  ");
        assert!(
            preflight(&capable).is_ok(),
            "a blank value means no keys, as it always did"
        );
        std::env::remove_var(VAR);
    }

    #[cfg(unix)]
    #[test]
    fn a_value_that_is_not_utf8_refuses_the_launch_instead_of_vanishing() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(
            Captured::from_os(Some(std::ffi::OsString::from_vec(b"h=\xff\xfe".to_vec()))),
            Captured::NotUtf8
        );
        let _lock = crate::test_support::env_guard();
        std::env::set_var(VAR, std::ffi::OsString::from_vec(b"h=\xff\xfe".to_vec()));
        let dir = tempfile::tempdir().unwrap();
        let outcome = preflight(&stub_proxy(dir.path(), "echo provider-keys-stdin"));
        let delivering_now = delivering();
        std::env::remove_var(VAR);
        assert!(
            outcome.is_err(),
            "fail-open: a non-UTF-8 value was treated as 'no keys'"
        );
        assert!(!delivering_now);
    }

    #[test]
    fn a_proxy_that_predates_stdin_delivery_is_refused_and_a_capable_one_is_not() {
        let _lock = crate::test_support::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(VAR, "api.x.com=sk-QA6395");
        // An old aa-proxy rejects the unknown flag; one that is silent or wrong is also not capable.
        let old = preflight(&stub_proxy(dir.path(), "echo 'error: unexpected argument' >&2; exit 2"));
        let silent = preflight(&stub_proxy(dir.path(), "exit 0"));
        let missing = preflight(&dir.path().join("no-such-binary"));
        let capable = preflight(&stub_proxy(dir.path(), "echo provider-keys-stdin"));
        std::env::remove_var(VAR);
        assert!(old.is_err() && silent.is_err() && missing.is_err());
        assert!(capable.is_ok(), "positive control");
    }

    #[test]
    fn a_hung_capability_probe_is_bounded_and_not_capable() {
        let dir = tempfile::tempdir().unwrap();
        let hung = stub_proxy(dir.path(), "sleep 30");
        let started = Instant::now();
        assert!(!probe_stdin_delivery(&hung, Duration::from_millis(300)));
        assert!(started.elapsed() < Duration::from_secs(10), "the probe must give up");
    }

    /// Child half of [`the_exec_time_environment_is_overwritten_not_just_unset`]: run
    /// only when re-invoked by it, never as part of a normal run.
    #[test]
    #[ignore = "re-executed by the_exec_time_environment_is_overwritten_not_just_unset"]
    fn scrub_probe_child() {
        let mode = std::env::var("AASM_SCRUB_PROBE_MODE").unwrap_or_default();
        match mode.as_str() {
            "none" => {}
            "remove" => std::env::remove_var(VAR),
            "scrub" => capture_and_scrub(),
            other => panic!("unknown mode {other}"),
        }
        let pid = std::process::id().to_string();
        let seen = if cfg!(target_os = "macos") {
            let out = Command::new("ps").args(["-Eww", "-p", &pid]).output().unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
        } else {
            String::from_utf8_lossy(&std::fs::read("/proc/self/environ").unwrap()).into_owned()
        };
        println!(
            "PROBE visible={} captured={}",
            seen.contains("QA6395SCRUB"),
            provider_keys().is_some()
        );
    }

    /// The claim that matters: what `ps -Eww` / `/proc/<pid>/environ` returns.
    /// Three arms so a pass cannot be an artifact of the probe: with nothing done
    /// the value is visible (the control), `remove_var` alone leaves it visible,
    /// and only the in-place overwrite hides it while the value is still held.
    #[test]
    fn the_exec_time_environment_is_overwritten_not_just_unset() {
        let run = |mode: &str| -> String {
            let out = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "commands::proxy::provider_keys::tests::scrub_probe_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(VAR, "api.anthropic.com=sk-ant-QA6395SCRUB")
                .env("AASM_SCRUB_PROBE_MODE", mode)
                .output()
                .expect("re-exec the test binary");
            // libtest prints `test <name> ... ` before the probe's own output, on one line.
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            stdout
                .lines()
                .find_map(|l| l.find("PROBE ").map(|at| l[at..].to_string()))
                .unwrap_or_else(|| panic!("{mode}: no probe line in: {stdout}"))
        };
        assert_eq!(
            run("none"),
            "PROBE visible=true captured=true",
            "control: the probe sees the value"
        );
        assert_eq!(
            run("remove"),
            "PROBE visible=true captured=false",
            "remove_var alone must not be mistaken for a scrub"
        );
        assert_eq!(
            run("scrub"),
            "PROBE visible=false captured=true",
            "capture_and_scrub must hide the value from ps/proc and still hold it"
        );
    }
}
