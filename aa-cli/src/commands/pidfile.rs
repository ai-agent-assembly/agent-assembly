//! PID-file management for the locally-managed `aasm` gateway process.
//!
//! Shared infrastructure for `aasm start` (Impl-3, AAASM-1717) and
//! `aasm stop` (Impl-4, AAASM-1722). Default on-disk location is
//! `~/.aasm/gateway.pid`; tests inject a temp path via the explicit
//! `&Path` arguments on each operation.

use std::path::{Path, PathBuf};

/// Errors that can occur while interacting with the PID file.
#[derive(Debug, thiserror::Error)]
pub enum PidFileError {
    /// Filesystem error reading, writing, or removing the file.
    #[error("pid file I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// File contents could not be parsed as a `u32`.
    #[error("pid file contents are not a valid PID: {raw:?}")]
    Parse {
        /// Raw bytes (trimmed) as they appeared on disk.
        raw: String,
    },
    /// `dirs::home_dir()` returned `None` — no resolvable home directory.
    #[error("no home directory could be resolved for the pid file path")]
    NoHomeDir,
}

/// Default PID file path: `$HOME/.aasm/gateway.pid`.
///
/// Returns `PidFileError::NoHomeDir` if `dirs::home_dir()` cannot
/// resolve a home directory (rare; sandboxed CI environments).
pub fn pid_file_path() -> Result<PathBuf, PidFileError> {
    let home = dirs::home_dir().ok_or(PidFileError::NoHomeDir)?;
    Ok(home.join(".aasm").join("gateway.pid"))
}

/// Write `pid` to `path`, creating parent directories if needed.
///
/// Overwrites any existing file. The PID is written as ASCII
/// decimal with a single trailing newline so the file is editor-
/// and `cat`-friendly.
pub fn write_pid(path: &Path, pid: u32) -> Result<(), PidFileError> {
    if let Some(parent) = path.parent() {
        // AAASM-6387: `~/.aasm` also holds the local SQLite stores, and this
        // command can create it before the server does, so it must be
        // owner-only from the start.
        aa_core::private_fs::create_private_dir_all(parent)?;
    }
    aa_core::private_fs::write_private_file(path, format!("{pid}\n").as_bytes())?;
    Ok(())
}

/// Read the PID from `path`.
///
/// Returns `Ok(None)` (not `Err`) when the file is absent — that
/// is the common "no gateway running" case and shouldn't surface
/// as an error to callers. Garbage contents yield `PidFileError::Parse`.
pub fn read_pid(path: &Path) -> Result<Option<u32>, PidFileError> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let trimmed = raw.trim();
    trimmed.parse::<u32>().map(Some).map_err(|_| PidFileError::Parse {
        raw: trimmed.to_string(),
    })
}

/// Check whether `pid` refers to a process that is currently alive.
///
/// Implemented via the Unix idiom `kill(pid, 0)`: signal `0` performs
/// no delivery but still runs the kernel's permission and existence
/// checks. Returns `false` for any failure (process gone, permission
/// denied, invalid PID) — callers treat liveness as a single bit.
pub fn is_pid_alive(pid: u32) -> bool {
    // SAFETY: `kill` with signal 0 is signal-safe and side-effect free;
    // it returns 0 if the process exists and the caller has permission
    // to signal it, -1 otherwise. No memory is dereferenced.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0
}

/// Remove the PID file at `path`. Idempotent — a missing file is
/// not an error.
///
/// Called by `aasm stop` after the gateway has terminated. Returns
/// any non-`NotFound` filesystem error verbatim so the operator
/// sees permission issues rather than a silently-stuck PID file.
pub fn remove_pid(path: &Path) -> Result<(), PidFileError> {
    remove_if_present(&url_file_path(path))?;
    remove_if_present(path)
}

fn remove_if_present(path: &Path) -> Result<(), PidFileError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// File beside the PID file that holds the base URL `aasm start` is serving
/// (AAASM-6385).
///
/// Operator commands default to a built-in API URL; without this record a
/// gateway started with `--port`/`--host` is unreachable to a bare
/// `aasm status`, because the start command is the only place that knows where
/// it bound. Removed with the PID file by [`remove_pid`], so it never outlives
/// a stopped gateway.
pub fn url_file_path(pid_file: &Path) -> PathBuf {
    pid_file.with_file_name("gateway.url")
}

/// Record the base URL the gateway just started on (see [`url_file_path`]).
pub fn write_gateway_url(pid_file: &Path, url: &str) -> Result<(), PidFileError> {
    aa_core::private_fs::write_private_file(&url_file_path(pid_file), format!("{url}\n").as_bytes())?;
    Ok(())
}

/// Record a started gateway: PID file and, best effort, its URL.
///
/// The URL record is removed *before* the PID file is rewritten and again if
/// writing it fails, so a PID that is live under the new gateway can never be
/// paired with the previous gateway's address. `Err` is a PID-file failure (the
/// start failed); `Ok(Some(_))` is a URL failure the caller should only warn
/// about (a bare `aasm status` then uses the default, `--api-url` still works).
pub fn record_gateway(
    pid_file: &Path,
    pid: u32,
    url: &str,
    write_url: impl Fn(&Path, &str) -> Result<(), PidFileError>,
) -> Result<Option<PidFileError>, PidFileError> {
    let url_file = url_file_path(pid_file);
    let removed = remove_if_present(&url_file);
    write_pid(pid_file, pid)?;
    if let Err(e) = removed {
        return Ok(Some(e));
    }
    if let Err(e) = write_url(pid_file, url) {
        let _ = remove_if_present(&url_file);
        return Ok(Some(e));
    }
    Ok(None)
}

/// A URL a recorded gateway may be trusted to have: plain `http`, no
/// credentials in it, and a loopback host. `aasm start` only ever binds an
/// address it can reach as `localhost` or an IP, and a file anyone could have
/// edited must not steer every operator command at a remote host.
fn is_trusted_gateway_url(raw: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    let host_ok = match url.host_str() {
        Some(h) if h.eq_ignore_ascii_case("localhost") => true,
        Some(h) => h
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    };
    url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        && host_ok
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}

/// The JSON body of `GET {base}/api/v1/health`, or `None` on any failure.
///
/// Callers pass only a loopback URL they chose. The client ignores proxy
/// settings and never follows a redirect, so the request cannot leave the
/// machine, and it gives up after 500 ms so a stranger on the port cannot stall
/// the caller.
fn fetch_health_body(base: &str) -> Option<serde_json::Value> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let resp = client
        .get(format!("{}/api/v1/health", base.trim_end_matches('/')))
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<serde_json::Value>().ok()
}

/// Whether `base` answers like an Agent Assembly API: `GET /api/v1/health`
/// returns JSON carrying string `status` and `api_version` fields.
///
/// Guards against a recycled PID (the dead gateway's number now belongs to some
/// other process) and against a listener that merely holds the port.
pub fn answers_health_signature(base: &str) -> bool {
    fetch_health_body(base).is_some_and(|v| {
        v.get("status").is_some_and(serde_json::Value::is_string)
            && v.get("api_version").is_some_and(serde_json::Value::is_string)
    })
}

/// The `version` the Agent Assembly API at `base` reports about itself, if it
/// answers the health signature and carries one (AAASM-6385).
pub fn server_reported_version(base: &str) -> Option<String> {
    let body = fetch_health_body(base)?;
    body.get("status")?.as_str()?;
    body.get("api_version")?.as_str()?;
    body.get("version")?.as_str().map(str::to_owned)
}

/// The base URL of the gateway `aasm start` left running, if one is.
///
/// `None` unless the PID file names a live process, a trusted loopback URL was
/// recorded, *and* that URL answers the health signature, so neither a crashed
/// gateway's stale record, a recycled PID, nor an edited file is preferred over
/// the built-in default.
pub fn running_gateway_url_at(pid_file: &Path) -> Option<String> {
    running_gateway_url_with(pid_file, answers_health_signature)
}

fn running_gateway_url_with(pid_file: &Path, answers: impl Fn(&str) -> bool) -> Option<String> {
    let pid = read_pid(pid_file).ok()??;
    if !is_pid_alive(pid) {
        return None;
    }
    let raw = std::fs::read_to_string(url_file_path(pid_file)).ok()?;
    let url = raw.trim();
    (is_trusted_gateway_url(url) && answers(url)).then(|| url.to_string())
}

/// [`running_gateway_url_at`] for the default PID file location.
pub fn running_gateway_url() -> Option<String> {
    running_gateway_url_at(&pid_file_path().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(tmp: &tempfile::TempDir, url: &str) -> PathBuf {
        let pid_file = tmp.path().join("gateway.pid");
        write_pid(&pid_file, std::process::id()).unwrap();
        write_gateway_url(&pid_file, url).unwrap();
        pid_file
    }

    #[test]
    fn a_recorded_url_is_returned_only_while_its_gateway_is_alive_and_answering() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        assert_eq!(running_gateway_url_with(&pid_file, |_| true), None, "nothing recorded");

        let pid_file = live(&tmp, "http://localhost:9123");
        assert_eq!(
            running_gateway_url_with(&pid_file, |_| true).as_deref(),
            Some("http://localhost:9123")
        );
        // PID reuse: the pid is alive but the recorded address does not answer.
        assert_eq!(running_gateway_url_with(&pid_file, |_| false), None, "not answering");

        write_pid(&pid_file, u32::MAX - 1).unwrap();
        assert_eq!(running_gateway_url_with(&pid_file, |_| true), None, "stale record");
    }

    #[test]
    fn only_trusted_loopback_http_urls_are_followed() {
        for bad in [
            "",
            "localhost:1",
            "http://a b",
            "file:///etc/passwd",
            "https://localhost:9123",
            "http://evil.example.com:9123",
            "http://10.0.0.5:9123",
            "http://user:pw@localhost:9123",
            "http://user@127.0.0.1:9123",
            "http://localhost:9123/path",
            "http://localhost:9123/?q=1",
        ] {
            let tmp = tempfile::TempDir::new().unwrap();
            let pid_file = live(&tmp, "http://localhost:1");
            std::fs::write(url_file_path(&pid_file), bad).unwrap();
            assert_eq!(running_gateway_url_with(&pid_file, |_| true), None, "{bad:?}");
        }
        for good in [
            "http://localhost:9123",
            "http://127.0.0.1:9123",
            "http://127.0.0.2:9123",
            "http://[::1]:9123",
        ] {
            let tmp = tempfile::TempDir::new().unwrap();
            let pid_file = live(&tmp, good);
            assert_eq!(
                running_gateway_url_with(&pid_file, |_| true).as_deref(),
                Some(good),
                "{good}"
            );
        }
    }

    #[test]
    fn the_health_signature_needs_an_aa_shaped_json_answer() {
        use std::io::{Read, Write};
        let serve = |body: &'static str| {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            std::thread::spawn(move || {
                if let Ok((mut s, _)) = l.accept() {
                    let mut b = [0u8; 1024];
                    let _ = s.read(&mut b);
                    let _ = write!(
                        s,
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            });
            format!("http://{addr}")
        };
        assert!(answers_health_signature(&serve(
            r#"{"status":"ok","version":"x","api_version":"v1"}"#
        )));
        assert!(!answers_health_signature(&serve(r#"{"hello":"world"}"#)));
        assert!(!answers_health_signature(&serve("not json")));
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        assert!(!answers_health_signature(&closed));
    }

    #[test]
    fn the_reported_version_is_read_only_from_an_aa_shaped_health_answer() {
        use std::io::{Read, Write};
        let serve = |body: &'static str| {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            std::thread::spawn(move || {
                if let Ok((mut s, _)) = l.accept() {
                    let mut b = [0u8; 1024];
                    let _ = s.read(&mut b);
                    let _ = write!(
                        s,
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            });
            format!("http://{addr}")
        };
        assert_eq!(
            server_reported_version(&serve(r#"{"status":"ok","version":"0.0.1-rc.6","api_version":"v1"}"#)).as_deref(),
            Some("0.0.1-rc.6")
        );
        // A listener that merely returns a `version` is not an Agent Assembly API.
        assert_eq!(server_reported_version(&serve(r#"{"version":"9.9.9"}"#)), None);
        // An answer with no version reports none rather than a guess.
        assert_eq!(
            server_reported_version(&serve(r#"{"status":"ok","api_version":"v1"}"#)),
            None
        );
    }

    #[test]
    fn a_failed_url_write_never_leaves_the_previous_gateways_url_beside_a_live_pid() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = live(&tmp, "http://localhost:1111"); // the OLD gateway's record
        let failing =
            |_: &Path, _: &str| -> Result<(), PidFileError> { Err(std::io::Error::other("disk full").into()) };
        let r = record_gateway(&pid_file, std::process::id(), "http://localhost:2222", failing).unwrap();
        assert!(r.is_some(), "the URL failure is reported, not fatal");
        assert!(!url_file_path(&pid_file).exists(), "old URL must not survive");
        assert_eq!(running_gateway_url_with(&pid_file, |_| true), None);

        let ok = record_gateway(
            &pid_file,
            std::process::id(),
            "http://localhost:2222",
            write_gateway_url,
        )
        .unwrap();
        assert!(ok.is_none());
        assert_eq!(
            running_gateway_url_with(&pid_file, |_| true).as_deref(),
            Some("http://localhost:2222")
        );
    }

    #[cfg(unix)]
    #[test]
    fn pid_and_url_files_are_owner_only_even_over_a_looser_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        std::fs::write(url_file_path(&pid_file), "x").unwrap();
        std::fs::set_permissions(url_file_path(&pid_file), std::fs::Permissions::from_mode(0o644)).unwrap();
        write_pid(&pid_file, 1).unwrap();
        write_gateway_url(&pid_file, "http://localhost:1").unwrap();
        for f in [pid_file.clone(), url_file_path(&pid_file)] {
            assert_eq!(
                std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o600,
                "{f:?}"
            );
        }
    }

    #[test]
    fn remove_pid_also_removes_the_recorded_url() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        write_pid(&pid_file, 1).unwrap();
        write_gateway_url(&pid_file, "http://localhost:1").unwrap();
        remove_pid(&pid_file).unwrap();
        assert!(!pid_file.exists() && !url_file_path(&pid_file).exists());
    }

    /// AAASM-6387 — the directory the PID file lands in is created owner-only,
    /// because it is the same `~/.aasm` that holds the local databases.
    #[cfg(unix)]
    #[test]
    fn write_pid_creates_owner_only_parent_directory() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".aasm").join("gateway.pid");
        write_pid(&path, 4242).unwrap();
        let mode = std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn pid_file_path_lives_under_aasm_directory() {
        let path = pid_file_path().expect("home dir resolves in tests");
        // Don't assert against a literal absolute path — `$HOME` differs
        // per machine. Just confirm the structure: `.../.aasm/gateway.pid`.
        assert!(
            path.ends_with(".aasm/gateway.pid"),
            "expected suffix `.aasm/gateway.pid`, got {}",
            path.display()
        );
    }

    #[test]
    fn write_pid_creates_missing_parent_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let nested = tmp.path().join("layer-a").join("layer-b").join("gateway.pid");
        // Parent directories do not exist yet.
        assert!(!nested.parent().unwrap().exists());
        write_pid(&nested, 42).expect("write_pid should mkdir -p the parent");
        assert!(nested.exists(), "pid file should exist after write_pid");
    }

    #[test]
    fn read_pid_returns_none_for_missing_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let absent = tmp.path().join("gateway.pid");
        // Sanity-check: the path really does not exist before we probe it.
        assert!(!absent.exists());
        assert_eq!(read_pid(&absent).unwrap(), None);
    }

    #[test]
    fn write_then_read_round_trip_preserves_pid() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        write_pid(&pid_file, 13_579).unwrap();
        assert_eq!(read_pid(&pid_file).unwrap(), Some(13_579));
    }

    #[test]
    fn read_pid_returns_parse_error_on_garbage_contents() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        std::fs::write(&pid_file, "not-a-pid\n").unwrap();
        let err = read_pid(&pid_file).unwrap_err();
        match err {
            PidFileError::Parse { raw } => assert_eq!(raw, "not-a-pid"),
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn remove_pid_is_idempotent_when_file_is_absent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        // First call against a missing file must succeed silently.
        remove_pid(&pid_file).expect("first call should be a no-op");
        // Calling again is still fine.
        remove_pid(&pid_file).expect("second call should also be a no-op");
    }

    #[test]
    fn is_pid_alive_recognises_current_process_and_rejects_obvious_dead_pid() {
        // The test process itself is alive by construction.
        let self_pid = std::process::id();
        assert!(is_pid_alive(self_pid), "self PID must be reported alive");

        // PID 0 is reserved by the kernel — `kill(0, 0)` targets the
        // caller's process group, which is not a real liveness probe
        // for an arbitrary PID. Use a near-`pid_t::MAX` value instead;
        // no real process can hold it on modern Unix.
        let unreachable = (libc::pid_t::MAX as u32).saturating_sub(1);
        assert!(!is_pid_alive(unreachable), "PID {unreachable} should not be alive");
    }
}
