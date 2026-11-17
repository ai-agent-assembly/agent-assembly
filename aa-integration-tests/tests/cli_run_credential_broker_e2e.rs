//! AAASM-6262 (golden journey J84) -- a local, loopback-only end-to-end run of the
//! credential broker: a governed agent calls a credential-requiring service
//! **without ever holding the credential**, and the credential is then revoked.
//!
//! # What is real, what is stand-in
//!
//! Real: `aasm run` (the supervisor and its launch environment), the credential
//! delivery to the per-launch proxy on stdin (AAASM-6395), the proxy's
//! credential injection and revocation path, `aasm proxy revoke-credential`
//! over the per-launch control socket, and the process surfaces measured with
//! `ps`, `lsof` and (in the `#[ignore]`d test) `lldb`.
//!
//! Stand-in: the proxy binary is `examples/proxy_with_mock_upstream` (the shipped
//! `ProxyServer`, only its upstream dial redirected -- the genuine binary refuses
//! loopback dials by design); the agent is `examples/j84_probe_agent` (an
//! unsigned Rust process, so a same-uid debugger can attach to it); the "service"
//! is a loopback TLS server in this file that **validates** the credential and
//! answers 401 to anything else, so a 200 is an actual verdict and not a fake.
//!
//! # The credential
//!
//! A synthetic value generated per run (`sk-ant-QA6262-J84-<pid>-<nanos>`), never
//! a real secret. It is handed to `aasm run` only as the operator's
//! `AA_PROXY_PROVIDER_KEYS`. Nothing here prints surface bytes: every check
//! reduces a surface to a count of occurrences of the full value or of its random
//! suffix (in case of partial redaction) and reports only the surface name.
//!
//! # What this does not cover
//!
//! * The per-launch proxy's own stdout and stderr go to `/dev/null` (`ProxyGuard`),
//!   and the proxy audit JSONL is not written for these calls, so a leak into the
//!   proxy's log output cannot be observed here. The receipt the run does write
//!   (`runs/<agent>-<id>/audit.jsonl`) and the supervisor's stderr are scanned.
//! * The proxy is the `proxy_with_mock_upstream` stand-in, whose credential loading is
//!   a copy of `aa_proxy::run`'s; a regression in the shipped binary's own wiring is
//!   covered only by the sentinel and proxy suites, not here.
//! * No ambient provider key is set in the brokered run, so `aa-isolation`'s
//!   withholding of an ambient `ANTHROPIC_API_KEY` is covered by
//!   `cli_run_credential_broker_sentinel.rs`, not here.
//! * macOS only (`ps -Eww`, `lsof`, `lldb`); Linux `/proc` is not exercised, and a
//!   debug, unsigned build is what a debugger could attach to.
//!
//! # Negative controls
//!
//! Each "this surface is clean" assertion is paired with a run in which the same
//! scanner must find the value: an ambient-credential launch (no broker) must be
//! flagged on the agent's environment and `ps -Eww`; the validating service must
//! refuse the agent's own wrong credential; the scanners must find a value planted
//! in a file, an argv, an environment and an open descriptor; and a launch that is
//! not revoked must keep succeeding, so the 403 is the revocation's doing.

// Only the macOS-gated module below calls `start_full_gateway`. The shared support module
// has no blanket `allow(dead_code)`, so on any other target (CI clippy runs on Linux)
// declaring it here would leave `start_full_gateway` unused and fail `-D warnings`.
#[cfg(all(unix, target_os = "macos"))]
#[allow(unused_imports)]
mod conformance_gateway_support;
#[allow(unused_imports)]
mod proxy_trust_support;

#[cfg(all(unix, target_os = "macos"))]
mod credential_broker_e2e {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use aa_proxy::tls::CaStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::conformance_gateway_support::start_full_gateway;
    use super::proxy_trust_support::{j84_probe_agent_binary, TrustedProxy};

    const HOST: &str = "api.anthropic.com";
    const AGENT_ID: &str = "aaasm6262-j84";

    /// A fresh synthetic credential: the full value and its random suffix.
    fn synthetic() -> (String, String) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("now is after the epoch")
            .as_nanos();
        let suffix = format!("{}-{nanos}", std::process::id());
        (format!("sk-ant-QA6262-J84-{suffix}"), suffix)
    }

    #[derive(Default, Clone, Debug)]
    struct ServiceStats {
        valid: usize,
        invalid: usize,
    }

    /// A loopback TLS service that accepts exactly one credential in `x-api-key`.
    struct ValidatingService {
        addr: std::net::SocketAddr,
        stats: Arc<Mutex<ServiceStats>>,
        _task: tokio::task::AbortHandle,
    }

    impl ValidatingService {
        async fn start(ca: &CaStore, accepted_credential: String) -> anyhow::Result<Self> {
            let ck = ca.sign_cert(HOST).map_err(|e| anyhow::anyhow!("sign_cert: {e}"))?;
            let config = ServerConfig::builder().with_no_client_auth().with_single_cert(
                vec![CertificateDer::from(ck.cert_der.clone())],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(ck.key_der.clone())),
            )?;
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let stats = Arc::new(Mutex::new(ServiceStats::default()));
            let task_stats = Arc::clone(&stats);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let acceptor = acceptor.clone();
                    let stats = Arc::clone(&task_stats);
                    let expected = accepted_credential.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut buf = Vec::new();
                        let mut tmp = [0u8; 4096];
                        let head_end = loop {
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break p;
                            }
                            match tls.read(&mut tmp).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                        let presented = head.lines().find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim().eq_ignore_ascii_case("x-api-key").then(|| v.trim().to_owned())
                        });
                        let accepted = presented.as_deref() == Some(expected.as_str());
                        {
                            let mut s = stats.lock().expect("stats mutex");
                            if accepted {
                                s.valid += 1;
                            } else {
                                s.invalid += 1;
                            }
                        }
                        let (status, body) = if accepted {
                            ("200 OK", r#"{"ok":true}"#)
                        } else {
                            ("401 Unauthorized", r#"{"error":"invalid credential"}"#)
                        };
                        let response = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                             Connection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = tls.write_all(response.as_bytes()).await;
                        let _ = tls.shutdown().await;
                    });
                }
            });
            Ok(Self {
                addr,
                stats,
                _task: task.abort_handle(),
            })
        }

        fn stats(&self) -> ServiceStats {
            self.stats.lock().expect("stats mutex").clone()
        }
    }

    // ---- scanners: every one reduces its input to a count ------------------------

    /// Occurrences of `needle` in `hay`. The only thing a scanner ever reports.
    fn occurrences(hay: &[u8], needle: &str) -> usize {
        let n = needle.as_bytes();
        if n.is_empty() || hay.len() < n.len() {
            return 0;
        }
        hay.windows(n.len()).filter(|w| *w == n).count()
    }

    /// Run `cmd` for at most `patience`, then SIGKILL it: a stalled host tool must
    /// not hold a queue lane. Pipes are drained on threads so a large output cannot
    /// block the child. `None` means it could not start or had to be killed.
    fn output_within(mut cmd: std::process::Command, patience: Duration) -> Option<std::process::Output> {
        use std::io::Read;
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().ok()?;
        let mut out = child.stdout.take()?;
        let mut err = child.stderr.take()?;
        // Readers report over channels and are never joined: a grandchild (lldb's
        // debugserver) can keep an inherited pipe open after the child is gone, and a
        // join would then block past the deadline. After a grace period the reader is
        // detached and what it has not delivered is treated as empty.
        let (tx_out, rx_out) = std::sync::mpsc::channel();
        let (tx_err, rx_err) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = out.read_to_end(&mut b);
            let _ = tx_out.send(b);
        });
        std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = err.read_to_end(&mut b);
            let _ = tx_err.send(b);
        });
        let deadline = Instant::now() + patience;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        const PIPE_GRACE: Duration = Duration::from_secs(3);
        let stdout = rx_out.recv_timeout(PIPE_GRACE).unwrap_or_default();
        let stderr = rx_err.recv_timeout(PIPE_GRACE).unwrap_or_default();
        status.map(|status| std::process::Output { status, stdout, stderr })
    }

    /// Combined output of a host tool. Never printed: callers only count it. A tool
    /// that cannot run or stalls FAILS the test: an empty result must never read as
    /// "scanned and clean".
    fn tool(program: &str, args: &[&str]) -> Vec<u8> {
        let mut cmd = std::process::Command::new(program);
        cmd.args(args);
        let o = output_within(cmd, Duration::from_secs(60))
            .unwrap_or_else(|| panic!("host tool `{program}` did not run to completion (NOT RUN, not clean)"));
        [o.stdout, o.stderr].concat()
    }

    /// Every regular file under `root`, concatenated with its path (a descriptor
    /// or file *name* can leak a value as well as its content).
    fn tree_bytes(root: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            out.extend_from_slice(path.to_string_lossy().as_bytes());
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                if let Ok(rd) = std::fs::read_dir(&path) {
                    stack.extend(rd.flatten().map(|e| e.path()));
                }
            } else if meta.is_file() {
                if let Ok(bytes) = std::fs::read(&path) {
                    out.extend_from_slice(&bytes);
                }
            }
        }
        out
    }

    /// Relative file names under `root` (names only), so the evidence shows which
    /// receipts and logs the run actually produced.
    fn file_names(root: &Path) -> Vec<String> {
        let mut names = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                if let Ok(rd) = std::fs::read_dir(&path) {
                    stack.extend(rd.flatten().map(|e| e.path()));
                }
            } else if meta.is_file() {
                names.push(path.strip_prefix(root).unwrap_or(&path).display().to_string());
            }
        }
        names.sort();
        names
    }

    /// One thing that could hold the credential: a name and its raw bytes.
    struct Surface {
        name: String,
        bytes: Vec<u8>,
    }

    /// The surfaces whose bytes hold the full value or its random suffix, with the
    /// count. Names only: this is the single reduction every assertion goes through.
    fn leaking(surfaces: &[Surface], synth: &(String, String)) -> BTreeMap<String, usize> {
        surfaces
            .iter()
            .filter_map(|s| {
                let n = occurrences(&s.bytes, &synth.0) + occurrences(&s.bytes, &synth.1);
                (n > 0).then(|| (s.name.clone(), n))
            })
            .collect()
    }

    fn process_surfaces(role: &str, pid: u32) -> Vec<Surface> {
        let p = pid.to_string();
        vec![
            // argv and the exec-time environment block, as any same-uid process reads them.
            Surface {
                name: format!("ps_eww:{role}"),
                bytes: tool("ps", &["-Eww", "-p", &p]),
            },
            Surface {
                name: format!("lsof:{role}"),
                bytes: tool("lsof", &["-nP", "-p", &p]),
            },
        ]
    }

    // ---- the journey ------------------------------------------------------------

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        /// The operator's credential is brokered: only `AA_PROXY_PROVIDER_KEYS`.
        Brokered,
        /// Negative control: no broker, the credential is ambient in `ANTHROPIC_API_KEY`.
        AmbientLeak,
    }

    struct Journey {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        agent_dir: PathBuf,
        state: PathBuf,
        ca_dir: PathBuf,
        audit: PathBuf,
        stdout_log: PathBuf,
        stderr_log: PathBuf,
        proxy: TrustedProxy,
        service: ValidatingService,
        _gateway_endpoint: String,
        child: std::process::Child,
        synth: (String, String),
    }

    impl Drop for Journey {
        /// A failed assertion must not leave a supervisor, an agent and a proxy
        /// running: release the agent, give the supervisor a moment to end by itself,
        /// then terminate it (its own shutdown stops the proxy it started).
        fn drop(&mut self) {
            let _ = std::fs::write(self.agent_dir.join("go"), "1");
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            // SAFETY: plain signal to a child this struct owns.
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn wait_for(path: &Path, patience: Duration) -> bool {
        let deadline = Instant::now() + patience;
        while Instant::now() < deadline {
            if path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    impl Journey {
        async fn start(mode: Mode) -> anyhow::Result<Self> {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tmp = tempfile::tempdir()?;
            let root = tmp.path().to_path_buf();
            let (ca_dir, state, agent_dir, home) = (
                root.join("ca"),
                root.join("state"),
                root.join("agent"),
                root.join("home"),
            );
            for d in [&ca_dir, &state, &agent_dir, &home] {
                std::fs::create_dir_all(d)?;
            }
            let synth = synthetic();

            let ca = CaStore::load_or_create(&ca_dir)
                .await
                .map_err(|e| anyhow::anyhow!("ca: {e}"))?;
            let service = ValidatingService::start(&ca, synth.0.clone()).await?;
            drop(ca);
            let proxy = TrustedProxy::start_intercepting(&ca_dir, service.addr, &state, &[])?;

            let policy = root.join("policy.yaml");
            std::fs::write(
                &policy,
                "apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nmetadata:\n  name: aaasm6262-j84\n  \
                 version: \"0.1.0\"\nspec:\n  tools:\n    read_file:\n      allow: true\n",
            )?;
            // The gateway the proxy asks for its network verdict must serve the policy
            // service as well as the lifecycle one: with only the lifecycle half the
            // proxy fails closed on the CONNECT, which is not the behaviour under test.
            let (gateway_endpoint, _registry) = start_full_gateway(&policy).await?;
            let probe = j84_probe_agent_binary();
            let audit = root.join("proxy-audit.jsonl");
            let stdout_log = root.join("aasm.stdout.log");
            let stderr_log = root.join("aasm.stderr.log");

            let mut cmd = std::process::Command::new(proxy.aasm());
            cmd.env_clear()
                .current_dir(&root)
                .env("PATH", format!("{}:/usr/bin:/bin", proxy.proxy_bin_dir().display()))
                .env("HOME", &home)
                .env("AASM_STATE_DIR", &state)
                .env("AA_CA_DIR", &ca_dir)
                .env("AA_DATA_DIR", proxy.data_dir())
                .env("AA_GATEWAY_ENDPOINT", &gateway_endpoint)
                .env("AA_TEST_PROXY_UPSTREAM", service.addr.to_string())
                .env("AA_PROXY_LLM_ONLY", "false")
                .env("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY", "1")
                .env("AA_PROXY_AUDIT_JSONL_PATH", &audit);
            match mode {
                Mode::Brokered => {
                    cmd.env("AA_PROXY_PROVIDER_KEYS", format!("{HOST}={}", synth.0));
                }
                Mode::AmbientLeak => {
                    cmd.env("ANTHROPIC_API_KEY", &synth.0);
                }
            }
            cmd.args(["run", "--policy"])
                .arg(&policy)
                .args(["--agent-id", AGENT_ID, "exec", "--"])
                .arg(&probe)
                .arg(&agent_dir)
                .arg(ca_dir.join("ca-cert.pem"))
                .stdout(std::fs::File::create(&stdout_log)?)
                .stderr(std::fs::File::create(&stderr_log)?);
            let child = cmd.spawn()?;

            Ok(Self {
                _tmp: tmp,
                root,
                agent_dir,
                state,
                ca_dir,
                audit,
                stdout_log,
                stderr_log,
                proxy,
                service,
                _gateway_endpoint: gateway_endpoint,
                child,
                synth,
            })
        }

        fn wait_ready(&self) {
            assert!(
                wait_for(&self.agent_dir.join("ready"), Duration::from_secs(120)),
                "the agent never completed its first call -- see {} / {}",
                self.stderr_log.display(),
                self.stdout_log.display(),
            );
        }

        fn status(&self, call: u8) -> String {
            std::fs::read_to_string(self.agent_dir.join(format!("call{call}.status"))).unwrap_or_default()
        }

        fn body(&self, call: u8) -> String {
            std::fs::read_to_string(self.agent_dir.join(format!("call{call}.body"))).unwrap_or_default()
        }

        /// pid of the agent, as the agent itself reported it.
        fn agent_pid(&self) -> u32 {
            let own = std::fs::read_to_string(self.agent_dir.join("self.txt")).expect("agent self report");
            own.lines()
                .next()
                .and_then(|l| l.strip_prefix("pid="))
                .and_then(|p| p.parse().ok())
                .expect("self.txt starts with pid=")
        }

        /// pid of this launch's own `aa-proxy` stand-in: the supervisor's child
        /// whose executable is named `aa-proxy`.
        fn launch_proxy_pid(&self) -> u32 {
            let kids = tool("pgrep", &["-P", &self.child.id().to_string()]);
            String::from_utf8_lossy(&kids)
                .lines()
                .filter_map(|l| l.trim().parse::<u32>().ok())
                .find(|pid| {
                    String::from_utf8_lossy(&tool("ps", &["-o", "comm=", "-p", &pid.to_string()]))
                        .trim()
                        .ends_with("aa-proxy")
                })
                .expect("the supervisor has an aa-proxy child while the agent runs")
        }

        /// Every surface that could hold the credential while the launch runs.
        fn surfaces(&self) -> Vec<Surface> {
            let mut all = Vec::new();
            all.extend(process_surfaces("aasm", self.child.id()));
            all.extend(process_surfaces("agent", self.agent_pid()));
            all.extend(process_surfaces("proxy", self.launch_proxy_pid()));
            all.extend(self.surfaces_after_exit());
            all
        }

        /// The file-backed surfaces: state and receipts, logs, proxy audit, CA dir.
        fn surfaces_after_exit(&self) -> Vec<Surface> {
            let mut all = Vec::new();
            for (name, root) in [
                ("tree:state_and_receipts", &self.state),
                ("tree:agent_dir", &self.agent_dir),
                ("tree:ca_dir", &self.ca_dir),
                ("tree:proxy_data", &self.proxy.data_dir().to_path_buf()),
            ] {
                all.push(Surface {
                    name: name.into(),
                    bytes: tree_bytes(root),
                });
            }
            for (name, file) in [
                ("file:proxy_audit_jsonl", &self.audit),
                ("file:standalone_proxy_log", &self.proxy.log_path().to_path_buf()),
                ("file:aasm_stdout", &self.stdout_log),
                ("file:aasm_stderr", &self.stderr_log),
            ] {
                all.push(Surface {
                    name: name.into(),
                    bytes: std::fs::read(file).unwrap_or_default(),
                });
            }
            all
        }

        /// `aasm proxy revoke-credential` against this launch's proxy.
        fn revoke(&self) -> std::process::Output {
            let mut cmd = std::process::Command::new(self.proxy.aasm());
            cmd.env_clear()
                .env("HOME", self.root.join("home"))
                .env("AASM_STATE_DIR", &self.state)
                .env("AA_DATA_DIR", self.proxy.data_dir())
                .args(["proxy", "revoke-credential", "--host", HOST, "--agent", AGENT_ID]);
            output_within(cmd, Duration::from_secs(60)).expect("aasm proxy revoke-credential ran to completion")
        }

        /// Release the agent for its second call and wait for the supervisor to end.
        fn finish(&mut self) -> std::process::ExitStatus {
            std::fs::write(self.agent_dir.join("go"), "1").expect("release the agent");
            assert!(
                wait_for(&self.agent_dir.join("call2.status"), Duration::from_secs(60)),
                "the agent never completed its second call -- see {}",
                self.stderr_log.display()
            );
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(st) = self.child.try_wait().expect("poll aasm run") {
                    return st;
                }
                if Instant::now() >= deadline {
                    // SAFETY: plain signal to a child this struct owns.
                    unsafe {
                        libc::kill(self.child.id() as i32, libc::SIGTERM);
                    }
                    std::thread::sleep(Duration::from_secs(5));
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    panic!("aasm run did not end within 60s of the agent finishing");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// What one `lldb` heap scan covered, so `(0, 0)` is distinguishable from a
    /// scan that read nothing.
    #[derive(Debug)]
    struct MemoryScan {
        counts: (usize, usize),
        bytes_scanned: usize,
        regions: usize,
        read_failures: usize,
    }

    /// Smallest amount of writable memory a scan of these processes must cover for a
    /// zero count to mean anything (a Rust process maps far more than this).
    const MIN_SCANNED_BYTES: usize = 1 << 20;

    /// Occurrences of the full value and of its suffix in a live process's writable
    /// memory, counted by an `lldb` attached for the duration of the scan (same
    /// uid, no core file). `None` means the debugger could not attach, scan or
    /// finish in time, which the caller must treat as "not measured", never "clean".
    fn memory_counts(pid: u32, synth: &(String, String)) -> Option<MemoryScan> {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/j84_lldb_scan.py");
        let mut cmd = std::process::Command::new("lldb");
        cmd.env_clear()
            .env("HOME", std::env::var_os("HOME").unwrap_or_default())
            .env("PATH", "/usr/bin:/bin")
            // The needles reach lldb through its environment, so they are in no argv.
            .env("J84_NEEDLES", format!("{},{}", synth.0, synth.1))
            .args(["--batch", "-p", &pid.to_string(), "-o"])
            .arg(format!("command script import {script}"))
            .args(["-o", "detach"]);
        let out = output_within(cmd, Duration::from_secs(300))?;
        let text = String::from_utf8_lossy(&[out.stdout, out.stderr].concat()).into_owned();
        let line = text.lines().find(|l| l.starts_with("J84SCAN counts=["))?;
        let inner = line.strip_prefix("J84SCAN counts=[")?.split(']').next()?;
        let mut parts = inner.split(',').map(|p| p.trim().parse::<usize>());
        let counts = (parts.next()?.ok()?, parts.next()?.ok()?);
        let field = |name: &str| -> Option<usize> {
            line.split_whitespace()
                .find_map(|w| w.strip_prefix(name)?.strip_prefix('=')?.parse().ok())
        };
        Some(MemoryScan {
            counts,
            bytes_scanned: field("bytes_scanned")?,
            regions: field("regions")?,
            read_failures: field("read_failures")?,
        })
    }

    /// A scan that attached but read (almost) nothing is "not measured", not clean.
    fn scanned_enough(role: &str, scan: Option<MemoryScan>) -> MemoryScan {
        let scan = scan.unwrap_or_else(|| panic!("lldb could not scan the {role} (NOT RUN, not clean)"));
        assert!(
            scan.bytes_scanned >= MIN_SCANNED_BYTES,
            "the {role} scan covered only {} bytes in {} regions ({} read failures): not a measurement",
            scan.bytes_scanned,
            scan.regions,
            scan.read_failures
        );
        // A mostly-failed scan must not read as "0 hits": at most 5% of regions may fail.
        assert!(
            scan.read_failures * 20 <= scan.regions,
            "the {role} scan failed to read {} of {} regions: not a measurement",
            scan.read_failures,
            scan.regions
        );
        scan
    }

    /// Surfaces a live brokered launch is known to populate.
    const POPULATED_WHILE_RUNNING: [&str; 11] = [
        "ps_eww:aasm",
        "ps_eww:agent",
        "ps_eww:proxy",
        "lsof:aasm",
        "lsof:agent",
        "lsof:proxy",
        "tree:state_and_receipts",
        "tree:agent_dir",
        "tree:ca_dir",
        "tree:proxy_data",
        "file:aasm_stderr",
    ];

    /// File-backed surfaces known to be populated once the run has ended.
    const POPULATED_AFTER_EXIT: [&str; 7] = [
        "agent:call1.body",
        "agent:call2.body",
        "tree:state_and_receipts",
        "tree:agent_dir",
        "tree:ca_dir",
        "tree:proxy_data",
        "file:aasm_stderr",
    ];

    /// A "clean" verdict over a surface that is empty is vacuous. These are the
    /// surfaces the run is known to populate; each must hold something.
    fn assert_populated(surfaces: &[Surface], must_hold_bytes: &[&str]) {
        for name in must_hold_bytes {
            let s = surfaces
                .iter()
                .find(|s| s.name == *name)
                .unwrap_or_else(|| panic!("no surface named {name}"));
            assert!(
                !s.bytes.is_empty(),
                "surface {name} is empty, so a clean verdict over it is vacuous"
            );
        }
    }

    fn report(label: &str, surfaces: &[Surface], synth: &(String, String)) {
        let hits = leaking(surfaces, synth);
        // Sizes, so an empty surface (a file the run never wrote) is visibly
        // "nothing to scan" and not mistaken for "scanned and clean".
        let sizes: Vec<String> = surfaces
            .iter()
            .map(|s| format!("{}={}", s.name, s.bytes.len()))
            .collect();
        println!(
            "J84-EVIDENCE {label}: surfaces_scanned={} non_empty={} surfaces_with_credential={} names={:?} sizes_bytes=[{}]",
            surfaces.len(),
            surfaces.iter().filter(|s| !s.bytes.is_empty()).count(),
            hits.len(),
            hits.keys().collect::<Vec<_>>(),
            sizes.join(" ")
        );
    }

    // ---- the tests ----------------------------------------------------------------

    /// (a) the call succeeds with the credential, (b) revocation breaks the NEXT
    /// call, (c) no scanned surface holds the credential at any point.
    #[tokio::test(flavor = "multi_thread")]
    async fn brokered_call_succeeds_revocation_breaks_the_next_call_and_no_surface_holds_the_credential(
    ) -> anyhow::Result<()> {
        let mut j = Journey::start(Mode::Brokered).await?;
        j.wait_ready();

        // (a) The agent sent a wrong credential of its own; only the broker's
        // injection can make the validating service answer 200.
        assert_eq!(j.status(1), "200", "call 1 body: {}", j.body(1));
        let s1 = j.service.stats();
        assert_eq!((s1.valid, s1.invalid), (1, 0), "the service saw exactly one valid call");

        let before = j.surfaces();
        report("while-running", &before, &j.synth);
        assert_populated(&before, &POPULATED_WHILE_RUNNING);
        assert_eq!(
            leaking(&before, &j.synth),
            BTreeMap::new(),
            "surfaces holding the credential while the agent runs"
        );

        // (b) revoke, then the NEXT call is refused and never reaches the service.
        // Exit 3 is the documented, accurate answer for a per-launch proxy: revoked in
        // the running proxy, with no durable record (the proxy is never restarted, and a
        // record shared across launches would carry a revocation into later ones).
        let revoked = j.revoke();
        assert_eq!(
            revoked.status.code(),
            Some(3),
            "revoke stderr: {}",
            String::from_utf8_lossy(&revoked.stderr)
        );
        assert!(String::from_utf8_lossy(&revoked.stderr).contains("revoked in memory only"));
        let exit = j.finish();
        assert!(exit.success(), "aasm run exit: {exit:?}");
        assert_eq!(j.status(2), "403", "call 2 body: {}", j.body(2));
        assert!(
            j.body(2).contains("credential_revoked"),
            "the refusal must be distinguishable from an upstream 401: {}",
            j.body(2)
        );
        let s2 = j.service.stats();
        assert_eq!(
            (s2.valid, s2.invalid),
            (1, 0),
            "the revoked call must never reach the service (no second request of any kind)"
        );

        // (c) again after the run, when receipts and logs are final. The agent and
        // proxy have exited, so only files remain, plus whatever the supervisor left.
        let after: Vec<Surface> = j
            .surfaces_after_exit()
            .into_iter()
            .chain([
                Surface {
                    name: "agent:call1.body".into(),
                    bytes: j.body(1).into_bytes(),
                },
                Surface {
                    name: "agent:call2.body".into(),
                    bytes: j.body(2).into_bytes(),
                },
            ])
            .collect();
        report("after-exit", &after, &j.synth);
        assert_populated(&after, &POPULATED_AFTER_EXIT);
        // Receipts, audit and logs the run did not write are named, not counted clean.
        println!("J84-EVIDENCE state-tree-files: {:?}", file_names(&j.state));
        for name in [
            "file:proxy_audit_jsonl",
            "file:standalone_proxy_log",
            "file:aasm_stdout",
        ] {
            let empty = after
                .iter()
                .find(|s| s.name == name)
                .is_some_and(|s| s.bytes.is_empty());
            println!(
                "J84-EVIDENCE {name}: {}",
                if empty {
                    "NOT PRODUCED (nothing to scan)"
                } else {
                    "produced"
                }
            );
        }
        assert_eq!(
            leaking(&after, &j.synth),
            BTreeMap::new(),
            "files holding the credential after the run"
        );
        Ok(())
    }

    /// Control for (b): the identical run, never revoked, keeps succeeding, so the
    /// 403 above is the revocation's doing and not a side effect of the harness.
    #[tokio::test(flavor = "multi_thread")]
    async fn control_without_revocation_the_next_call_still_succeeds() -> anyhow::Result<()> {
        let mut j = Journey::start(Mode::Brokered).await?;
        j.wait_ready();
        assert_eq!(j.status(1), "200");
        let exit = j.finish();
        assert!(exit.success(), "aasm run exit: {exit:?}");
        assert_eq!(j.status(2), "200", "call 2 body: {}", j.body(2));
        let s = j.service.stats();
        assert_eq!((s.valid, s.invalid), (2, 0));
        Ok(())
    }

    /// Control for (a) and (c): with no broker, the credential is ambient. The
    /// validating service must refuse the agent's own (wrong) credential, and the
    /// same scanners must flag the agent's environment and `ps -Eww`.
    #[tokio::test(flavor = "multi_thread")]
    async fn control_ambient_credential_is_refused_by_the_service_and_flagged_by_the_scanners() -> anyhow::Result<()> {
        let mut j = Journey::start(Mode::AmbientLeak).await?;
        j.wait_ready();
        assert_eq!(j.status(1), "401", "without the broker nothing injects the credential");
        let s = j.service.stats();
        assert_eq!((s.valid, s.invalid), (0, 1));

        let mut surfaces = j.surfaces();
        surfaces.push(Surface {
            name: "agent:self_report".into(),
            bytes: std::fs::read(j.agent_dir.join("self.txt"))?,
        });
        let hits = leaking(&surfaces, &j.synth);
        report("ambient-control", &surfaces, &j.synth);
        assert_populated(&surfaces, &POPULATED_WHILE_RUNNING);
        // The proxy inherits the ambient key too, so it must flag as well.
        for must_flag in ["ps_eww:agent", "ps_eww:aasm", "ps_eww:proxy", "agent:self_report"] {
            assert!(
                hits.contains_key(must_flag),
                "the scanners missed {must_flag}: {hits:?}"
            );
        }
        let _ = j.finish();
        Ok(())
    }

    /// Control for the bound itself: a grandchild that keeps stdout open must not hold
    /// `output_within` past its deadline, whether the child exits or has to be killed.
    #[test]
    fn control_output_within_returns_even_when_a_grandchild_holds_the_pipe() {
        let started = Instant::now();
        // The shell exits at once; the backgrounded sleep inherits and keeps stdout open.
        let mut exits = std::process::Command::new("sh");
        exits.args(["-c", "sleep 8 & echo hi"]);
        let out = output_within(exits, Duration::from_secs(5)).expect("the shell exits on its own");
        assert!(out.status.success());

        // The shell is still running at the deadline and has to be killed.
        let mut stalls = std::process::Command::new("sh");
        stalls.args(["-c", "sleep 8 & sleep 8"]);
        assert!(
            output_within(stalls, Duration::from_secs(1)).is_none(),
            "a stalled child is reported, not waited for"
        );
        assert!(
            started.elapsed() < Duration::from_secs(14),
            "output_within waited for a grandchild's pipe: {:?}",
            started.elapsed()
        );
    }

    /// Control for every scanner kind: a value planted in a file, an argv, an
    /// environment block and an open descriptor name must be found by the very
    /// functions the journey test relies on.
    #[test]
    fn control_the_scanners_find_a_planted_value_in_each_surface_kind() {
        let synth = synthetic();
        let dir = tempfile::tempdir().expect("tempdir");
        let planted = dir.path().join(format!("held-{}", synth.1));
        std::fs::write(&planted, &synth.0).expect("plant file");

        // `sh` holds the planted file open on fd 3, carries the value in argv and in
        // its environment, and stays alive long enough to be scanned.
        let mut holder = std::process::Command::new("sh")
            .args(["-c", "exec 3<\"$1\"; sleep 20", "sh"])
            .arg(&planted)
            .arg(&synth.0)
            .env_clear()
            .env("J84_CONTROL", &synth.0)
            .spawn()
            .expect("spawn holder");
        std::thread::sleep(Duration::from_millis(500));

        let mut surfaces = process_surfaces("holder", holder.id());
        surfaces.push(Surface {
            name: "tree:planted".into(),
            bytes: tree_bytes(dir.path()),
        });
        let hits = leaking(&surfaces, &synth);
        let _ = holder.kill();
        let _ = holder.wait();
        for must_flag in ["ps_eww:holder", "lsof:holder", "tree:planted"] {
            assert!(hits.contains_key(must_flag), "scanner missed {must_flag}: {hits:?}");
        }
    }

    /// (d) heap-visible surface. Needs an `lldb` that may attach to a same-uid
    /// process (Developer Tools enabled), so it is opt-in:
    /// `cargo nextest run ... --run-ignored only`.
    ///
    /// The agent's heap must not hold the credential. The proxy's heap must: it
    /// injects the value, so a count of zero would mean the scanner cannot see
    /// memory (the positive control). That a same-uid debugger can read the
    /// proxy's heap on macOS is the documented boundary (ADR 0038), not a defect
    /// this test hides; the supervisor's heap is reported, not asserted.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs an lldb that may attach to a same-uid process"]
    async fn memory_scan_agent_heap_is_clean_and_the_proxy_heap_is_the_positive_control() -> anyhow::Result<()> {
        let mut j = Journey::start(Mode::Brokered).await?;
        j.wait_ready();
        assert_eq!(j.status(1), "200");

        let agent = scanned_enough("agent", memory_counts(j.agent_pid(), &j.synth));
        let proxy = scanned_enough("proxy", memory_counts(j.launch_proxy_pid(), &j.synth));
        let supervisor = memory_counts(j.child.id(), &j.synth);
        println!("J84-EVIDENCE memory: agent={agent:?} proxy={proxy:?} supervisor={supervisor:?}");
        assert_eq!(agent.counts, (0, 0), "the agent's writable memory holds the credential");
        assert!(
            proxy.counts.0 > 0,
            "the proxy injects the credential, so its heap must hold it; zero means the scanner is blind"
        );
        let _ = j.finish();
        Ok(())
    }

    /// Control for the memory scan: the same agent, the same scanner, but with the
    /// credential ambient (no broker). Only the input differs, so the agent heap
    /// must now be flagged -- the scan can see an agent's memory.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs an lldb that may attach to a same-uid process"]
    async fn memory_scan_control_an_ambient_credential_is_found_in_the_agent_heap() -> anyhow::Result<()> {
        let mut j = Journey::start(Mode::AmbientLeak).await?;
        j.wait_ready();
        let agent = scanned_enough("agent", memory_counts(j.agent_pid(), &j.synth));
        println!("J84-EVIDENCE memory-control: agent={agent:?}");
        assert!(
            agent.counts.0 > 0,
            "the scanner cannot see an agent's memory: {agent:?}"
        );
        let _ = j.finish();
        Ok(())
    }
}
