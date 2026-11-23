//! AAASM-6261: a launch grant reaches a real `aa-proxy` process only through its
//! stdin pipe, and the process starts governed from it.
//!
//! The grant must not be readable the way a same-user process reads another
//! process's environment: `ps -Eww` on macOS and `/proc/<pid>/environ` and
//! `cmdline` on Linux. This test starts the real `aa-proxy` binary, delivers the
//! grant on stdin exactly as `aasm run` does, waits for readiness, and asserts the
//! grant appears in neither the environment nor the argv.
//!
//! What it does not do: it does not scan the proxy's memory (the grant is held in
//! a zeroizing, `mlock`ed buffer, and a same-user debugger can still read it), and
//! it does not run `aasm run` end to end. That the registration token never
//! reaches the proxy is therefore NOT observed here: it rests on the types
//! (`ProxyGuardOptions` carries a `LaunchGrant`, and the token is private to
//! `run_registration`), and this test does not test it.

#[path = "grpc_gateway_support/mod.rs"]
mod grpc_gateway_support;
#[path = "proxy_trust_support/mod.rs"]
mod proxy_trust_support;

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use aa_proxy::credentials::LaunchGrant;

const GRANT: &str = "grant-QA6261-process-test-synthetic";

/// Everything another process of this user can read about `pid`'s launch inputs.
fn visible_launch_inputs(pid: u32) -> String {
    if cfg!(target_os = "macos") {
        let out = Command::new("ps")
            .args(["-Eww", "-o", "command=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout).into_owned()
    } else {
        let env = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
        let args = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        format!("{}\n{}", String::from_utf8_lossy(&env), String::from_utf8_lossy(&args))
    }
}

#[test]
fn the_grant_reaches_a_real_proxy_on_stdin_and_is_not_in_its_environment_or_argv() {
    let bin = proxy_trust_support::aa_proxy_binary();
    let work = tempfile::tempdir().unwrap();
    let ready_file = work.path().join("ready");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let gateway = runtime
        .block_on(grpc_gateway_support::GrpcGateway::start_with_policy())
        .expect("start a gateway for the governed proxy to reach");

    let mut cmd = Command::new(&bin);
    cmd.env("AA_PROXY_ADDR", "127.0.0.1:0")
        .env("AA_PROXY_READY_FILE", &ready_file)
        .env("AA_CA_DIR", work.path().join("ca"))
        .env("AA_PROXY_SYSTEM_TRUST_INSTALL", "never")
        .env("AA_PROXY_LAUNCH_GRANT_STDIN", "1")
        // A governed proxy needs a reachable gateway and ignores the fail-open knobs (AAASM-6483),
        // so it is given a real one. The test is about what the grant is visible in, not about
        // enforcement; the gateway only has to be there.
        .env("AA_PROXY_GATEWAY_ENDPOINT", gateway.endpoint())
        .env_remove("AA_PROXY_PROVIDER_KEYS")
        .env_remove("AA_PROXY_PROVIDER_KEYS_STDIN")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(work.path().join("proxy.stderr")).unwrap());
    let mut child = cmd.spawn().expect("spawn the real aa-proxy");

    let grant = LaunchGrant::new(String::new(), "team-a".into(), "did:key:agent-a".into(), GRANT.into());
    {
        let mut stdin = child.stdin.take().expect("stdin pipe");
        stdin.write_all(&grant.encode_line().unwrap()).unwrap();
        stdin.write_all(b"\n").unwrap();
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let addr = loop {
        if let Some(first) = std::fs::read_to_string(&ready_file)
            .ok()
            .and_then(|c| c.lines().next().map(str::to_string))
        {
            if let Ok(addr) = first.parse::<SocketAddr>() {
                break addr;
            }
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "the proxy exited before it was ready: a delivered grant must not stop it starting; its stderr:\n{}",
            std::fs::read_to_string(work.path().join("proxy.stderr")).unwrap_or_default()
        );
        assert!(std::time::Instant::now() < deadline, "no readiness within 30s");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(addr.ip().is_loopback());

    let visible = visible_launch_inputs(child.id());
    // The proxy marks itself non-dumpable (`hardening::harden_process`), so on
    // Linux `/proc/<pid>/environ` is unreadable for it by design and cannot be
    // the control. The control is a dumpable witness given the same variable:
    // it proves the probe reads an environment, so the proxy's lack of the
    // grant is not just a blind probe.
    #[cfg(not(target_os = "macos"))]
    {
        let mut witness = Command::new("sleep")
            .arg("30")
            .env("AA_PROXY_LAUNCH_GRANT_STDIN", "1")
            .spawn()
            .expect("spawn witness");
        // Between fork and exec the new process's environ reads back empty, so
        // wait for the witness to be fully exec'd before treating a miss as a
        // blind probe.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut seen = visible_launch_inputs(witness.id());
        while !seen.contains("AA_PROXY_LAUNCH_GRANT_STDIN") && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
            seen = visible_launch_inputs(witness.id());
        }
        let _ = witness.kill();
        let _ = witness.wait();
        assert!(
            seen.contains("AA_PROXY_LAUNCH_GRANT_STDIN"),
            "control: the probe can read a dumpable process's environment: {seen:?}"
        );
        // Say what the proxy half can and cannot show: its environ is unreadable
        // here (non-dumpable), so only its argv is actually inspected below. The
        // environment guarantee itself rests on the stdin-delivery code path and
        // its unit tests, not on this probe.
        assert!(
            std::fs::read(format!("/proc/{}/environ", child.id()))
                .map(|b| b.is_empty())
                .unwrap_or(true),
            "the proxy's environ should be unreadable once it is hardened"
        );
    }
    #[cfg(target_os = "macos")]
    assert!(
        visible.contains("AA_PROXY_LAUNCH_GRANT_STDIN"),
        "control: the probe can see this process's environment at all: {visible:?}"
    );
    assert!(
        !visible.contains(GRANT),
        "the grant is readable from the environment or argv"
    );

    // A proxy told to expect a grant and given none must not start.
    let mut refusing = Command::new(&bin);
    refusing
        .env("AA_PROXY_ADDR", "127.0.0.1:0")
        .env("AA_CA_DIR", work.path().join("ca2"))
        .env("AA_PROXY_SYSTEM_TRUST_INSTALL", "never")
        .env("AA_PROXY_LAUNCH_GRANT_STDIN", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = refusing.status().expect("spawn");
    assert!(
        !status.success(),
        "a proxy expecting a grant that never arrived must refuse to start"
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// AAASM-6483: a grant is delivered but no gateway endpoint is configured. The proxy would
/// never connect to a gateway and so never bind a single answer to the launch's agent while
/// still reporting itself governed, so the real binary must refuse to start.
#[test]
fn a_grant_without_a_gateway_endpoint_stops_a_real_proxy_starting() {
    let bin = proxy_trust_support::aa_proxy_binary();
    let work = tempfile::tempdir().unwrap();
    let ready_file = work.path().join("ready");

    let mut cmd = Command::new(&bin);
    cmd.env("AA_PROXY_ADDR", "127.0.0.1:0")
        .env("AA_PROXY_READY_FILE", &ready_file)
        .env("AA_CA_DIR", work.path().join("ca"))
        .env("AA_PROXY_SYSTEM_TRUST_INSTALL", "never")
        .env("AA_PROXY_LAUNCH_GRANT_STDIN", "1")
        .env_remove("AA_PROXY_GATEWAY_ENDPOINT")
        .env_remove("AA_PROXY_PROVIDER_KEYS")
        .env_remove("AA_PROXY_PROVIDER_KEYS_STDIN")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("spawn the real aa-proxy");
    let grant = LaunchGrant::new(String::new(), "team-a".into(), "did:key:agent-a".into(), GRANT.into());
    {
        let mut stdin = child.stdin.take().expect("stdin pipe");
        stdin.write_all(&grant.encode_line().unwrap()).unwrap();
        stdin.write_all(b"\n").unwrap();
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the proxy neither exited nor refused within 60s"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        !status.success(),
        "a governed proxy with no gateway endpoint must refuse to start"
    );
    assert!(
        !ready_file.exists(),
        "it must refuse before it reports readiness, not after"
    );
}
