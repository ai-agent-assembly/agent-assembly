//! AAASM-6259 (PR4) - the governed lease gate wired into the real `aa-runtime`
//! binary.
//!
//! Every test here launches the actual `aa-runtime` executable (so startup
//! refusal is an observable exit status, not a returned `Result`), talks to it
//! over its real IPC socket with the real handshake, and counts what reaches a
//! fake gateway. In-process `run()` is not used: it installs a process-global
//! metrics recorder and so cannot be started twice in one test binary.
//!
//! The forbidden side effect on every deny is "the gateway was asked": each
//! test that asserts a deny also asserts the gateway counter did not move, and
//! has a permit in the same run so a counter stuck at zero cannot pass.
//!
//! Removed from the crates.io build with the gate by `.ci/strip-for-publish.sh`.
#![cfg(unix)]

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::ipc::v1::HandshakeProof;
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use aa_proto::assembly::policy::v1::{
    ActionContext, BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
    OpControlSubscribeRequest, ToolCallContext,
};
use aa_runtime::lease::state::{init_run, load, revoke_ids, LeaseState};
use ed25519_dalek::Signer;
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const REFUSED: i32 = 78;

/// Log lines the runtime emits as it brings subsystems up. A refusal must be
/// decided before any of them, which is what "nothing was bound" means here.
const STARTUP_MARKERS: [&str; 3] = [
    "aa-runtime starting",
    "IPC server task spawned",
    "health server task spawned",
];
const GATEWAY_ALLOW: &str = "gateway-allow";
const LEASE_DENY: &str = "capability lease required";

// ---------------------------------------------------------------- gateway --

struct CountingGateway(Arc<AtomicUsize>);

#[tonic::async_trait]
impl PolicyService for CountingGateway {
    async fn check_action(&self, _r: Request<CheckActionRequest>) -> Result<Response<CheckActionResponse>, Status> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(CheckActionResponse {
            decision: Decision::Allow as i32,
            reason: GATEWAY_ALLOW.to_string(),
            ..Default::default()
        }))
    }
    async fn batch_check(&self, _r: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    type OpControlStreamStream = std::pin::Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send>>;
    async fn op_control_stream(
        &self,
        _r: Request<OpControlSubscribeRequest>,
    ) -> Result<Response<Self::OpControlStreamStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

async fn start_gateway() -> (SocketAddr, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    let c = calls.clone();
    tokio::spawn(async move {
        Server::builder()
            .add_service(PolicyServiceServer::new(CountingGateway(c)))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("mock gateway serve");
    });
    (addr, calls)
}

// -------------------------------------------------------------------- rig --

static COUNTER: AtomicU32 = AtomicU32::new(0);

const BASE_TOOLS: &str = "tools:\n  calc: { allow: true, capabilities: [none] }\n  \
     reader: { allow: true, capabilities: [filesystem_read] }\n  \
     writer: { allow: true, capabilities: [filesystem_write] }\n  \
     both: { allow: true, capabilities: [filesystem_read, filesystem_write] }\n  \
     denied: { allow: false, capabilities: [none] }\n";

fn policy_yaml(lease_lines: &str) -> String {
    format!("{BASE_TOOLS}authority:\n  leases:\n{lease_lines}")
}

fn read_lease(ttl: u64) -> String {
    format!("    - domain: filesystem_read\n      scope: whole\n      ttl_seconds: {ttl}\n      reason: test\n")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// A temp directory (mode 0700, as the state loader requires), one agent id,
/// a policy and its lease state record.
#[derive(Clone)]
struct Rig {
    dir: Arc<tempfile::TempDir>,
    agent: String,
    policy: PathBuf,
    state: PathBuf,
    digest: String,
}

impl Rig {
    fn new(yaml: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir_real = dir.path().canonicalize().unwrap();
        let policy = dir_real.join("policy.yaml");
        std::fs::write(&policy, yaml).unwrap();
        let resolution = aa_policy::resolve::load(&policy);
        let digest = resolution
            .content_digest()
            .map(|d| d.strip_prefix("sha256:").unwrap().to_string())
            .unwrap_or_else(|| "0".repeat(64));
        Self {
            agent: format!("lw-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)),
            state: dir_real.join("lease.json"),
            policy,
            digest,
            dir: Arc::new(dir),
        }
    }

    fn init(&self) -> LeaseState {
        init_run(&self.state, &self.agent, &self.digest, now_secs(), false).expect("init lease state")
    }

    fn socket(&self) -> PathBuf {
        PathBuf::from(format!("/tmp/aa-runtime-{}.sock", self.agent))
    }

    fn command(&self, gateway: Option<SocketAddr>, port: u16) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_aa-runtime"));
        c.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("AA_AGENT_ID", &self.agent)
            .env("AA_POLICY_PATH", "")
            .env("AA_METRICS_ADDR", format!("127.0.0.1:{port}"))
            .env("AA_AUDIT_BUFFER_PATH", self.dir.path().join("audit.db"))
            .env("RUST_LOG", "info")
            .env("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "3");
        if let Some(g) = gateway {
            c.env("AA_GATEWAY_ENDPOINT", format!("http://{g}"));
        }
        c
    }

    fn governed(&self, gateway: SocketAddr) -> Runtime {
        let rig = self.clone();
        Runtime::spawn(
            move |port| {
                let mut c = rig.command(Some(gateway), port);
                c.env("AA_LEASE_POLICY", &rig.policy).env("AA_LEASE_STATE", &rig.state);
                c
            },
            self,
        )
    }
}

struct Runtime {
    child: Child,
    agent: String,
    port: u16,
    socket: PathBuf,
    build: Box<dyn Fn(u16) -> Command + Send + Sync>,
    log: PathBuf,
}

/// Seconds of cold-start allowance the permit windows below are sized against.
fn warm_up_binary() {
    // A freshly built, never-launched binary can take minutes to validate on
    // macOS. Pay that once, here, so it cannot land inside a timed window.
    static WARM: std::sync::Once = std::sync::Once::new();
    WARM.call_once(|| {
        let _ = Command::new(env!("CARGO_BIN_EXE_aa-runtime")).arg("--version").output();
    });
}

impl Runtime {
    fn spawn(build: impl Fn(u16) -> Command + Send + Sync + 'static, rig: &Rig) -> Self {
        warm_up_binary();
        let log = rig.dir.path().join("runtime.log");
        let build: Box<dyn Fn(u16) -> Command + Send + Sync> = Box::new(build);
        let (child, port) = Self::launch(&*build, rig.socket(), &log);
        Self {
            child,
            agent: rig.agent.clone(),
            port,
            socket: rig.socket(),
            build,
            log,
        }
    }

    fn launch(build: &dyn Fn(u16) -> Command, socket: PathBuf, log: &Path) -> (Child, u16) {
        let port = free_port();
        let _ = std::fs::remove_file(socket);
        let out = std::fs::File::create(log).unwrap();
        let child = build(port)
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .expect("spawn aa-runtime");
        (child, port)
    }

    async fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut relaunches = 0;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                // `free_port` can lose a race for the port between probing and
                // binding. That one failure is retried; any other early exit is real.
                let text = std::fs::read_to_string(&self.log).unwrap_or_default();
                assert!(
                    relaunches < 3 && text.contains("failed to bind health server"),
                    "runtime exited early with {status}:\n{text}"
                );
                relaunches += 1;
                let (child, port) = Self::launch(&*self.build, self.socket.clone(), &self.log);
                self.child = child;
                self.port = port;
                continue;
            }
            // The IPC socket appears before the health server is spawned, and the
            // health port is held (so a bare TCP connect succeeds) from before
            // either (AAASM-6383); wait for a real `/health` answer.
            if self.socket.exists() && UnixStream::connect(&self.socket).await.is_ok() && self.health_answers() {
                return;
            }
            assert!(Instant::now() < deadline, "runtime never became ready");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// `/health` answers 200 (not merely accepts a connection).
    fn health_answers(&self) -> bool {
        use std::io::{Read, Write};
        let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", self.port)) else {
            return false;
        };
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = s.write_all(b"GET /health HTTP/1.0\r\nHost: x\r\n\r\n");
        let mut head = String::new();
        let _ = s.read_to_string(&mut head);
        head.starts_with("HTTP/1.0 200") || head.starts_with("HTTP/1.1 200")
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    async fn connect(&self) -> UnixStream {
        let mut s = UnixStream::connect(&self.socket).await.expect("connect ipc");
        let tag = s.read_u8().await.unwrap();
        assert_eq!(tag, 5, "expected handshake challenge");
        let len = read_varint(&mut s).await;
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf).await.unwrap();
        let nonce = aa_proto::assembly::ipc::v1::HandshakeChallenge::decode(buf.as_ref())
            .unwrap()
            .nonce;
        // Handshake key derives from the *server's* agent id; SDK-asserted ids
        // in requests are a separate, untrusted field.
        let seed: [u8; 32] = Sha256::digest(self.agent.as_bytes()).into();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let proof = HandshakeProof {
            agent_did: format!("did:key:{}", self.agent),
            public_key: hex::encode(sk.verifying_key().to_bytes()),
            signature: sk.sign(&nonce).to_bytes().to_vec(),
            sdk_version: String::new(),
        };
        write_frame(&mut s, 5, &proof.encode_to_vec()).await;
        s
    }

    /// One policy query on a fresh connection.
    async fn ask(&self, req: CheckActionRequest) -> CheckActionResponse {
        let mut s = self.connect().await;
        write_frame(&mut s, 1, &req.encode_to_vec()).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let tag = s.read_u8().await.expect("response tag");
                let len = read_varint(&mut s).await;
                let mut buf = vec![0u8; len];
                s.read_exact(&mut buf).await.unwrap();
                if tag == 1 {
                    return CheckActionResponse::decode(buf.as_ref()).unwrap();
                }
            }
        })
        .await
        .expect("no policy response")
    }

    async fn tool(&self, name: &str) -> CheckActionResponse {
        self.ask(tool_call(name)).await
    }

    fn health(&self) -> serde_json::Value {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(("127.0.0.1", self.port)).expect("health connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET /health HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
        let mut body = String::new();
        s.read_to_string(&mut body).unwrap();
        serde_json::from_str(body.split("\r\n\r\n").nth(1).expect("http body")).expect("health json")
    }

    fn lease_governance(&self) -> Option<serde_json::Value> {
        self.health().get("lease_governance").cloned()
    }

    /// Block until `/health` shows `generation` (the acknowledgement
    /// `aasm lease revoke --wait-health` waits for).
    async fn wait_generation(&self, generation: u64) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let g = self
                .lease_governance()
                .expect("governed runtime reports lease_governance");
            if g["generation"].as_u64() >= Some(generation) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "runtime never reached generation {generation}: {g}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn stop(&mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

async fn read_varint(s: &mut UnixStream) -> usize {
    let (mut v, mut shift) = (0u64, 0u32);
    loop {
        let b = s.read_u8().await.unwrap();
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return v as usize;
        }
        shift += 7;
    }
}

async fn write_frame(s: &mut UnixStream, tag: u8, payload: &[u8]) {
    let mut out = vec![tag];
    let mut n = payload.len() as u64;
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
    out.extend_from_slice(payload);
    s.write_all(&out).await.unwrap();
    s.flush().await.unwrap();
}

fn tool_call(name: &str) -> CheckActionRequest {
    CheckActionRequest {
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: name.to_string(),
                ..Default::default()
            })),
        }),
        ..Default::default()
    }
}

fn permitted(r: &CheckActionResponse) -> bool {
    r.decision == Decision::Allow as i32 && r.reason == GATEWAY_ALLOW
}

fn lease_denied(r: &CheckActionResponse) -> bool {
    r.decision == Decision::Deny as i32 && r.reason == LEASE_DENY
}

fn lease_id(state: &LeaseState, domain: &str) -> String {
    state.lease_id(domain).unwrap()
}

// ----------------------------------------------------------------- tests --

#[tokio::test]
async fn a_valid_lease_permits_and_the_gateway_is_still_consulted() {
    let (gw, calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    let _state = rig.init();
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;
    // The runtime's own log shows startup ordering markers (control for the
    // refusal test's "none of these before a refusal" assertion).
    for marker in STARTUP_MARKERS {
        assert!(
            rt.log_text().contains(marker),
            "control: {marker:?} missing from a normal start"
        );
    }

    assert!(permitted(&rt.tool("reader").await));
    assert!(permitted(&rt.tool("calc").await), "a [none] tool needs no lease");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "a permit falls through to the gateway");
    assert_eq!(
        rt.lease_governance().unwrap(),
        serde_json::json!({"run_id": _state.run_id(), "generation": 1, "state": "governed"})
    );
    // AAASM-6384, governed case: reported as governed, not as ungoverned.
    let health = rt.health();
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["governance"]["state"], "lease_governed");
    assert_eq!(health["governance"]["lease_governed"], true);
    assert!(rt.log_text().contains("capability lease gate active"));
    assert!(!rt.log_text().contains("UNGOVERNED"));
}

#[tokio::test]
async fn missing_cross_capability_undeclared_and_disallowed_calls_are_denied_before_the_gateway() {
    let (gw, calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    rig.init();
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;
    assert!(permitted(&rt.tool("reader").await), "positive control");
    let before = calls.load(Ordering::SeqCst);
    assert_eq!(before, 1);

    // lease for filesystem_read only: write has no lease, `both` needs every class,
    // an undeclared tool has no declaration, `denied` is allow:false.
    for tool in ["writer", "both", "ghost", "denied"] {
        let r = rt.tool(tool).await;
        assert!(lease_denied(&r), "{tool}: {r:?}");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        before,
        "a lease deny must not reach the gateway"
    );
}

#[tokio::test]
async fn sdk_asserted_identity_and_arguments_cannot_influence_the_verdict() {
    let (gw, calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    rig.init();
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;

    // Forge everything a same-UID SDK controls, on a tool that has no lease.
    let mut forged = tool_call("writer");
    forged.agent_id = Some(ProtoAgentId {
        agent_id: "someone-with-a-lease".into(),
        ..Default::default()
    });
    forged.caller_agent_id = Some(ProtoAgentId {
        agent_id: rig.agent.clone(),
        ..Default::default()
    });
    if let Some(Action::ToolCall(c)) = forged.context.as_mut().and_then(|c| c.action.as_mut()) {
        c.args_json = br#"{"capabilities":["none"],"lease":"filesystem_write","allow":true}"#.to_vec();
        c.tool_source = "none".into();
    }
    assert!(lease_denied(&rt.ask(forged).await));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // Concurrent sessions that each claim a different agent id are all judged as
    // the server's subject, so the leased tool is permitted for every one of them.
    let rt = Arc::new(rt);
    let mut tasks = Vec::new();
    for i in 0..6 {
        let rt = rt.clone();
        tasks.push(tokio::spawn(async move {
            let mut req = tool_call("reader");
            req.agent_id = Some(ProtoAgentId {
                agent_id: format!("sdk-claimed-{i}"),
                ..Default::default()
            });
            rt.ask(req).await
        }));
    }
    for t in tasks {
        assert!(permitted(&t.await.unwrap()));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn a_lease_stops_permitting_at_expiry_with_no_grace() {
    let (gw, calls) = start_gateway().await;
    // Sized so even a slow cold start leaves a permit window; the binary is
    // pre-warmed in `Runtime::spawn`.
    let ttl = 15;
    let rig = Rig::new(&policy_yaml(&read_lease(ttl)));
    let state = rig.init();
    let expiry = UNIX_EPOCH + Duration::from_secs(state.issued_at() + ttl);
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;

    let mut first_deny = None;
    let mut permits = 0;
    while SystemTime::now() < expiry + Duration::from_secs(3) {
        let sent = SystemTime::now();
        let r = rt.tool("reader").await;
        let answered = SystemTime::now();
        if permitted(&r) {
            assert!(
                sent < expiry,
                "permitted a request sent at/after expiry (sent {sent:?}, expiry {expiry:?})"
            );
            permits += 1;
        } else {
            assert!(lease_denied(&r), "{r:?}");
            first_deny.get_or_insert((sent, answered));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        permits > 0,
        "never permitted before expiry (startup slower than the ttl?)"
    );
    let (sent, _) = first_deny.expect("lease never expired");
    // Whole-second issuance means a request sent at/after the expiry instant must
    // deny; allow the poll cadence plus IPC latency as the only slack.
    assert!(
        sent >= expiry - Duration::from_millis(500),
        "denied long before expiry: {sent:?} vs {expiry:?}"
    );
    assert!(
        sent <= expiry + Duration::from_millis(1500),
        "still permitting well past expiry (grace?): first deny sent {sent:?}, expiry {expiry:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), permits, "denies reached the gateway");
}

/// Lease windows count from the record's `issued_at` (the `aasm lease init`
/// time), not from when the runtime started: a restart must not refresh them.
#[tokio::test]
async fn the_ttl_counts_from_the_record_not_from_runtime_start() {
    let (gw, calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(60)));
    init_run(&rig.state, &rig.agent, &rig.digest, now_secs() - 100, false).unwrap();
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;
    assert!(permitted(&rt.tool("calc").await), "positive control");
    assert!(
        lease_denied(&rt.tool("reader").await),
        "a lease issued 100s ago with a 60s ttl is expired"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn revocation_denies_on_the_next_check_and_survives_a_restart() {
    let (gw, calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    let state = rig.init();
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;
    assert!(permitted(&rt.tool("reader").await));

    let revoked = revoke_ids(&rig.state, &[lease_id(&state, "filesystem_read")]).unwrap();
    rt.wait_generation(revoked.generation()).await;

    let before = calls.load(Ordering::SeqCst);
    assert!(lease_denied(&rt.tool("reader").await), "revoked lease must deny");
    assert!(permitted(&rt.tool("calc").await), "a lease-free tool is unaffected");
    assert_eq!(calls.load(Ordering::SeqCst), before + 1);
    assert_eq!(rt.lease_governance().unwrap()["generation"], 2);

    // Restart on the same record: revocation persists, nothing is re-granted.
    rt.stop();
    let mut rt2 = rig.governed(gw);
    rt2.wait_ready().await;
    assert_eq!(rt2.lease_governance().unwrap()["generation"], 2);
    assert!(lease_denied(&rt2.tool("reader").await), "restart must not re-grant");
    assert!(permitted(&rt2.tool("calc").await));
}

#[tokio::test]
async fn live_corruption_or_deletion_denies_everything_and_never_heals() {
    let (gw, calls) = start_gateway().await;
    for (name, damage) in [
        (
            "garbage",
            Box::new(|p: &Path| std::fs::write(p, b"not json").unwrap()) as Box<dyn Fn(&Path)>,
        ),
        (
            "truncated",
            Box::new(|p: &Path| std::fs::write(p, b"{\"version\":1,\"sub").unwrap()),
        ),
        ("deleted", Box::new(|p: &Path| std::fs::remove_file(p).unwrap())),
    ] {
        let rig = Rig::new(&policy_yaml(&read_lease(3600)));
        let state = rig.init();
        let original = state.to_bytes();
        let mut rt = rig.governed(gw);
        rt.wait_ready().await;
        assert!(permitted(&rt.tool("calc").await), "{name}: positive control");
        let before = calls.load(Ordering::SeqCst);

        damage(&rig.state);
        let deadline = Instant::now() + Duration::from_secs(10);
        while rt.lease_governance().unwrap()["state"] != "denied_all" {
            assert!(Instant::now() < deadline, "{name}: never tripped");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for tool in ["calc", "reader"] {
            assert!(lease_denied(&rt.tool(tool).await), "{name}/{tool} must deny");
        }

        // Restoring the exact original record must not heal a tripped gate.
        std::fs::write(&rig.state, &original).unwrap();
        std::fs::set_permissions(&rig.state, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&rig.state).is_ok(), "{name}: restored record is valid");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(lease_denied(&rt.tool("calc").await), "{name}: healed after restore");
        assert_eq!(rt.lease_governance().unwrap()["state"], "denied_all");
        // AAASM-6384: the top level must not keep saying healthy / lease_governed
        // while every call is denied.
        let health = rt.health();
        assert_eq!(health["status"], "degraded", "{name}: {health}");
        assert_eq!(health["governance"]["state"], "denied_all", "{name}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "{name}: a deny reached the gateway"
        );
    }
}

/// Replace the record the way an operator tool would: write a sibling, then
/// rename over it, so the runtime can never read a half-written file.
fn replace_record_atomically(path: &Path, bytes: &[u8]) {
    let tmp = path.with_extension("restore.tmp");
    std::fs::write(&tmp, bytes).unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

/// A valid record for the same run with a chosen generation and revoked set.
fn crafted(base: &LeaseState, generation: u64, revoked: &[&str]) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(&base.to_bytes()).unwrap();
    v["generation"] = generation.into();
    v["revoked"] = serde_json::json!(revoked);
    let bytes = serde_json::to_vec_pretty(&v).unwrap();
    LeaseState::parse(&bytes).expect("the crafted record is itself valid");
    bytes
}

async fn assert_trips_with(rig: &Rig, rt: &Runtime, reason: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while rt.lease_governance().unwrap()["state"] != "denied_all" {
        assert!(Instant::now() < deadline, "never tripped (wanted {reason:?})");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(lease_denied(&rt.tool("reader").await));
    assert!(
        rt.log_text().contains(reason),
        "expected {reason:?} in:\n{}",
        rt.log_text()
    );
    let _ = rig;
}

#[tokio::test]
async fn a_restored_older_record_trips_the_gate() {
    let (gw, _calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    let state = rig.init();
    let original = state.to_bytes();
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;
    let revoked = revoke_ids(&rig.state, &[lease_id(&state, "filesystem_read")]).unwrap();
    rt.wait_generation(revoked.generation()).await;
    // The older, valid record back: it would re-grant the lease. It is both a
    // lower generation and a smaller revoked set; the generation check is first.
    replace_record_atomically(&rig.state, &original);
    assert_trips_with(&rig, &rt, "generation went backwards").await;
}

#[tokio::test]
async fn a_record_whose_generation_went_backwards_trips_even_with_a_larger_revoked_set() {
    let (gw, _calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    let state = rig.init();
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;
    let revoked = revoke_ids(&rig.state, &[lease_id(&state, "filesystem_read")]).unwrap();
    rt.wait_generation(revoked.generation()).await;
    // Generation 1 (was 2) but a superset of the revoked set: only the
    // generation rule can object.
    let ids = [
        lease_id(&state, "filesystem_read"),
        lease_id(&state, "filesystem_write"),
    ];
    let mut sorted = ids.clone();
    sorted.sort();
    let refs: Vec<&str> = sorted.iter().map(String::as_str).collect();
    replace_record_atomically(&rig.state, &crafted(&state, 1, &refs));
    assert_trips_with(&rig, &rt, "generation went backwards").await;
}

#[tokio::test]
async fn a_record_that_drops_a_revocation_trips_even_with_a_higher_generation() {
    let (gw, _calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    let state = rig.init();
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;
    let revoked = revoke_ids(&rig.state, &[lease_id(&state, "filesystem_read")]).unwrap();
    rt.wait_generation(revoked.generation()).await;
    // Generation 5 (was 2) with the revoked lease absent: only the shrink rule can object.
    replace_record_atomically(&rig.state, &crafted(&state, 5, &["unrelated-id"]));
    assert_trips_with(&rig, &rt, "revocation set shrank").await;
}

/// Launch with a bad setup and require: exit 78, the reason on stderr/stdout, no
/// IPC socket and nothing listening on the health port.
fn assert_refuses(rig: &Rig, configure: impl FnOnce(&mut Command), why: &str, expect_in_log: &str) {
    let port = free_port();
    let mut c = rig.command(None, port);
    configure(&mut c);
    let _ = std::fs::remove_file(rig.socket());
    let log = rig.dir.path().join("refusal.log");
    let f = std::fs::File::create(&log).unwrap();
    let mut child = c
        .stdout(Stdio::from(f.try_clone().unwrap()))
        .stderr(Stdio::from(f))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{why}: runtime kept running instead of refusing");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(status.code(), Some(REFUSED), "{why}: {text}");
    assert!(
        text.contains(expect_in_log),
        "{why}: expected {expect_in_log:?} in:\n{text}"
    );
    // Falsifiable form of "nothing was bound": the refusal is logged and none of
    // the lines a subsystem start-up emits precede it, so it was decided before
    // any listener could have been created (not merely cleaned up afterwards).
    assert!(text.contains("refused to start"), "{why}: no refusal line in:\n{text}");
    for marker in STARTUP_MARKERS {
        assert!(
            !text.contains(marker),
            "{why}: {marker:?} logged before the refusal:\n{text}"
        );
    }
    assert!(!rig.socket().exists(), "{why}: an IPC socket was created");
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
        "{why}: the health port is listening"
    );
}

fn governed_env(rig: &Rig) -> impl FnOnce(&mut Command) + '_ {
    move |c| {
        c.env("AA_LEASE_POLICY", &rig.policy).env("AA_LEASE_STATE", &rig.state);
    }
}

#[test]
fn startup_refuses_on_every_unsatisfiable_governed_setup() {
    // Missing record: never auto-created.
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    assert_refuses(&rig, governed_env(&rig), "missing state", "not found");
    assert!(!rig.state.exists(), "a missing record was created");

    // Corrupt: garbage, truncated, wrong version.
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    let good = rig.init().to_bytes();
    for (why, bytes) in [
        ("garbage", b"garbage".to_vec()),
        ("truncated", good[..good.len() / 2].to_vec()),
        ("empty", Vec::new()),
    ] {
        std::fs::write(&rig.state, bytes).unwrap();
        assert_refuses(&rig, governed_env(&rig), why, "corrupt");
    }
    std::fs::write(
        &rig.state,
        String::from_utf8(good.clone())
            .unwrap()
            .replace("\"version\": 1", "\"version\": 9"),
    )
    .unwrap();
    assert_refuses(&rig, governed_env(&rig), "unsupported version", "not supported");

    // Subject differs from the server agent id.
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    init_run(&rig.state, "some-other-agent", &rig.digest, now_secs(), false).unwrap();
    assert_refuses(&rig, governed_env(&rig), "subject mismatch", "subject differs");

    // Policy digest differs: the record is for another policy. The message names
    // the digest to pass to `aasm lease init`.
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    init_run(&rig.state, &rig.agent, &"ab".repeat(32), now_secs(), false).unwrap();
    assert_refuses(&rig, governed_env(&rig), "digest mismatch", &rig.digest.clone());

    // Digest binding survives a policy edit after init.
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    rig.init();
    std::fs::write(&rig.policy, policy_yaml(&read_lease(7200))).unwrap();
    assert_refuses(&rig, governed_env(&rig), "edited policy", "policy digest differs");

    // AA_LEASE_STATE unset.
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    assert_refuses(
        &rig,
        |c| {
            c.env("AA_LEASE_POLICY", &rig.policy);
        },
        "no state path",
        "AA_LEASE_STATE is not set",
    );

    // AA_LEASE_POLICY set but empty is "requested", not "disabled".
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    assert_refuses(
        &rig,
        |c| {
            c.env("AA_LEASE_POLICY", "").env("AA_LEASE_STATE", &rig.state);
        },
        "empty policy var",
        "governed lease mode",
    );

    // Policy cannot load.
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    rig.init();
    std::fs::remove_file(&rig.policy).unwrap();
    assert_refuses(&rig, governed_env(&rig), "policy missing", "enforced policy");
    std::fs::write(&rig.policy, "tools: [this is not: a policy").unwrap();
    assert_refuses(&rig, governed_env(&rig), "policy unparsable", "enforced policy");

    // Policy resolves but enforces nothing.
    let rig = Rig::new("tools: {}\n");
    rig.init();
    assert_refuses(&rig, governed_env(&rig), "empty policy", "enforced policy");

    // A lease the gate cannot honour: `max_count` is refused at startup.
    let rig = Rig::new(&policy_yaml(
        "    - domain: filesystem_read\n      scope: whole\n      max_count: 1\n      reason: t\n",
    ));
    rig.init();
    assert_refuses(&rig, governed_env(&rig), "max_count", "governed lease mode");
}

/// `process_creation` and `syscall` leases are *not* a startup refusal (the
/// lowering accepts them); the decision refuses every tool that declares them,
/// because an admission check cannot bound a class that subsumes the others.
#[tokio::test]
async fn tools_declaring_process_creation_or_syscall_are_denied_even_with_a_matching_lease() {
    let (gw, calls) = start_gateway().await;
    let yaml = "tools:\n  calc: { allow: true, capabilities: [none] }\n  \
         spawner: { allow: true, capabilities: [process_creation] }\n  \
         raw: { allow: true, capabilities: [syscall] }\n\
         authority:\n  leases:\n    - domain: process_creation\n      scope: whole\n      reason: t\n    \
         - domain: syscall\n      scope: whole\n      reason: t\n";
    let rig = Rig::new(yaml);
    rig.init();
    let mut rt = rig.governed(gw);
    rt.wait_ready().await;
    assert!(permitted(&rt.tool("calc").await), "positive control");
    for tool in ["spawner", "raw"] {
        assert!(lease_denied(&rt.tool(tool).await), "{tool}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn without_aa_lease_policy_the_runtime_is_ungoverned_whatever_else_is_present() {
    let (gw, calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    rig.init();
    // A state record exists and AA_LEASE_STATE is set, but only AA_LEASE_POLICY
    // may switch governed mode on.
    let r = rig.clone();
    let mut rt = Runtime::spawn(
        move |port| {
            let mut c = r.command(Some(gw), port);
            c.env("AA_LEASE_STATE", &r.state);
            c
        },
        &rig,
    );
    rt.wait_ready().await;

    // No lease for `writer`, an undeclared tool, a forged agent: all reach the gateway.
    for tool in ["writer", "ghost", "reader"] {
        assert!(permitted(&rt.tool(tool).await), "{tool}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(
        rt.lease_governance().is_none(),
        "ungoverned /health must not grow a lease field"
    );
}

/// AAASM-6383: a governed runtime is identifiable by its lease `run_id`, which
/// makes "the second runtime did not take over" observable on `/health` itself
/// rather than inferred from process state. Both collisions are tried against
/// the one governed instance: its health port, and its agent id's socket path.
#[tokio::test]
async fn a_second_runtime_cannot_displace_a_governed_one_on_its_port_or_its_socket() {
    let (gw, _calls) = start_gateway().await;
    let rig = Rig::new(&policy_yaml(&read_lease(3600)));
    let state = rig.init();
    let mut first = rig.governed(gw);
    first.wait_ready().await;
    let identity = serde_json::json!({"run_id": state.run_id(), "generation": 1, "state": "governed"});
    assert_eq!(
        first.lease_governance().unwrap(),
        identity,
        "control: first runtime identity"
    );

    let refused = |mut c: Command| {
        let out = c.output().expect("spawn second aa-runtime");
        let text = String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(REFUSED),
            "second runtime must be refused:\n{text}"
        );
    };
    // Same health port, different agent id.
    let mut other_agent = rig.command(Some(gw), first.port);
    other_agent
        .env("AA_AGENT_ID", format!("{}-b", rig.agent))
        .env("AA_LEASE_POLICY", &rig.policy)
        .env("AA_LEASE_STATE", &rig.state);
    refused(other_agent);
    // Same agent id (same socket path), different health port.
    let mut same_agent = rig.command(Some(gw), free_port());
    same_agent
        .env("AA_LEASE_POLICY", &rig.policy)
        .env("AA_LEASE_STATE", &rig.state);
    refused(same_agent);

    assert_eq!(
        first.lease_governance().unwrap(),
        identity,
        "/health must still answer as the first runtime"
    );
    assert!(
        permitted(&first.tool("reader").await),
        "the first runtime still serves IPC"
    );
}
