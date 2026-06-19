//! AAASM-3430 — runtime→gateway per-tool deny enforcement E2E.
//!
//! Regression guard for the bug where `aa-runtime` ignored its configured
//! `AA_GATEWAY_ENDPOINT` and evaluated every policy check locally (always
//! allowing), so a per-tool `deny` held by the gateway never fired end-to-end
//! (the AAASM-3407 symptom: `delete_file` returned ALLOW through the real
//! SDK→runtime→gateway chain).
//!
//! The loss point was `aa-runtime::runtime::run`, which passed `None` for the
//! pipeline's gateway client unconditionally. The fix constructs a
//! `GatewayClient` from the configured endpoint so checks are forwarded to the
//! authoritative gateway.
//!
//! This test spawns a real `aa-gateway` (with a section-based tool-deny policy)
//! and a real `aa-runtime` configured to forward to it, then sends two
//! `CheckActionRequest`s over the runtime's Unix-socket IPC — exactly the wire
//! the SDK uses — and asserts the gateway's per-tool decision is honoured:
//! `read_file` → Allow, `delete_file` → Deny.
//!
//! It skips cleanly when the `aa-gateway` / `aa-runtime` binaries are not built,
//! mirroring the existing `e2e_sdk_node` pattern, so a single-crate test run
//! without a prior workspace build does not fail.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use aa_proto::assembly::common::v1::{ActionType, AgentId, Decision};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, CheckActionResponse, ToolCallContext};
use common::live_gateway::{gateway_binary_locatable, LiveGateway};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Section-based policy: deny the `delete_file` tool, allow `read_file`.
/// Tool deny is keyed by tool name and is agent-independent, so the check
/// fires for an unregistered agent (the gateway skips credential validation
/// for agents it has never seen).
const TOOL_DENY_POLICY: &str = "\
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: aaasm-3430-tool-deny
  version: \"0.1.0\"
spec:
  tools:
    read_file:
      allow: true
    delete_file:
      allow: false
";

/// Inbound IPC tag for a policy query (SDK → runtime). Mirrors
/// `aa-runtime::ipc::codec::TAG_POLICY_QUERY`.
const TAG_POLICY_QUERY: u8 = 1;
/// Outbound IPC tag for a policy response (runtime → SDK). Mirrors
/// `aa-runtime::ipc::codec::TAG_POLICY_RESPONSE`.
const TAG_POLICY_RESPONSE: u8 = 1;

/// Locate the `aa-runtime` binary the same way `live_gateway` finds the gateway.
fn locate_runtime_binary() -> Option<PathBuf> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let workspace_root = Path::new(&manifest).parent()?;
    for profile in ["debug", "release"] {
        let candidate = workspace_root.join("target").join(profile).join("aa-runtime");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// A spawned `aa-runtime` sidecar pointed at a gateway endpoint. Killed on drop.
struct LiveRuntime {
    child: Option<Child>,
    socket_path: PathBuf,
    _home: tempfile::TempDir,
}

impl LiveRuntime {
    /// Spawn `aa-runtime` with `AA_GATEWAY_ENDPOINT` set so it forwards policy
    /// checks to the gateway. Policy enforcement is disabled on disk
    /// (`AA_POLICY_PATH=""`) so the only authority is the gateway — exactly the
    /// configuration that exposed the bug.
    fn spawn(binary: &Path, agent_id: &str, gateway_endpoint: &str, metrics_port: u16) -> std::io::Result<Self> {
        let home = tempfile::tempdir()?;
        let socket_path = PathBuf::from(format!("/tmp/aa-runtime-{agent_id}.sock"));
        let child = Command::new(binary)
            .env("HOME", home.path())
            .env("AA_AGENT_ID", agent_id)
            .env("AA_POLICY_PATH", "")
            .env("AA_GATEWAY_ENDPOINT", gateway_endpoint)
            .env("AA_METRICS_ADDR", format!("127.0.0.1:{metrics_port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self {
            child: Some(child),
            socket_path,
            _home: home,
        })
    }

    /// Block until the runtime's UDS accepts a connection.
    async fn await_ready(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if UnixStream::connect(&self.socket_path).await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
}

impl Drop for LiveRuntime {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Build a tool-call `CheckActionRequest` for `tool_name`.
fn tool_call_request(agent_id: &str, tool_name: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(AgentId {
            org_id: "test-org".to_string(),
            team_id: "test-team".to_string(),
            agent_id: agent_id.to_string(),
        }),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: tool_name.to_string(),
                tool_source: "function".to_string(),
                ..Default::default()
            })),
        }),
        ..Default::default()
    }
}

/// Write a varint length prefix then the payload (prost length-delimited).
async fn write_varint(stream: &mut UnixStream, mut value: u64) -> std::io::Result<()> {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            stream.write_u8(byte).await?;
            return Ok(());
        }
        stream.write_u8(byte | 0x80).await?;
    }
}

/// Read a prost-style unsigned varint.
async fn read_varint(stream: &mut UnixStream) -> std::io::Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = stream.read_u8().await?;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

/// Send one `CheckActionRequest` over the runtime UDS and return the gateway's
/// decision as relayed back in the `CheckActionResponse`.
async fn check_tool(socket_path: &Path, req: &CheckActionRequest) -> CheckActionResponse {
    let mut stream = UnixStream::connect(socket_path).await.expect("connect to runtime UDS");

    let payload = req.encode_to_vec();
    stream.write_u8(TAG_POLICY_QUERY).await.expect("write tag");
    write_varint(&mut stream, payload.len() as u64)
        .await
        .expect("write len");
    stream.write_all(&payload).await.expect("write payload");
    stream.flush().await.expect("flush");

    let tag = stream.read_u8().await.expect("read response tag");
    assert_eq!(tag, TAG_POLICY_RESPONSE, "expected a PolicyResponse frame");
    let len = read_varint(&mut stream).await.expect("read response len") as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.expect("read response payload");
    CheckActionResponse::decode(buf.as_ref()).expect("decode CheckActionResponse")
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_forwards_per_tool_deny_to_gateway() {
    let Some(runtime_bin) = locate_runtime_binary() else {
        eprintln!("skipping: aa-runtime binary not built — run `cargo build -p aa-runtime`");
        return;
    };
    if !gateway_binary_locatable() {
        eprintln!("skipping: aa-gateway binary not built — run `cargo build -p aa-gateway`");
        return;
    }

    // Real gateway holding the per-tool deny policy.
    let gateway = LiveGateway::spawn_with_policy(TOOL_DENY_POLICY).expect("spawn aa-gateway");
    let endpoint = format!("http://{}", gateway.addr());

    // Real runtime, configured to forward checks to that gateway.
    let agent_id = format!("aaasm3430-{}", std::process::id());
    let metrics_port = portpicker::pick_unused_port().expect("free metrics port");
    let runtime = LiveRuntime::spawn(&runtime_bin, &agent_id, &endpoint, metrics_port).expect("spawn aa-runtime");
    assert!(
        runtime.await_ready(Duration::from_secs(30)).await,
        "aa-runtime did not bind its UDS in time"
    );

    // Allow path: the gateway permits `read_file`.
    let allow = check_tool(&runtime.socket_path, &tool_call_request(&agent_id, "read_file")).await;
    assert_eq!(
        allow.decision,
        Decision::Allow as i32,
        "read_file must be ALLOWED end-to-end (got reason: {})",
        allow.reason
    );

    // Deny path (the regression): the gateway denies `delete_file`, and the
    // runtime MUST forward the check and relay the Deny — not short-circuit to
    // a local allow.
    let deny = check_tool(&runtime.socket_path, &tool_call_request(&agent_id, "delete_file")).await;
    assert_eq!(
        deny.decision,
        Decision::Deny as i32,
        "delete_file must be DENIED end-to-end via the gateway — a local allow \
         here is the AAASM-3430 regression (got reason: {})",
        deny.reason
    );
}
