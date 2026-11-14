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
use aa_proto::assembly::ipc::v1::{HandshakeChallenge, HandshakeProof};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, CheckActionResponse, ToolCallContext};
use aa_sdk_client::AgentKeypair;
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
/// Inbound IPC tag for the signed handshake proof (SDK → runtime). Mirrors
/// `aa-runtime::ipc::codec::TAG_HANDSHAKE_PROOF` (AAASM-3585).
const TAG_HANDSHAKE_PROOF: u8 = 5;
/// Outbound IPC tag for a policy response (runtime → SDK). Mirrors
/// `aa-runtime::ipc::codec::TAG_POLICY_RESPONSE`.
const TAG_POLICY_RESPONSE: u8 = 1;
/// Outbound IPC tag for the per-session nonce challenge (runtime → SDK). Mirrors
/// `aa-runtime::ipc::codec::TAG_HANDSHAKE_CHALLENGE` (AAASM-3585).
const TAG_HANDSHAKE_CHALLENGE: u8 = 5;

/// Env var naming an explicit `aa-runtime` binary (see `AA_GATEWAY_BIN` for the gateway).
const RUNTIME_BIN_ENV: &str = "AA_RUNTIME_BIN";

/// Locate the `aa-runtime` binary the same way `live_gateway` finds the gateway.
///
/// Routes through `common::precondition::cargo_target_root()` (AAASM-5977)
/// rather than the plain `<workspace>/target` this used before: the latter
/// silently misses a binary built under this repo's shared
/// `CARGO_TARGET_DIR` convention, which made this guard always skip on a
/// dev machine and left the conversion below unverifiable locally.
fn locate_runtime_binary() -> Result<PathBuf, String> {
    // AAASM-6469: an explicit binary is authoritative so a lane can qualify the
    // exact candidate artifact; a bad path is an error, never a silent fallback.
    if let Some(explicit) = std::env::var_os(RUNTIME_BIN_ENV) {
        let explicit = PathBuf::from(explicit);
        return if explicit.is_file() {
            Ok(explicit)
        } else {
            Err(format!("{RUNTIME_BIN_ENV}={} is not a file", explicit.display()))
        };
    }
    let target_root = common::precondition::cargo_target_root();
    for profile in ["debug", "release"] {
        let candidate = target_root.join(profile).join("aa-runtime");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "aa-runtime binary not found under {} (debug or release) — run `cargo build -p aa-runtime` first",
        target_root.display()
    ))
}

/// As `common::live_gateway::gateway_binary_locatable`, but `Result`-shaped
/// for `common::precondition::require` — a thin local wrapper rather than
/// changing that shared function's signature, which `e2e_sdk_node.rs` and
/// `e2e_audit.rs` also call and which AAASM-5977 does not list.
fn gateway_binary_locatable_result() -> Result<(), String> {
    if gateway_binary_locatable() {
        Ok(())
    } else {
        Err("aa-gateway binary not found (looked in target/{debug,release} and $PATH) — run `cargo build -p aa-gateway` first".to_string())
    }
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

/// Complete the AAASM-3585 session handshake the runtime now requires before it
/// serves any application frame: read its nonce challenge, sign it with the
/// agent's deterministic Ed25519 key, and send back a `HandshakeProof`.
///
/// This mirrors exactly what the real `aa-sdk-client` does on connect (see
/// `aa-sdk-client::ipc::perform_handshake`), reusing the production
/// [`AgentKeypair`] so the proof verifies against the runtime's expected key.
/// Skipping it makes the runtime drop the connection, so the test must perform
/// it on every fresh connection.
async fn perform_handshake(stream: &mut UnixStream, agent_id: &str) {
    // Read the challenge frame: [tag][varint len][HandshakeChallenge].
    let tag = stream.read_u8().await.expect("read handshake challenge tag");
    assert_eq!(tag, TAG_HANDSHAKE_CHALLENGE, "expected a HandshakeChallenge frame");
    let len = read_varint(stream).await.expect("read challenge len") as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.expect("read challenge payload");
    let challenge = HandshakeChallenge::decode(buf.as_ref()).expect("decode HandshakeChallenge");

    // Sign `nonce || sdk_version` with the agent's deterministic keypair
    // (AAASM-3666). This client sends no version (empty), so the signed payload
    // reduces to the bare nonce — the backward-compat path — and the runtime
    // verifies it exactly as before.
    let keypair = AgentKeypair::derive_transport_key(agent_id);
    let sdk_version = String::new();
    let mut signed_payload = challenge.nonce.clone();
    signed_payload.extend_from_slice(sdk_version.as_bytes());
    let proof = HandshakeProof {
        agent_did: keypair.did_key(),
        public_key: keypair.public_key_hex(),
        signature: keypair.sign(&signed_payload).to_vec(),
        sdk_version,
    };

    // Write the proof frame: [tag][varint len][HandshakeProof].
    let payload = proof.encode_to_vec();
    stream.write_u8(TAG_HANDSHAKE_PROOF).await.expect("write proof tag");
    write_varint(stream, payload.len() as u64)
        .await
        .expect("write proof len");
    stream.write_all(&payload).await.expect("write proof payload");
    stream.flush().await.expect("flush proof");
}

/// Send one `CheckActionRequest` over the runtime UDS and return the gateway's
/// decision as relayed back in the `CheckActionResponse`.
async fn check_tool(socket_path: &Path, agent_id: &str, req: &CheckActionRequest) -> CheckActionResponse {
    let mut stream = UnixStream::connect(socket_path).await.expect("connect to runtime UDS");

    // AAASM-3585: the runtime requires a signed session handshake before it will
    // serve any PolicyQuery — perform it first, exactly as the real SDK does.
    perform_handshake(&mut stream, agent_id).await;

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
    let runtime_bin = match locate_runtime_binary() {
        Ok(p) => p,
        Err(e) => {
            common::precondition::require("runtime_forwards_per_tool_deny_to_gateway", Err(e));
            return;
        }
    };
    if !common::precondition::require(
        "runtime_forwards_per_tool_deny_to_gateway",
        gateway_binary_locatable_result(),
    ) {
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
    let allow = check_tool(
        &runtime.socket_path,
        &agent_id,
        &tool_call_request(&agent_id, "read_file"),
    )
    .await;
    assert_eq!(
        allow.decision,
        Decision::Allow as i32,
        "read_file must be ALLOWED end-to-end (got reason: {})",
        allow.reason
    );

    // Deny path (the regression): the gateway denies `delete_file`, and the
    // runtime MUST forward the check and relay the Deny — not short-circuit to
    // a local allow.
    let deny = check_tool(
        &runtime.socket_path,
        &agent_id,
        &tool_call_request(&agent_id, "delete_file"),
    )
    .await;
    assert_eq!(
        deny.decision,
        Decision::Deny as i32,
        "delete_file must be DENIED end-to-end via the gateway — a local allow \
         here is the AAASM-3430 regression (got reason: {})",
        deny.reason
    );
}

// ---------------------------------------------------------------------------
// AAASM-6469 / J27 — "scrub where the layer can, otherwise deny" on the
// non-proxy SDK path.
//
// Owner decision (2026-11-14, rc.8): on the path every SDK uses (SDK ->
// runtime socket -> gateway), a gateway `redact_only` verdict cannot be applied
// to tool arguments, because nothing carries scrubbed arguments back to the
// SDK. The runtime must therefore answer `Deny` — never `Redact`, never
// `Allow` — so the SDK cannot execute the tool with the secret-bearing
// arguments. `aa-runtime::pipeline::normalize_gateway_decision` is the single
// place that guarantees this; these tests drive it over the real wire.
//
// Every negative has a control whose only variable is the one under test, so a
// Deny can only come from the redaction verdict being refused, not from a
// missing backend or a malformed request.
// ---------------------------------------------------------------------------

/// Fabricated AWS-style access key (pattern-matching only, not a credential).
const FAKE_AWS_KEY: &str = "AKIAABCDEFGHIJKLMNOP";

fn credential_policy(credential_action: &str) -> String {
    format!(
        "\
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: aaasm-6469-{credential_action}
  version: \"0.1.0\"
spec:
  tools:
    write_file:
      allow: true
  data:
    credential_action: {credential_action}
"
    )
}

fn tool_call_with_args(agent_id: &str, tool_name: &str, args_json: &str) -> CheckActionRequest {
    let mut req = tool_call_request(agent_id, tool_name);
    if let Some(Action::ToolCall(call)) = req.context.as_mut().and_then(|c| c.action.as_mut()) {
        call.args_json = args_json.as_bytes().to_vec();
    }
    req
}

fn args_with_secret() -> String {
    format!(r#"{{"path":"/tmp/x.txt","aws_key":"{FAKE_AWS_KEY}"}}"#)
}

fn args_without_secret() -> String {
    r#"{"path":"/tmp/x.txt","note":"nothing sensitive here"}"#.to_string()
}

/// A real gateway + real runtime pair for one `credential_action`. `None` means
/// the binaries are absent and the precondition helper chose to skip.
struct CredentialStack {
    _gateway: LiveGateway,
    runtime: LiveRuntime,
    agent_id: String,
}

async fn start_credential_stack(scenario: &str, credential_action: &str) -> Option<CredentialStack> {
    let runtime_bin = match locate_runtime_binary() {
        Ok(p) => p,
        Err(e) => {
            common::precondition::require(scenario, Err(e));
            return None;
        }
    };
    if !common::precondition::require(scenario, gateway_binary_locatable_result()) {
        return None;
    }
    let gateway = LiveGateway::spawn_with_policy(&credential_policy(credential_action)).expect("spawn aa-gateway");
    let endpoint = format!("http://{}", gateway.addr());
    let agent_id = format!("aaasm6469-{credential_action}-{}", std::process::id());
    let metrics_port = portpicker::pick_unused_port().expect("free metrics port");
    let runtime = LiveRuntime::spawn(&runtime_bin, &agent_id, &endpoint, metrics_port).expect("spawn aa-runtime");
    assert!(
        runtime.await_ready(Duration::from_secs(30)).await,
        "aa-runtime did not bind its UDS in time"
    );
    Some(CredentialStack {
        _gateway: gateway,
        runtime,
        agent_id,
    })
}

impl CredentialStack {
    async fn check(&self, args_json: &str) -> CheckActionResponse {
        check_tool(
            &self.runtime.socket_path,
            &self.agent_id,
            &tool_call_with_args(&self.agent_id, "write_file", args_json),
        )
        .await
    }
}

fn assert_no_raw_secret(resp: &CheckActionResponse, what: &str) {
    let wire = resp.encode_to_vec();
    assert!(
        !wire.windows(FAKE_AWS_KEY.len()).any(|w| w == FAKE_AWS_KEY.as_bytes()),
        "{what}: the raw secret appears in the bytes the runtime sent back to the SDK"
    );
}

/// The J27 SDK-path contract: `redact_only` + a credential in tool arguments
/// reaches the SDK as `Deny`. The SDK acts only on that answer, so the tool is
/// never invoked with the unredacted arguments.
#[tokio::test(flavor = "multi_thread")]
async fn runtime_denies_redact_only_secret_instead_of_relaying_redact() {
    let scenario = "runtime_denies_redact_only_secret_instead_of_relaying_redact";
    let Some(stack) = start_credential_stack(scenario, "redact_only").await else {
        return;
    };
    let resp = stack.check(&args_with_secret()).await;
    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "redact_only + a credential in tool args must reach the SDK as Deny — Redact or Allow here lets the \
         SDK run the tool with the raw secret (got decision {}, reason: {})",
        resp.decision,
        resp.reason
    );
    assert_no_raw_secret(&resp, "redact_only deny");
}

/// Control: same mode and tool, no credential. The Deny above must come from
/// the redaction verdict, not from a broken stack or a policy that denies the tool.
#[tokio::test(flavor = "multi_thread")]
async fn control_redact_only_without_secret_is_allowed() {
    let scenario = "control_redact_only_without_secret_is_allowed";
    let Some(stack) = start_credential_stack(scenario, "redact_only").await else {
        return;
    };
    let resp = stack.check(&args_without_secret()).await;
    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "clean args under redact_only must be allowed (got reason: {})",
        resp.reason
    );
}

/// Control: same secret, `alert_only` — the documented "forward unredacted,
/// alert instead" mode, so the runtime must relay Allow.
#[tokio::test(flavor = "multi_thread")]
async fn control_alert_only_with_secret_is_allowed() {
    let scenario = "control_alert_only_with_secret_is_allowed";
    let Some(stack) = start_credential_stack(scenario, "alert_only").await else {
        return;
    };
    let resp = stack.check(&args_with_secret()).await;
    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "alert_only + secret must be allowed (got reason: {})",
        resp.reason
    );
}

/// Control: same secret, `block` — a plain gateway Deny, which shows the Deny
/// path in the redact_only test is the same observable outcome.
#[tokio::test(flavor = "multi_thread")]
async fn control_block_with_secret_is_denied() {
    let scenario = "control_block_with_secret_is_denied";
    let Some(stack) = start_credential_stack(scenario, "block").await else {
        return;
    };
    let resp = stack.check(&args_with_secret()).await;
    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "block + secret must be denied (got reason: {})",
        resp.reason
    );
    assert_no_raw_secret(&resp, "block deny");
}
