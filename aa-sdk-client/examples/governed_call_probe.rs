//! `governed_call_probe` — AAASM-5886: drives one real governed **allow** call
//! and one real governed **deny** call through a live `aa-runtime` over its
//! Unix-socket IPC, the same wire the SDK uses.
//!
//! ## Why this exists
//!
//! The J52 sidecar smoke (`docker/smoke/run-smoke.sh`, AAASM-3524) proved only
//! that the base-image agent runs and that `aa-runtime` starts — never that a
//! governed call is actually enforced by the containerized sidecar. The
//! published base images don't yet ship the SDK's native `_core` transport
//! (AAASM-1202), so the smoke's own per-language agents cannot drive that call
//! themselves today. This probe exercises the running `aa-runtime` container's
//! real `CheckAction` path directly over the UDS it publishes — the same
//! handshake + framing `aa-integration-tests/tests/e2e_runtime_gateway_deny.rs`
//! already proves against a locally-spawned runtime — so the Docker-level smoke
//! gets the same real assertion without re-deriving the wire protocol.
//!
//! It is intentionally a standalone binary rather than a `#[test]`: the Docker
//! smoke harness runs it as a throwaway container against the compose stack's
//! shared UDS volume (see `docker/smoke/probe/Dockerfile.probe` and
//! `docker/smoke/docker-compose.smoke.yml`), not inside `cargo nextest`.
//!
//! ## Usage
//!
//! ```text
//! AA_RUNTIME_SOCKET=/tmp/aa-runtime-<id>.sock AA_AGENT_ID=<id> \
//!   cargo run -p aa-sdk-client --example governed_call_probe
//! ```
//!
//! Prints one JSON line and exits 0 when both checks land on the expected
//! decision; exits 1 (with `"ok":false` and an `"error"`) otherwise — never
//! silently reports success on an unexpected decision.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use aa_proto::assembly::common::v1::{ActionType, AgentId, Decision};
use aa_proto::assembly::ipc::v1::{HandshakeChallenge, HandshakeProof};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::{
    ActionContext, CheckActionRequest, CheckActionResponse, ProcessExecContext, ToolCallContext,
};
use aa_sdk_client::codec::{TAG_HANDSHAKE_CHALLENGE, TAG_HANDSHAKE_PROOF, TAG_POLICY_QUERY, TAG_POLICY_RESPONSE};
use aa_sdk_client::AgentKeypair;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Write a prost-style unsigned varint length prefix.
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

/// Read a prost-style unsigned varint length prefix.
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

/// Complete the runtime's session handshake (AAASM-3585): read its nonce
/// challenge, sign it with the agent's deterministic Ed25519 key, and send
/// back a `HandshakeProof`. The runtime drops the connection before serving
/// any application frame if this is skipped.
async fn perform_handshake(stream: &mut UnixStream, agent_id: &str) -> Result<(), String> {
    let tag = stream
        .read_u8()
        .await
        .map_err(|e| format!("read handshake challenge tag: {e}"))?;
    if tag != TAG_HANDSHAKE_CHALLENGE {
        return Err(format!(
            "expected HandshakeChallenge frame (tag {TAG_HANDSHAKE_CHALLENGE}), got {tag}"
        ));
    }
    let len = read_varint(stream)
        .await
        .map_err(|e| format!("read challenge len: {e}"))? as usize;
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("read challenge payload: {e}"))?;
    let challenge = HandshakeChallenge::decode(buf.as_ref()).map_err(|e| format!("decode HandshakeChallenge: {e}"))?;

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

    let payload = proof.encode_to_vec();
    stream
        .write_u8(TAG_HANDSHAKE_PROOF)
        .await
        .map_err(|e| format!("write proof tag: {e}"))?;
    write_varint(stream, payload.len() as u64)
        .await
        .map_err(|e| format!("write proof len: {e}"))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| format!("write proof payload: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush proof: {e}"))?;
    Ok(())
}

/// Open a fresh connection, complete the handshake, send one
/// `CheckActionRequest`, and return the runtime's `CheckActionResponse`.
async fn check_action(
    socket_path: &Path,
    agent_id: &str,
    req: &CheckActionRequest,
) -> Result<CheckActionResponse, String> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("connect to runtime UDS {}: {e}", socket_path.display()))?;

    perform_handshake(&mut stream, agent_id).await?;

    let payload = req.encode_to_vec();
    stream
        .write_u8(TAG_POLICY_QUERY)
        .await
        .map_err(|e| format!("write tag: {e}"))?;
    write_varint(&mut stream, payload.len() as u64)
        .await
        .map_err(|e| format!("write len: {e}"))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| format!("write payload: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;

    let tag = stream.read_u8().await.map_err(|e| format!("read response tag: {e}"))?;
    if tag != TAG_POLICY_RESPONSE {
        return Err(format!(
            "expected PolicyResponse frame (tag {TAG_POLICY_RESPONSE}), got {tag}"
        ));
    }
    let len = read_varint(&mut stream)
        .await
        .map_err(|e| format!("read response len: {e}"))? as usize;
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("read response payload: {e}"))?;
    CheckActionResponse::decode(buf.as_ref()).map_err(|e| format!("decode CheckActionResponse: {e}"))
}

/// A `TOOL_CALL` — not in `docker/smoke/policy.toml`'s `blocked_actions`, so a
/// correctly-enforcing runtime must ALLOW it.
fn allowed_tool_call_request(agent_id: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(AgentId {
            org_id: "smoke-org".to_string(),
            team_id: "smoke-team".to_string(),
            agent_id: agent_id.to_string(),
        }),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "tool.search".to_string(),
                tool_source: "function".to_string(),
                ..Default::default()
            })),
        }),
        ..Default::default()
    }
}

/// A `PROCESS_EXEC` — the restricted action `docker/smoke/policy.toml` blocks,
/// so a correctly-enforcing runtime must DENY it.
fn denied_process_exec_request(agent_id: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(AgentId {
            org_id: "smoke-org".to_string(),
            team_id: "smoke-team".to_string(),
            agent_id: agent_id.to_string(),
        }),
        action_type: ActionType::ProcessExec as i32,
        context: Some(ActionContext {
            action: Some(Action::ProcessExec(ProcessExecContext {
                command: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "id".to_string()],
            })),
        }),
        ..Default::default()
    }
}

fn emit(ok: bool, fields: &[(&str, String)]) {
    let mut body = format!("\"ok\":{ok}");
    for (k, v) in fields {
        body.push_str(&format!(",\"{k}\":{v}"));
    }
    println!("{{{body}}}");
}

/// Minimal JSON string escaping — NOT `{:?}` (Rust `Debug`), which escapes
/// differently (e.g. `\'`, which is invalid JSON) and would corrupt this
/// output whenever `allow.reason`/`deny.reason` (attacker/runtime-controlled
/// text, not a fixed literal) contains a quote, backslash, or control char —
/// silently turning a real enforcement pass into an unparseable line that the
/// runner's `jq` read would misreport as a probe failure.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[tokio::main]
async fn main() -> ExitCode {
    let socket_path = match env::var("AA_RUNTIME_SOCKET") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            emit(
                false,
                &[(
                    "error",
                    json_str("AA_RUNTIME_SOCKET must be set to the aa-runtime UDS path"),
                )],
            );
            return ExitCode::FAILURE;
        }
    };
    let agent_id = match env::var("AA_AGENT_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            emit(
                false,
                &[(
                    "error",
                    json_str("AA_AGENT_ID must be set (matches the runtime's AA_AGENT_ID)"),
                )],
            );
            return ExitCode::FAILURE;
        }
    };
    let socket_path = Path::new(&socket_path);

    let allow = match check_action(socket_path, &agent_id, &allowed_tool_call_request(&agent_id)).await {
        Ok(r) => r,
        Err(e) => {
            emit(false, &[("stage", json_str("allow")), ("error", json_str(&e))]);
            return ExitCode::FAILURE;
        }
    };
    let deny = match check_action(socket_path, &agent_id, &denied_process_exec_request(&agent_id)).await {
        Ok(r) => r,
        Err(e) => {
            emit(false, &[("stage", json_str("deny")), ("error", json_str(&e))]);
            return ExitCode::FAILURE;
        }
    };

    let allow_ok = allow.decision == Decision::Allow as i32;
    let deny_ok = deny.decision == Decision::Deny as i32;

    let fields = [
        (
            "allow_decision",
            json_str(
                Decision::try_from(allow.decision)
                    .map(|d| d.as_str_name())
                    .unwrap_or("UNKNOWN"),
            ),
        ),
        ("allow_reason", json_str(&allow.reason)),
        (
            "deny_decision",
            json_str(
                Decision::try_from(deny.decision)
                    .map(|d| d.as_str_name())
                    .unwrap_or("UNKNOWN"),
            ),
        ),
        ("deny_reason", json_str(&deny.reason)),
    ];

    if allow_ok && deny_ok {
        emit(true, &fields);
        ExitCode::SUCCESS
    } else {
        emit(false, &fields);
        ExitCode::FAILURE
    }
}
