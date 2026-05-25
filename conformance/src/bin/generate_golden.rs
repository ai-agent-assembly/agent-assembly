//! Generates golden binary files for message-serialization conformance vectors.
//!
//! Run with:
//!   cargo run -p conformance --bin generate_golden
//!
//! Output: `conformance/vectors/proto/<name>.bin`
//!
//! Re-run whenever a proto definition changes to update the golden files.

use aa_proto::assembly::{
    agent::v1::{DeregisterRequest, HeartbeatRequest, RegisterRequest, RegisterResponse},
    common::v1::{AgentId, Decision, RiskTier, Timestamp},
    policy::v1::{
        ActionContext, CheckActionRequest, CheckActionResponse, RedactInstructions, RedactRule, ToolCallContext,
    },
};
use prost::Message;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn out_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/proto")
}

fn write(name: &str, msg: &impl Message) {
    let bytes = msg.encode_to_vec();
    let path = out_dir().join(format!("{name}.bin"));
    fs::write(&path, &bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

fn main() {
    fs::create_dir_all(out_dir()).expect("create vectors/proto dir");

    // ── AgentId ──────────────────────────────────────────────────────────────

    write(
        "agent_id_full",
        &AgentId {
            org_id: "acme-corp".into(),
            team_id: "platform".into(),
            agent_id: "did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T".into(),
        },
    );

    write(
        "agent_id_minimal",
        &AgentId {
            org_id: "acme".into(),
            team_id: String::new(),
            agent_id: String::new(),
        },
    );

    // ── CheckActionRequest ────────────────────────────────────────────────────

    write(
        "check_action_request_tool_call",
        &CheckActionRequest {
            agent_id: Some(AgentId {
                org_id: "acme-corp".into(),
                team_id: "platform".into(),
                agent_id: "did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T".into(),
            }),
            credential_token: "tok-abc123".into(),
            trace_id: "01HZAB1234567890ABCDEF".into(),
            span_id: "01HZAB0000000000000001".into(),
            action_type: 2, // TOOL_CALL
            context: Some(ActionContext {
                action: Some(aa_proto::assembly::policy::v1::action_context::Action::ToolCall(
                    ToolCallContext {
                        tool_name: "web_search".into(),
                        tool_source: "mcp".into(),
                        args_json: b"{\"query\":\"test\"}".to_vec(),
                        target_url: "https://search.example.com".into(),
                    },
                )),
            }),
            caller_agent_id: None,
        },
    );

    // ── CheckActionResponse ───────────────────────────────────────────────────

    write(
        "check_action_response_allow",
        &CheckActionResponse {
            decision: Decision::Allow as i32,
            reason: "Tool 'web_search' is allowed by policy rule".into(),
            policy_rule: "rule:allow-declared-tools-v1".into(),
            approval_id: String::new(),
            redact: None,
            decision_latency_us: 312,
        },
    );

    write(
        "check_action_response_redact",
        &CheckActionResponse {
            decision: Decision::Redact as i32,
            reason: "Credential detected in args_json".into(),
            policy_rule: "rule:redact-credentials-v1".into(),
            approval_id: String::new(),
            redact: Some(RedactInstructions {
                rules: vec![RedactRule {
                    field_path: "$.args.api_key".into(),
                    replacement: "[REDACTED]".into(),
                }],
            }),
            decision_latency_us: 520,
        },
    );

    // ── RegisterRequest / RegisterResponse ────────────────────────────────────

    write(
        "register_request",
        &RegisterRequest {
            agent_id: Some(AgentId {
                org_id: "acme-corp".into(),
                team_id: "platform".into(),
                agent_id: "did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T".into(),
            }),
            name: "acme-platform-agent-v1".into(),
            framework: "langgraph".into(),
            version: "1.2.3".into(),
            risk_tier: RiskTier::Medium as i32,
            tool_names: vec!["web_search".into(), "code_interpreter".into()],
            public_key: "ed25519:z6MkkMh5nVgAeTf9ZLaD3ABCDE".into(),
            metadata: [
                ("env".to_string(), "production".to_string()),
                ("team".to_string(), "platform".to_string()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    );

    write(
        "register_response",
        &RegisterResponse {
            credential_token: "eyJhbGciOiJFZERTQSJ9.tok.sig".into(),
            assigned_policy: "policy:acme-standard-v2".into(),
            heartbeat_interval_sec: 30,
            ..Default::default()
        },
    );

    // ── HeartbeatRequest ──────────────────────────────────────────────────────

    write(
        "heartbeat_request",
        &HeartbeatRequest {
            agent_id: Some(AgentId {
                org_id: "acme-corp".into(),
                team_id: "platform".into(),
                agent_id: "did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T".into(),
            }),
            credential_token: "tok-abc123".into(),
            active_runs: 3,
            actions_count: 17,
        },
    );

    // ── DeregisterRequest ─────────────────────────────────────────────────────

    write(
        "deregister_request",
        &DeregisterRequest {
            agent_id: Some(AgentId {
                org_id: "acme-corp".into(),
                team_id: "platform".into(),
                agent_id: "did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T".into(),
            }),
            credential_token: "tok-abc123".into(),
            reason: "clean shutdown".into(),
        },
    );

    // ── Timestamp ─────────────────────────────────────────────────────────────

    write(
        "timestamp",
        &Timestamp {
            unix_ms: 1_745_740_800_000,
        },
    );

    println!("All golden files written to {}", out_dir().display());
}
