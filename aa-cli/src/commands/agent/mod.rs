//! `aasm agent` — manage monitored agent processes.

use std::collections::BTreeMap;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

pub mod inspect;
pub mod kill;
pub mod list;
pub mod resume;
pub mod suspend;

/// Arguments for the `aasm agent` subcommand group.
#[derive(Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub command: AgentCommands,
}

/// Available agent subcommands.
#[derive(Subcommand)]
pub enum AgentCommands {
    /// List all registered agents.
    List(list::ListArgs),
    /// Show detailed information about a specific agent.
    Inspect(inspect::InspectArgs),
    /// Deregister and terminate an agent.
    Kill(kill::KillArgs),
    /// Suspend a running agent.
    Suspend(suspend::SuspendArgs),
    /// Resume a suspended agent.
    Resume(resume::ResumeArgs),
}

/// Dispatch an agent subcommand.
pub fn dispatch(args: AgentArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    match args.command {
        AgentCommands::List(list_args) => list::run(list_args, ctx, output),
        AgentCommands::Inspect(inspect_args) => inspect::run(inspect_args, ctx, output),
        AgentCommands::Kill(kill_args) => kill::run(kill_args, ctx),
        AgentCommands::Suspend(suspend_args) => suspend::run(suspend_args, ctx, output),
        AgentCommands::Resume(resume_args) => resume::run(resume_args, ctx, output),
    }
}

/// JSON representation of an agent returned by the gateway API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    /// Hex-encoded agent UUID.
    pub id: String,
    /// Human-readable agent name.
    pub name: String,
    /// Agent framework (e.g. "langgraph", "crewai").
    pub framework: String,
    /// Semver version string.
    pub version: String,
    /// Current runtime status.
    pub status: String,
    /// Tools declared at registration.
    pub tool_names: Vec<String>,
    /// Arbitrary metadata key-value pairs.
    pub metadata: BTreeMap<String, String>,
    /// OS process ID, if known.
    #[serde(default)]
    pub pid: Option<u32>,
    /// Number of sessions handled.
    #[serde(default)]
    pub session_count: Option<u32>,
    /// ISO 8601 timestamp of the most recent event.
    #[serde(default)]
    pub last_event: Option<String>,
    /// Number of policy violations recorded.
    #[serde(default)]
    pub policy_violations_count: Option<u32>,
    /// Currently active sessions for this agent.
    #[serde(default)]
    pub active_sessions: Vec<ActiveSessionResponse>,
    /// Most recent events emitted by this agent.
    #[serde(default)]
    pub recent_events: Vec<RecentEventResponse>,
    /// Most recent trace session IDs for this agent.
    #[serde(default)]
    pub recent_traces: Vec<RecentTraceResponse>,
}

/// Summary of an active session returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSessionResponse {
    /// Hex-encoded session UUID.
    pub session_id: String,
    /// ISO 8601 timestamp when the session started.
    pub started_at: String,
    /// Current status of the session.
    pub status: String,
}

/// Summary of a recent event returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentEventResponse {
    /// Event type classification (e.g. "violation", "approval", "budget").
    pub event_type: String,
    /// Short human-readable summary.
    pub summary: String,
    /// ISO 8601 timestamp when the event occurred.
    pub timestamp: String,
}

/// Summary of a recent trace session returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentTraceResponse {
    /// Hex-encoded session UUID, usable with `aasm trace <session-id>`.
    pub session_id: String,
    /// ISO 8601 timestamp when the trace session started.
    pub timestamp: String,
}

/// Paginated API response wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    #[allow(dead_code)]
    pub page: u32,
    #[allow(dead_code)]
    pub per_page: u32,
    #[allow(dead_code)]
    pub total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_response_deserializes_from_json() {
        let json = r#"{
            "id": "aabbccdd00112233aabbccdd00112233",
            "name": "my-agent",
            "framework": "langgraph",
            "version": "0.2.0",
            "status": "Active",
            "tool_names": ["search", "calculator"],
            "metadata": {"env": "production"}
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(agent.id, "aabbccdd00112233aabbccdd00112233");
        assert_eq!(agent.name, "my-agent");
        assert_eq!(agent.framework, "langgraph");
        assert_eq!(agent.version, "0.2.0");
        assert_eq!(agent.status, "Active");
        assert_eq!(agent.tool_names, vec!["search", "calculator"]);
        assert_eq!(agent.metadata.get("env").unwrap(), "production");
    }

    #[test]
    fn agent_response_round_trip() {
        let agent = AgentResponse {
            id: "00112233445566778899aabbccddeeff".to_string(),
            name: "round-trip-agent".to_string(),
            framework: "crewai".to_string(),
            version: "1.0.0".to_string(),
            status: "Suspended(PolicyViolation)".to_string(),
            tool_names: vec![],
            metadata: BTreeMap::new(),
            pid: Some(1234),
            session_count: Some(5),
            last_event: Some("2025-01-01T00:00:00Z".to_string()),
            policy_violations_count: Some(2),
            active_sessions: vec![],
            recent_events: vec![],
            recent_traces: vec![],
        };

        let json = serde_json::to_string(&agent).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, agent.id);
        assert_eq!(parsed.status, agent.status);
        assert!(parsed.tool_names.is_empty());
    }

    #[test]
    fn paginated_response_deserializes() {
        let json = r#"{
            "items": [
                {
                    "id": "aabb",
                    "name": "a1",
                    "framework": "f1",
                    "version": "0.1.0",
                    "status": "Active",
                    "tool_names": [],
                    "metadata": {}
                }
            ],
            "page": 1,
            "per_page": 20,
            "total": 1
        }"#;

        let resp: PaginatedResponse<AgentResponse> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].name, "a1");
        assert_eq!(resp.page, 1);
        assert_eq!(resp.total, 1);
    }

    #[test]
    fn agent_response_with_empty_metadata() {
        let json = r#"{
            "id": "ff",
            "name": "empty-meta",
            "framework": "custom",
            "version": "0.0.1",
            "status": "Deregistered",
            "tool_names": [],
            "metadata": {}
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert!(agent.metadata.is_empty());
        assert!(agent.tool_names.is_empty());
    }

    #[test]
    fn new_fields_default_to_none_when_missing() {
        let json = r#"{
            "id": "aa",
            "name": "old-server",
            "framework": "custom",
            "version": "0.0.1",
            "status": "Active",
            "tool_names": [],
            "metadata": {}
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert!(agent.pid.is_none());
        assert!(agent.session_count.is_none());
        assert!(agent.last_event.is_none());
        assert!(agent.policy_violations_count.is_none());
        assert!(agent.active_sessions.is_empty());
        assert!(agent.recent_events.is_empty());
    }

    #[test]
    fn new_fields_deserialize_when_present() {
        let json = r#"{
            "id": "bb",
            "name": "full-agent",
            "framework": "langgraph",
            "version": "1.0.0",
            "status": "Active",
            "tool_names": ["search"],
            "metadata": {},
            "pid": 4567,
            "session_count": 12,
            "last_event": "2025-06-15T08:30:00Z",
            "policy_violations_count": 3
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(agent.pid, Some(4567));
        assert_eq!(agent.session_count, Some(12));
        assert_eq!(agent.last_event.as_deref(), Some("2025-06-15T08:30:00Z"));
        assert_eq!(agent.policy_violations_count, Some(3));
    }

    #[test]
    fn round_trip_preserves_new_fields() {
        let agent = AgentResponse {
            id: "cc".to_string(),
            name: "rt-agent".to_string(),
            framework: "crewai".to_string(),
            version: "2.0.0".to_string(),
            status: "Active".to_string(),
            tool_names: vec![],
            metadata: BTreeMap::new(),
            pid: Some(9999),
            session_count: Some(42),
            last_event: Some("2025-03-01T12:00:00Z".to_string()),
            policy_violations_count: Some(0),
            active_sessions: vec![],
            recent_events: vec![],
            recent_traces: vec![],
        };

        let json = serde_json::to_string(&agent).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, Some(9999));
        assert_eq!(parsed.session_count, Some(42));
        assert_eq!(parsed.last_event.as_deref(), Some("2025-03-01T12:00:00Z"));
        assert_eq!(parsed.policy_violations_count, Some(0));
    }

    #[test]
    fn active_sessions_and_recent_events_deserialize() {
        let json = r#"{
            "id": "dd",
            "name": "session-agent",
            "framework": "custom",
            "version": "1.0.0",
            "status": "Active",
            "tool_names": [],
            "metadata": {},
            "active_sessions": [
                {"session_id": "s1", "started_at": "2025-06-01T10:00:00Z", "status": "running"},
                {"session_id": "s2", "started_at": "2025-06-01T11:00:00Z", "status": "idle"}
            ],
            "recent_events": [
                {"event_type": "violation", "summary": "blocked call", "timestamp": "2025-06-01T10:05:00Z"}
            ]
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(agent.active_sessions.len(), 2);
        assert_eq!(agent.active_sessions[0].session_id, "s1");
        assert_eq!(agent.active_sessions[0].status, "running");
        assert_eq!(agent.active_sessions[1].session_id, "s2");
        assert_eq!(agent.recent_events.len(), 1);
        assert_eq!(agent.recent_events[0].event_type, "violation");
        assert_eq!(agent.recent_events[0].summary, "blocked call");
    }

    #[test]
    fn recent_traces_defaults_to_empty_when_missing() {
        let json = r#"{
            "id": "ee",
            "name": "no-traces",
            "framework": "custom",
            "version": "1.0.0",
            "status": "Active",
            "tool_names": [],
            "metadata": {}
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert!(agent.recent_traces.is_empty());
    }

    #[test]
    fn recent_traces_deserialize_when_present() {
        let json = r#"{
            "id": "ff",
            "name": "traced-agent",
            "framework": "langgraph",
            "version": "1.0.0",
            "status": "Active",
            "tool_names": [],
            "metadata": {},
            "recent_traces": [
                {"session_id": "sess-abc123", "timestamp": "2026-04-30T10:00:00Z"},
                {"session_id": "sess-def456", "timestamp": "2026-04-30T09:30:00Z"}
            ]
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(agent.recent_traces.len(), 2);
        assert_eq!(agent.recent_traces[0].session_id, "sess-abc123");
        assert_eq!(agent.recent_traces[0].timestamp, "2026-04-30T10:00:00Z");
        assert_eq!(agent.recent_traces[1].session_id, "sess-def456");
    }

    #[test]
    fn recent_traces_round_trip() {
        let agent = AgentResponse {
            id: "gg".to_string(),
            name: "rt-traces".to_string(),
            framework: "crewai".to_string(),
            version: "1.0.0".to_string(),
            status: "Active".to_string(),
            tool_names: vec![],
            metadata: BTreeMap::new(),
            pid: None,
            session_count: None,
            last_event: None,
            policy_violations_count: None,
            active_sessions: vec![],
            recent_events: vec![],
            recent_traces: vec![RecentTraceResponse {
                session_id: "sess-111".to_string(),
                timestamp: "2026-04-30T08:00:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&agent).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.recent_traces.len(), 1);
        assert_eq!(parsed.recent_traces[0].session_id, "sess-111");
        assert_eq!(parsed.recent_traces[0].timestamp, "2026-04-30T08:00:00Z");
    }
}
