//! Mesh topology edge endpoints.
//!
//! Four endpoints:
//!   POST /topology/edges           — record a new directed edge (intake for SDK emitters)
//!   GET  /topology/edges           — list all edges, optionally filtered by team
//!   GET  /agents/{id}/edges        — paginated edge listing for one agent
//!   GET  /agents/{id}/graph        — BFS subgraph reachable from one agent

use std::collections::{HashMap, HashSet, VecDeque};

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use aa_core::identity::AgentId;
use aa_core::topology::{Edge, EdgeType, NewEdge};

use crate::error::ProblemDetail;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_agent_id(id: &str) -> Result<AgentId, ProblemDetail> {
    let bytes: Vec<u8> = (0..id.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&id[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| {
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid agent ID format: {id}"))
        })?;
    let arr: [u8; 16] = bytes.try_into().map_err(|_| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(format!("Agent ID must be 32 hex characters: {id}"))
    })?;
    Ok(AgentId::from_bytes(arr))
}

fn format_id(id: &AgentId) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_edge_type(s: &str) -> Result<EdgeType, ProblemDetail> {
    EdgeType::try_from(s).map_err(|_| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!(
            "Unknown edge_type: {s}. Valid values: delegates_to, calls, reads, writes, approves, messages"
        ))
    })
}

// ---------------------------------------------------------------------------
// Shared response types
// ---------------------------------------------------------------------------

/// A single directed edge between two agents.
#[derive(Debug, Serialize, ToSchema)]
pub struct EdgeResponse {
    /// Auto-assigned edge identifier.
    pub id: i64,
    /// Hex-encoded source agent ID.
    pub source_agent_id: String,
    /// Hex-encoded target agent ID.
    pub target_agent_id: String,
    /// Edge semantic type (snake_case).
    pub edge_type: String,
    /// ISO 8601 timestamp when the edge was recorded.
    pub created_at: String,
    /// Whether the edge crosses team boundaries.
    pub is_cross_team: bool,
    /// Optional freeform metadata attached at emission time.
    #[schema(value_type = Option<serde_json::Value>)]
    pub metadata: Option<serde_json::Value>,
}

fn edge_to_response(edge: &Edge, is_cross_team: bool) -> EdgeResponse {
    EdgeResponse {
        id: edge.id,
        source_agent_id: format_id(&edge.source),
        target_agent_id: format_id(&edge.target),
        edge_type: edge.edge_type.as_str().to_owned(),
        created_at: edge.created_at.to_rfc3339(),
        is_cross_team,
        metadata: edge.metadata.clone(),
    }
}

// ---------------------------------------------------------------------------
// is_cross_team helper
// ---------------------------------------------------------------------------

/// Batch-compute `is_cross_team` for a set of edges by comparing team_id
/// from the agent registry.  Missing agents → treated as team-less (false).
fn compute_cross_team(edges: &[Edge], state: &AppState) -> Vec<bool> {
    // Collect all unique agent IDs
    let mut ids: HashSet<AgentId> = HashSet::new();
    for e in edges {
        ids.insert(e.source);
        ids.insert(e.target);
    }

    // Batch lookup: agent_id → Option<team_id>
    let team_map: HashMap<AgentId, Option<String>> = ids
        .into_iter()
        .map(|id| {
            let team = state.agent_registry.get(id.as_bytes()).and_then(|r| r.team_id.clone());
            (id, team)
        })
        .collect();

    edges
        .iter()
        .map(|e| {
            let src_team = team_map.get(&e.source).and_then(|t| t.as_deref());
            let tgt_team = team_map.get(&e.target).and_then(|t| t.as_deref());
            match (src_team, tgt_team) {
                (Some(a), Some(b)) => a != b,
                _ => false,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// POST /topology/edges — record a new edge (SDK intake)
// ---------------------------------------------------------------------------

/// Request body for recording a new directed edge.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReportEdgeRequest {
    /// Hex-encoded source agent ID.
    pub source_agent_id: String,
    /// Hex-encoded target agent ID.
    pub target_agent_id: String,
    /// Edge semantic type (e.g. `"messages"`, `"delegates_to"`).
    pub edge_type: String,
    /// Optional metadata JSON string.
    pub metadata_json: Option<String>,
}

/// Response after recording a new edge.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReportEdgeResponse {
    /// Auto-assigned edge identifier.
    pub id: i64,
}

/// Record a new directed topology edge.
///
/// Used by SDK emitters (Python, Node.js, Go) to push observed
/// agent-to-agent interactions into the gateway edge store.
#[utoipa::path(
    post,
    path = "/api/v1/topology/edges",
    request_body = ReportEdgeRequest,
    responses(
        (status = 201, description = "Edge recorded", body = ReportEdgeResponse),
        (status = 400, description = "Invalid request", body = ProblemDetail),
        (status = 500, description = "Store error", body = ProblemDetail),
    ),
    tag = "topology"
)]
pub async fn report_edge(
    Extension(state): Extension<AppState>,
    Json(body): Json<ReportEdgeRequest>,
) -> Result<(StatusCode, Json<ReportEdgeResponse>), ProblemDetail> {
    let source = parse_agent_id(&body.source_agent_id)?;
    let target = parse_agent_id(&body.target_agent_id)?;
    let edge_type = parse_edge_type(&body.edge_type)?;

    let metadata = if let Some(json_str) = body.metadata_json {
        if json_str.is_empty() {
            None
        } else {
            let v: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
                ProblemDetail::from_status(StatusCode::BAD_REQUEST)
                    .with_detail(format!("metadata_json is not valid JSON: {e}"))
            })?;
            Some(v)
        }
    } else {
        None
    };

    let id = state
        .edge_repo
        .insert(NewEdge {
            source,
            target,
            edge_type,
            metadata,
        })
        .await
        .map_err(|e| {
            ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail(format!("Edge store error: {e}"))
        })?;

    Ok((StatusCode::CREATED, Json(ReportEdgeResponse { id })))
}

// ---------------------------------------------------------------------------
// GET /agents/{id}/edges
// ---------------------------------------------------------------------------

/// Query parameters for the edge listing endpoint.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct EdgeListParams {
    /// Filter by edge type (snake_case). Omit for all types.
    #[param(example = "messages")]
    pub r#type: Option<String>,
    /// Direction of edges relative to the agent. Defaults to `outgoing`.
    #[param(example = "outgoing")]
    pub direction: Option<String>,
    /// Maximum number of results. Defaults to 100, capped at 1000.
    #[param(example = 100)]
    pub limit: Option<u32>,
    /// Return only edges recorded before this ISO 8601 timestamp.
    #[param(example = "2026-01-01T00:00:00Z")]
    pub before: Option<String>,
}

/// Paginated list of directed edges for an agent.
#[derive(Debug, Serialize, ToSchema)]
pub struct EdgeListResponse {
    /// The queried agent ID.
    pub agent_id: String,
    /// The list of matching edges, newest first.
    pub edges: Vec<EdgeResponse>,
    /// Total number of edges returned.
    pub count: usize,
}

/// List directed edges for an agent.
///
/// Returns edges ordered newest-first.  `direction` defaults to `outgoing`.
/// `limit` defaults to 100 and is capped at 1000.  `before` filters to edges
/// recorded before the given ISO 8601 timestamp.
#[utoipa::path(
    get,
    path = "/api/v1/agents/{id}/edges",
    params(
        ("id" = String, Path, description = "Hex-encoded agent ID"),
        EdgeListParams,
    ),
    responses(
        (status = 200, description = "Edge list", body = EdgeListResponse),
        (status = 400, description = "Invalid request", body = ProblemDetail),
        (status = 500, description = "Store error", body = ProblemDetail),
    ),
    tag = "agents"
)]
pub async fn list_agent_edges(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(params): Query<EdgeListParams>,
) -> Result<(StatusCode, Json<EdgeListResponse>), ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    let edge_type: Option<EdgeType> = params.r#type.as_deref().map(parse_edge_type).transpose()?;

    let direction = params.direction.as_deref().unwrap_or("outgoing");
    let limit = params.limit.unwrap_or(100).min(1000);

    let before: Option<DateTime<Utc>> = params
        .before
        .as_deref()
        .map(|s| {
            s.parse::<DateTime<Utc>>().map_err(|_| {
                ProblemDetail::from_status(StatusCode::BAD_REQUEST)
                    .with_detail(format!("Invalid 'before' timestamp: {s}"))
            })
        })
        .transpose()?;

    let raw_edges = match direction {
        "incoming" => state.edge_repo.list_incoming(agent_id, edge_type, limit).await,
        _ => state.edge_repo.list_outgoing(agent_id, edge_type, limit).await,
    }
    .map_err(|e| {
        ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail(format!("Edge store error: {e}"))
    })?;

    // Apply optional `before` cursor (best-effort for in-memory store)
    let filtered: Vec<Edge> = if let Some(cutoff) = before {
        raw_edges.into_iter().filter(|e| e.created_at < cutoff).collect()
    } else {
        raw_edges
    };

    let cross_team_flags = compute_cross_team(&filtered, &state);
    let edges: Vec<EdgeResponse> = filtered
        .iter()
        .zip(cross_team_flags.iter())
        .map(|(e, &ct)| edge_to_response(e, ct))
        .collect();

    let count = edges.len();
    Ok((
        StatusCode::OK,
        Json(EdgeListResponse {
            agent_id: id,
            edges,
            count,
        }),
    ))
}

// ---------------------------------------------------------------------------
// GET /agents/{id}/graph
// ---------------------------------------------------------------------------

/// Query parameters for the subgraph endpoint.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct GraphParams {
    /// BFS depth from the root agent. Defaults to 2, capped at 5.
    #[param(example = 2)]
    pub depth: Option<u32>,
}

/// A node in the topology subgraph.
#[derive(Debug, Serialize, ToSchema)]
pub struct GraphNode {
    /// Hex-encoded agent ID.
    pub id: String,
}

/// Subgraph reachable from an agent within a depth bound.
#[derive(Debug, Serialize, ToSchema)]
pub struct GraphResponse {
    /// Root agent ID used for the BFS.
    pub root_agent_id: String,
    /// All unique agent nodes reachable within `depth` hops.
    pub nodes: Vec<GraphNode>,
    /// All edges between nodes in this subgraph.
    pub edges: Vec<EdgeResponse>,
}

/// Return the topology subgraph reachable from an agent.
///
/// Performs BFS outward from `id` up to `depth` hops (default 2, max 5).
/// Returns all unique nodes reachable and the edges between them, with
/// `is_cross_team` computed via a batched registry lookup.
#[utoipa::path(
    get,
    path = "/api/v1/agents/{id}/graph",
    params(
        ("id" = String, Path, description = "Hex-encoded root agent ID"),
        GraphParams,
    ),
    responses(
        (status = 200, description = "Subgraph", body = GraphResponse),
        (status = 400, description = "Invalid request", body = ProblemDetail),
        (status = 500, description = "Store error", body = ProblemDetail),
    ),
    tag = "agents"
)]
pub async fn get_agent_graph(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(params): Query<GraphParams>,
) -> Result<(StatusCode, Json<GraphResponse>), ProblemDetail> {
    let root_id = parse_agent_id(&id)?;
    let depth = params.depth.unwrap_or(2).min(5);

    // BFS: collect unique node IDs within `depth` hops
    let mut visited: HashSet<AgentId> = HashSet::new();
    let mut queue: VecDeque<(AgentId, u32)> = VecDeque::new();
    queue.push_back((root_id, 0));
    visited.insert(root_id);

    while let Some((node, d)) = queue.pop_front() {
        if d >= depth {
            continue;
        }
        let outgoing = state.edge_repo.list_outgoing(node, None, 1000).await.map_err(|e| {
            ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail(format!("Edge store error: {e}"))
        })?;
        for edge in outgoing {
            if visited.insert(edge.target) {
                queue.push_back((edge.target, d + 1));
            }
        }
    }

    // Batch-fetch all edges where source is in the visited set
    let mut all_edges: Vec<Edge> = Vec::new();
    for &node in &visited {
        let outgoing = state.edge_repo.list_outgoing(node, None, 1000).await.map_err(|e| {
            ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail(format!("Edge store error: {e}"))
        })?;
        // Keep only edges whose target is also in the subgraph
        for edge in outgoing {
            if visited.contains(&edge.target) {
                all_edges.push(edge);
            }
        }
    }

    let cross_team_flags = compute_cross_team(&all_edges, &state);
    let edge_responses: Vec<EdgeResponse> = all_edges
        .iter()
        .zip(cross_team_flags.iter())
        .map(|(e, &ct)| edge_to_response(e, ct))
        .collect();

    let nodes: Vec<GraphNode> = visited
        .into_iter()
        .map(|node_id| GraphNode {
            id: format_id(&node_id),
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(GraphResponse {
            root_agent_id: id,
            nodes,
            edges: edge_responses,
        }),
    ))
}

// ---------------------------------------------------------------------------
// GET /topology/edges — list all edges (optionally filtered by team)
// ---------------------------------------------------------------------------

/// Query parameters for the topology-wide edge listing endpoint.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct TopologyEdgeListParams {
    /// Return only edges where at least one endpoint belongs to this team.
    #[param(example = "team-alpha")]
    pub team_id: Option<String>,
    /// Maximum number of edges to return. Defaults to 500, capped at 1000.
    #[param(example = 500)]
    pub limit: Option<u32>,
}

/// All edges in the topology graph, optionally filtered by team membership.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopologyEdgeListResponse {
    /// Matching edges, sorted newest-first within each edge type.
    pub edges: Vec<EdgeResponse>,
    /// Total number of edges returned.
    pub count: usize,
}

/// List all topology edges, optionally filtered by team.
///
/// Iterates every known edge type and collects up to `limit` edges total
/// (default 500, max 1 000). When `team_id` is provided, only edges where
/// the source **or** target agent belongs to that team are returned.
#[utoipa::path(
    get,
    path = "/api/v1/topology/edges",
    params(TopologyEdgeListParams),
    responses(
        (status = 200, description = "Edge list", body = TopologyEdgeListResponse),
        (status = 500, description = "Store error", body = ProblemDetail),
    ),
    tag = "topology"
)]
pub async fn list_topology_edges(
    Extension(state): Extension<AppState>,
    Query(params): Query<TopologyEdgeListParams>,
) -> Result<(StatusCode, Json<TopologyEdgeListResponse>), ProblemDetail> {
    let cap = params.limit.unwrap_or(500).min(1000) as usize;
    // Epoch-0 acts as "no lower time bound" — list_by_type returns all records.
    let epoch = DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_default();

    let mut all_edges: Vec<Edge> = Vec::new();
    for &et in EdgeType::ALL {
        let batch = state.edge_repo.list_by_type(et, epoch, 1000).await.map_err(|e| {
            ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail(format!("Edge store error: {e}"))
        })?;
        all_edges.extend(batch);
    }

    // Optional team filter: keep edges where source or target belongs to the team.
    let filtered: Vec<Edge> = match &params.team_id {
        Some(tid) => all_edges
            .into_iter()
            .filter(|e| {
                let src_team = state.agent_registry.get(e.source.as_bytes()).and_then(|r| r.team_id);
                let tgt_team = state.agent_registry.get(e.target.as_bytes()).and_then(|r| r.team_id);
                src_team.as_deref() == Some(tid.as_str()) || tgt_team.as_deref() == Some(tid.as_str())
            })
            .collect(),
        None => all_edges,
    };

    // Stable newest-first order across types.
    let mut sorted = filtered;
    sorted.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    sorted.truncate(cap);

    let cross_team_flags = compute_cross_team(&sorted, &state);
    let edges: Vec<EdgeResponse> = sorted
        .iter()
        .zip(cross_team_flags.iter())
        .map(|(e, &ct)| edge_to_response(e, ct))
        .collect();

    let count = edges.len();
    Ok((StatusCode::OK, Json(TopologyEdgeListResponse { edges, count })))
}
