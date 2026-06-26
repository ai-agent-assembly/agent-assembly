//! Coverage for the topology render layer (AAASM-3812).
//!
//! The existing `topology.rs` suite drives each subcommand's `run()` in
//! `Table` format only, so the JSON/YAML serialisation arms in
//! `render::json` and several data-dependent table branches were never
//! exercised. Here we:
//!
//! 1. drive every topology shape through `run()` in `Json` *and* `Yaml`
//!    format (the house pattern — wiremock + a dedicated thread for the
//!    per-command tokio runtime), covering `render_json` / `render_yaml`
//!    for all five `TopologyPayload` variants; and
//! 2. call the pure table/tree render helpers directly with branch-covering
//!    data (standalone roots, root lineage, an over-60-char delegation
//!    reason that guards the `&r[..60]` slice, populated histograms, nested
//!    children, and the otherwise-unwired `render_lineage_chain`).

use std::process::ExitCode;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::commands::topology::render::{
    self, AgentLineage, AgentNode, AgentTree, LineageStep, TeamSummary, TopologyOverview, TopologyStats,
};
use aa_cli::output::OutputFormat;

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

// ── run() in Json + Yaml for every topology shape ─────────────────────

#[tokio::test]
async fn overview_json_and_yaml_succeed() {
    let body = serde_json::json!({
        "team_count": 1,
        "root_agent_count": 1,
        "total_agent_count": 2,
        "teams": [{"team_id": "team-alpha", "agent_count": 2, "root_agent_count": 1}],
        "standalone_root_agents": []
    });
    for fmt in [OutputFormat::Json, OutputFormat::Yaml] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/topology/overview"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let uri = server.uri();
        let code = std::thread::spawn(move || {
            let args = aa_cli::commands::topology::overview::OverviewArgs {
                status: None,
                show_budget: false,
            };
            aa_cli::commands::topology::overview::run(args, &make_context(&uri), fmt)
        })
        .join()
        .unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    }
}

#[tokio::test]
async fn tree_json_and_yaml_succeed() {
    let root_id = "0102030405060708090a0b0c0d0e0f10";
    let body = serde_json::json!({
        "id": root_id,
        "name": "root-agent",
        "depth": 0,
        "status": "active",
        "team_id": "team-alpha",
        "delegation_reason": null,
        "spawned_by_tool": null,
        "children": []
    });
    for fmt in [OutputFormat::Json, OutputFormat::Yaml] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/topology/tree/{root_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let uri = server.uri();
        let code = std::thread::spawn(move || {
            let args = aa_cli::commands::topology::tree::TreeArgs {
                agent_id: root_id.to_string(),
                depth: None,
                status: None,
                show_budget: false,
            };
            aa_cli::commands::topology::tree::run(args, &make_context(&uri), fmt)
        })
        .join()
        .unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    }
}

#[tokio::test]
async fn team_json_and_yaml_succeed() {
    let body = serde_json::json!({
        "team_id": "team-alpha",
        "agent_count": 1,
        "members": [
            {"id": "aabb", "name": "agent-1", "depth": 0, "status": "active", "team_id": "team-alpha"}
        ]
    });
    for fmt in [OutputFormat::Json, OutputFormat::Yaml] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/topology/team/team-alpha"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let uri = server.uri();
        let code = std::thread::spawn(move || {
            let args = aa_cli::commands::topology::team::TeamArgs {
                team_id: "team-alpha".to_string(),
                status: None,
                show_budget: false,
            };
            aa_cli::commands::topology::team::run(args, &make_context(&uri), fmt)
        })
        .join()
        .unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    }
}

#[tokio::test]
async fn lineage_json_and_yaml_succeed() {
    let agent_id = "aabbccdd00112233aabbccdd00112233";
    let body = serde_json::json!({
        "agent_id": agent_id,
        "ancestor_count": 1,
        "ancestors": [
            {"id": agent_id, "name": "root", "depth": 0, "delegation_reason": null, "team_id": null}
        ]
    });
    for fmt in [OutputFormat::Json, OutputFormat::Yaml] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/topology/lineage/{agent_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let uri = server.uri();
        let code = std::thread::spawn(move || {
            let args = aa_cli::commands::topology::lineage::LineageArgs {
                agent_id: agent_id.to_string(),
                show_permissions: false,
            };
            aa_cli::commands::topology::lineage::run(args, &make_context(&uri), fmt)
        })
        .join()
        .unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    }
}

#[tokio::test]
async fn stats_json_and_yaml_succeed() {
    let body = serde_json::json!({
        "total_agents": 3,
        "root_agent_count": 1,
        "max_depth": 2,
        "active_count": 3,
        "suspended_count": 0,
        "deregistered_count": 0,
        "team_count": 1,
        "team_sizes": {"team-alpha": 3},
        "depth_histogram": {"0": 1, "1": 2},
        "team_size_histogram": {"3": 1},
        "spawn_count_histogram": {"0": 1},
        "orphan_count": 0,
        "avg_children_per_parent": 1.0
    });
    for fmt in [OutputFormat::Json, OutputFormat::Yaml] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/topology/stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let uri = server.uri();
        let code = std::thread::spawn(move || {
            let args = aa_cli::commands::topology::stats::StatsArgs {};
            aa_cli::commands::topology::stats::run(args, &make_context(&uri), fmt)
        })
        .join()
        .unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    }
}

// ── pure render helpers: branch coverage via direct calls ─────────────

fn node(id: &str, name: &str, status: &str, team: Option<&str>) -> AgentNode {
    AgentNode {
        id: id.to_string(),
        name: name.to_string(),
        depth: 0,
        status: status.to_string(),
        team_id: team.map(str::to_string),
        governance_level: None,
    }
}

/// The overview table's "standalone root agents" block is only reached when
/// `standalone_root_agents` is non-empty — the wiremock suite always sends an
/// empty list, so cover it here.
#[test]
fn overview_table_renders_standalone_root_agents() {
    let overview = TopologyOverview {
        team_count: 1,
        root_agent_count: 2,
        total_agent_count: 3,
        teams: vec![TeamSummary {
            team_id: "team-alpha".to_string(),
            agent_count: 2,
            root_agent_count: 1,
        }],
        standalone_root_agents: vec![
            node("dead", "loner-1", "active", None),
            node("beef", "loner-2", "deregistered", Some("team-x")),
        ],
    };
    // Renders both the team table and the standalone-agents table without panic.
    render::table::render_overview_table(&overview);
}

/// A single depth-0 ancestor triggers the "(this is a root agent)" footer; an
/// over-60-char delegation reason exercises the `&r[..60]` truncation slice (a
/// panic risk if the boundary logic were wrong).
#[test]
fn lineage_table_handles_root_and_long_reason() {
    let root = AgentLineage {
        agent_id: "root0000000000000000000000000000".to_string(),
        ancestor_count: 1,
        ancestors: vec![LineageStep {
            id: "root0000000000000000000000000000".to_string(),
            name: "root".to_string(),
            depth: 0,
            delegation_reason: None,
            team_id: None,
        }],
    };
    render::table::render_lineage_table(&root);

    let long_reason = "x".repeat(120);
    let chain = AgentLineage {
        agent_id: "child".to_string(),
        ancestor_count: 2,
        ancestors: vec![
            LineageStep {
                id: "root".to_string(),
                name: "root".to_string(),
                depth: 0,
                delegation_reason: None,
                team_id: Some("team-alpha".to_string()),
            },
            LineageStep {
                id: "child".to_string(),
                name: "child".to_string(),
                depth: 1,
                delegation_reason: Some(long_reason),
                team_id: None,
            },
        ],
    };
    render::table::render_lineage_table(&chain);
}

/// An empty-ancestry lineage takes the "No ancestry data." early return.
#[test]
fn lineage_table_handles_empty_ancestry() {
    let empty = AgentLineage {
        agent_id: "ghost".to_string(),
        ancestor_count: 0,
        ancestors: vec![],
    };
    render::table::render_lineage_table(&empty);
}

/// Populated depth and team-size histograms exercise the two optional
/// histogram blocks in the stats table.
#[test]
fn stats_table_renders_histograms() {
    use std::collections::{BTreeMap, HashMap};
    let mut team_sizes = HashMap::new();
    team_sizes.insert("team-alpha".to_string(), 5usize);
    let mut depth_histogram = BTreeMap::new();
    depth_histogram.insert("0".to_string(), 1u32);
    depth_histogram.insert("1".to_string(), 4u32);
    let mut team_size_histogram = BTreeMap::new();
    team_size_histogram.insert("5".to_string(), 1u32);
    let stats = TopologyStats {
        total_agents: 5,
        root_agent_count: 1,
        max_depth: 1,
        active_count: 4,
        suspended_count: 1,
        deregistered_count: 0,
        team_count: 1,
        team_sizes,
        depth_histogram,
        team_size_histogram,
        spawn_count_histogram: BTreeMap::new(),
        orphan_count: 0,
        avg_children_per_parent: 4.0,
    };
    render::table::render_stats_table(&stats);
}

fn tree_node(name: &str, team: Option<&str>, children: Vec<AgentTree>) -> AgentTree {
    AgentTree {
        id: format!("id-{name}"),
        name: name.to_string(),
        depth: 0,
        status: "active".to_string(),
        team_id: team.map(str::to_string),
        delegation_reason: None,
        spawned_by_tool: None,
        governance_level: None,
        children,
    }
}

/// Nested children and a `None` team_id cover the recursion and the empty
/// `team_tag` branch of `render_agent_tree`.
#[test]
fn agent_tree_renders_nested_children() {
    let tree = tree_node(
        "root",
        Some("team-alpha"),
        vec![
            tree_node("child-a", None, vec![tree_node("grandchild", None, vec![])]),
            tree_node("child-b", Some("team-beta"), vec![]),
        ],
    );
    render::tree::render_agent_tree(&tree, "", true);
}

/// `render_lineage_chain` is a public helper that the `render()` dispatcher
/// does not wire up (lineage Table uses the flat table form), so it has no
/// other caller. Exercise both the `Some`/`None` delegation-reason arms.
#[test]
fn lineage_chain_renders_with_and_without_reason() {
    let lineage = AgentLineage {
        agent_id: "child".to_string(),
        ancestor_count: 2,
        ancestors: vec![
            LineageStep {
                id: "root".to_string(),
                name: "root".to_string(),
                depth: 0,
                delegation_reason: None,
                team_id: None,
            },
            LineageStep {
                id: "child".to_string(),
                name: "child".to_string(),
                depth: 1,
                delegation_reason: Some("orchestrate".to_string()),
                team_id: Some("team-alpha".to_string()),
            },
        ],
    };
    render::tree::render_lineage_chain(&lineage);
}
