//! Integration tests for the `commands::permissions` module — AAASM-1049 F100
//!
//! Spins up a wiremock server returning a fixture
//! `EffectivePermissionsResponse` and asserts:
//! - the typed wire-shape round-trips through `fetch_effective_permissions`
//! - the comfy-table text rendering contains the expected per-capability rows
//!   with `Granted by` / `Denied by` provenance
//! - the JSON rendering deserialises back into the same response shape with
//!   matching merged + per-source fields

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::commands::permissions::{self, EffectivePermissions};
use aa_cli::output::OutputFormat;

const FIXTURE_AGENT_ID: &str = "aabbccdd00112233aabbccdd00112233";

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

fn fixture_response_json() -> serde_json::Value {
    // Stands in for the AAASM-1049 fixture registry+policy bundle:
    //   global policy: allow {file_read, file_write}
    //   team:platform policy: allow {file_read}, deny {network_outbound}
    // Effective merge: allow={file_read}, deny={network_outbound}.
    serde_json::json!({
        "allow": ["file_read"],
        "deny": ["network_outbound"],
        "sources": [
            {
                "scope": "global",
                "allow": ["file_read", "file_write"],
                "deny": []
            },
            {
                "scope": "team:platform",
                "allow": ["file_read"],
                "deny": ["network_outbound"]
            }
        ]
    })
}

async fn fixture_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{FIXTURE_AGENT_ID}/capabilities")))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture_response_json()))
        .expect(1)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn fetch_returns_typed_response_matching_wire_shape() {
    let server = fixture_server().await;
    let ctx = make_context(&server.uri());

    let perms = permissions::fetch_effective_permissions(&ctx, FIXTURE_AGENT_ID)
        .await
        .expect("fetch should succeed");

    assert_eq!(perms.allow, vec!["file_read"]);
    assert_eq!(perms.deny, vec!["network_outbound"]);
    assert_eq!(perms.sources.len(), 2);
    assert_eq!(perms.sources[0].scope, "global");
    assert_eq!(perms.sources[0].allow, vec!["file_read", "file_write"]);
    assert!(perms.sources[0].deny.is_empty());
    assert_eq!(perms.sources[1].scope, "team:platform");
    assert_eq!(perms.sources[1].allow, vec!["file_read"]);
    assert_eq!(perms.sources[1].deny, vec!["network_outbound"]);
}

#[tokio::test]
async fn text_output_contains_per_capability_rows_with_provenance() {
    let server = fixture_server().await;
    let ctx = make_context(&server.uri());

    let perms = permissions::fetch_effective_permissions(&ctx, FIXTURE_AGENT_ID)
        .await
        .unwrap();

    let mut buf = Vec::new();
    permissions::render_to(&perms, OutputFormat::Table, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    // Header row from comfy-table.
    assert!(out.contains("Capability"), "missing Capability header: {out}");
    assert!(out.contains("Effective"), "missing Effective header: {out}");
    assert!(out.contains("Granted by"), "missing Granted by header: {out}");
    assert!(out.contains("Denied by"), "missing Denied by header: {out}");

    // Every capability that appears in any source should produce a row.
    assert!(out.contains("file_read"), "expected file_read row: {out}");
    assert!(out.contains("file_write"), "expected file_write row: {out}");
    assert!(out.contains("network_outbound"), "expected network_outbound row: {out}");

    // Provenance: file_read is granted by both global and team:platform.
    let read_line = out.lines().find(|l| l.contains("file_read")).expect("file_read row");
    assert!(
        read_line.contains("global"),
        "file_read should show global granter: {read_line}"
    );
    assert!(
        read_line.contains("team:platform"),
        "file_read should show team:platform granter: {read_line}"
    );

    // network_outbound is denied by team:platform.
    let net_line = out
        .lines()
        .find(|l| l.contains("network_outbound"))
        .expect("network_outbound row");
    assert!(
        net_line.contains("team:platform"),
        "network_outbound should show team:platform denier: {net_line}"
    );

    // Effective verdicts.
    assert!(read_line.contains("Allow"), "file_read should be Allow: {read_line}");
    assert!(net_line.contains("Deny"), "network_outbound should be Deny: {net_line}");
}

#[tokio::test]
async fn json_output_round_trips_into_typed_schema() {
    let server = fixture_server().await;
    let ctx = make_context(&server.uri());

    let perms = permissions::fetch_effective_permissions(&ctx, FIXTURE_AGENT_ID)
        .await
        .unwrap();

    let mut buf = Vec::new();
    permissions::render_to(&perms, OutputFormat::Json, &mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();

    // Round-trip back through the typed schema.
    let parsed: EffectivePermissions = serde_json::from_str(&s).expect("rendered JSON should parse");
    assert_eq!(parsed.allow, perms.allow);
    assert_eq!(parsed.deny, perms.deny);
    assert_eq!(parsed.sources.len(), perms.sources.len());
    for (a, b) in parsed.sources.iter().zip(perms.sources.iter()) {
        assert_eq!(a.scope, b.scope);
        assert_eq!(a.allow, b.allow);
        assert_eq!(a.deny, b.deny);
    }
}

#[tokio::test]
async fn fetch_propagates_404_when_agent_unknown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{FIXTURE_AGENT_ID}/capabilities")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let ctx = make_context(&server.uri());
    let err = permissions::fetch_effective_permissions(&ctx, FIXTURE_AGENT_ID)
        .await
        .expect_err("404 should surface as an error");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("not found") || msg.contains("404"),
        "got: {msg}"
    );
}
