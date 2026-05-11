//! JSON and YAML serialisation for topology payloads.

use super::TopologyPayload;

/// Render a topology payload as pretty-printed JSON to stdout.
pub fn render_json(payload: &TopologyPayload<'_>) {
    let result = match payload {
        TopologyPayload::Overview(v) => serde_json::to_string_pretty(v),
        TopologyPayload::Tree(v) => serde_json::to_string_pretty(v),
        TopologyPayload::Team(v) => serde_json::to_string_pretty(v),
        TopologyPayload::Lineage(v) => serde_json::to_string_pretty(v),
        TopologyPayload::Stats(v) => serde_json::to_string_pretty(v),
    };
    match result {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing JSON: {e}"),
    }
}
