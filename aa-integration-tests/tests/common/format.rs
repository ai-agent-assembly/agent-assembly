//! Output-format helpers for CLI integration tests (AAASM-1449 / F121 ST-0).
//!
//! Parses `aasm` stdout in each `--output` format (json / yaml / table) and
//! asserts cross-format equivalence — every leaf with `--output` support
//! should produce the same logical record set regardless of format.
//!
//! ## Scope
//!
//! * `parse_json` / `parse_yaml` — full document parsers; panic on invalid
//!   input with the stdout dumped for debugging.
//! * `parse_table_rows` — whitespace-tokenized row parser. Adequate for the
//!   simple ID-column tables `aasm` emits today; intentionally lossy on
//!   multi-word column values (callers should assert via `contains` rather
//!   than per-cell equality for those).
//! * `assert_equivalent_records` — JSON-vs-YAML structural equivalence
//!   asserter for collection endpoints. Table is checked separately via
//!   `table_contains_value` because table parsing is approximate.

/// Parse `aasm`'s stdout as a single JSON document. Panics with the stdout
/// dumped if parsing fails.
pub fn parse_json(stdout: &[u8]) -> serde_json::Value {
    serde_json::from_slice(stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not valid JSON: {e}\nstdout:\n{}",
            String::from_utf8_lossy(stdout)
        )
    })
}

/// Parse `aasm`'s stdout as a single YAML document. Panics with the stdout
/// dumped if parsing fails.
pub fn parse_yaml(stdout: &[u8]) -> serde_yaml::Value {
    serde_yaml::from_slice(stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not valid YAML: {e}\nstdout:\n{}",
            String::from_utf8_lossy(stdout)
        )
    })
}

/// Parse a printed table into rows of whitespace-separated cells.
///
/// * Skips empty lines and divider-only lines (`---`, `═══`, `===`, etc.).
/// * Splits each remaining line on runs of whitespace via
///   [`str::split_whitespace`]. Multi-word column values will be split
///   into adjacent cells — callers that need cell-accurate assertions
///   should parse table output some other way (or call `parse_json`
///   instead and compare structurally).
pub fn parse_table_rows(stdout: &[u8]) -> Vec<Vec<String>> {
    let text = String::from_utf8_lossy(stdout);
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            // Skip divider lines (─, =, -, |, +, whitespace only).
            if trimmed
                .chars()
                .all(|c| matches!(c, '-' | '=' | '|' | '+' | '─' | '═' | '╪' | '┼') || c.is_whitespace())
            {
                return None;
            }
            Some(trimmed.split_whitespace().map(String::from).collect::<Vec<_>>())
        })
        .collect()
}

/// Returns `true` if any cell in the table output exactly equals `value`.
pub fn table_contains_value(stdout: &[u8], value: &str) -> bool {
    parse_table_rows(stdout)
        .into_iter()
        .any(|row| row.iter().any(|cell| cell == value))
}

/// Asserts the JSON and YAML representations describe the same record set —
/// same count, same set of `id_field` values (order-independent).
///
/// `id_field` is the JSON key / YAML key that uniquely identifies each
/// record (e.g. `"agent_id"`, `"id"`, `"name"`). The function handles
/// three common collection shapes:
///
/// 1. Top-level array: `[{...}, {...}]`
/// 2. Wrapped under `items`: `{"items": [{...}, ...]}`
/// 3. Single record: `{"id": "..."}`
pub fn assert_equivalent_records(json_out: &[u8], yaml_out: &[u8], id_field: &str) {
    let json_v = parse_json(json_out);
    let yaml_v = parse_yaml(yaml_out);

    let mut json_ids = extract_json_ids(&json_v, id_field);
    let mut yaml_ids = extract_yaml_ids(&yaml_v, id_field);
    json_ids.sort();
    yaml_ids.sort();

    assert_eq!(
        json_ids.len(),
        yaml_ids.len(),
        "JSON and YAML record counts diverge (json={} yaml={})\n\
         json stdout:\n{}\nyaml stdout:\n{}",
        json_ids.len(),
        yaml_ids.len(),
        String::from_utf8_lossy(json_out),
        String::from_utf8_lossy(yaml_out),
    );
    assert_eq!(
        json_ids,
        yaml_ids,
        "JSON and YAML record id sets diverge\n\
         json stdout:\n{}\nyaml stdout:\n{}",
        String::from_utf8_lossy(json_out),
        String::from_utf8_lossy(yaml_out),
    );
}

fn extract_json_ids(v: &serde_json::Value, field: &str) -> Vec<String> {
    if let Some(arr) = v.as_array() {
        return arr
            .iter()
            .filter_map(|e| e.get(field).and_then(|x| x.as_str()).map(String::from))
            .collect();
    }
    if let Some(items) = v.get("items").and_then(|x| x.as_array()) {
        return items
            .iter()
            .filter_map(|e| e.get(field).and_then(|x| x.as_str()).map(String::from))
            .collect();
    }
    if let Some(s) = v.get(field).and_then(|x| x.as_str()) {
        return vec![s.to_string()];
    }
    vec![]
}

fn extract_yaml_ids(v: &serde_yaml::Value, field: &str) -> Vec<String> {
    if let Some(seq) = v.as_sequence() {
        return seq
            .iter()
            .filter_map(|e| e.get(field).and_then(|x| x.as_str()).map(String::from))
            .collect();
    }
    if let Some(items) = v.get("items").and_then(|x| x.as_sequence()) {
        return items
            .iter()
            .filter_map(|e| e.get(field).and_then(|x| x.as_str()).map(String::from))
            .collect();
    }
    if let Some(s) = v.get(field).and_then(|x| x.as_str()) {
        return vec![s.to_string()];
    }
    vec![]
}
