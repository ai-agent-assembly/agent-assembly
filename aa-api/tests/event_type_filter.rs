//! Tests for EventType::parse_filter and event filtering logic.

use aa_api::models::EventType;

#[test]
fn parse_filter_none_returns_all_types() {
    let types = EventType::parse_filter(None);
    assert_eq!(types.len(), 4);
    assert!(types.contains(&EventType::Violation));
    assert!(types.contains(&EventType::Approval));
    assert!(types.contains(&EventType::Budget));
    assert!(types.contains(&EventType::OpsChange));
}

#[test]
fn parse_filter_empty_string_returns_all_types() {
    let types = EventType::parse_filter(Some(""));
    assert_eq!(types.len(), 4);
}

#[test]
fn parse_filter_single_type() {
    let types = EventType::parse_filter(Some("violation"));
    assert_eq!(types, vec![EventType::Violation]);
}

#[test]
fn parse_filter_multiple_types() {
    let types = EventType::parse_filter(Some("violation,budget"));
    assert_eq!(types.len(), 2);
    assert!(types.contains(&EventType::Violation));
    assert!(types.contains(&EventType::Budget));
}

#[test]
fn parse_filter_ignores_unknown_types() {
    let types = EventType::parse_filter(Some("violation,unknown,budget"));
    assert_eq!(types.len(), 2);
    assert!(types.contains(&EventType::Violation));
    assert!(types.contains(&EventType::Budget));
}

#[test]
fn parse_filter_trims_whitespace() {
    let types = EventType::parse_filter(Some(" approval , budget "));
    assert_eq!(types.len(), 2);
    assert!(types.contains(&EventType::Approval));
    assert!(types.contains(&EventType::Budget));
}

#[test]
fn event_type_serializes_to_snake_case() {
    let json = serde_json::to_string(&EventType::Violation).unwrap();
    assert_eq!(json, "\"violation\"");

    let json = serde_json::to_string(&EventType::Approval).unwrap();
    assert_eq!(json, "\"approval\"");

    let json = serde_json::to_string(&EventType::Budget).unwrap();
    assert_eq!(json, "\"budget\"");
}
