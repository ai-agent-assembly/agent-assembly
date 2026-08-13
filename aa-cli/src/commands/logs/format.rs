//! Log line formatting and color output for the `aasm logs` command.

use chrono::{DateTime, Utc};
use console::Style;
use serde::{Deserialize, Serialize};

use crate::sanitize::sanitize_terminal;

/// Normalised log entry shared by both fetch (REST) and follow (WS) modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLineData {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Event type label (e.g. `"violation"`).
    pub event_type: String,
    /// Hex-encoded agent identifier.
    pub agent_id: String,
    /// Human-readable message summary.
    pub message: String,
}

/// Format a single log line for human-readable terminal output.
///
/// Output: `<timestamp> [<TYPE>] <agent_id>  <message>`
///
/// When `use_color` is true the type tag is styled according to
/// [`style_for_type`].
pub fn format_log_line(entry: &LogLineData, use_color: bool) -> String {
    // All four fields are server-supplied; strip terminal escapes so a
    // malicious agent cannot inject ANSI/OSC sequences into the operator's
    // terminal. The original `event_type` still drives the colour lookup.
    let timestamp = sanitize_terminal(&entry.timestamp);
    let agent_id = sanitize_terminal(&entry.agent_id);
    let message = sanitize_terminal(&entry.message);
    let tag = format!("[{}]", sanitize_terminal(&entry.event_type).to_uppercase());
    let styled_tag = if use_color {
        let style = style_for_type(&entry.event_type);
        style.apply_to(&tag).to_string()
    } else {
        tag
    };
    format!("{} {:12} {}  {}", timestamp, styled_tag, agent_id, message)
}

/// Format a log entry as a single newline-delimited JSON object.
pub fn format_log_json(entry: &LogLineData) -> String {
    serde_json::to_string(entry).unwrap_or_default()
}

/// Parse a `--since` value into a [`DateTime<Utc>`].
///
/// Accepts either:
/// - A duration shorthand: `30m`, `2h`, `1d` (minutes, hours, days)
/// - An ISO 8601 timestamp: `2026-04-30T10:00:00Z`
///
/// Duration values are resolved relative to the current time.
pub fn parse_since(value: &str) -> Option<DateTime<Utc>> {
    // Try duration shorthand first.
    if let Some(duration) = parse_duration_shorthand(value) {
        return Some(Utc::now() - duration);
    }
    // Fall back to ISO 8601 timestamp.
    value.parse::<DateTime<Utc>>().ok()
}

/// Parse an `--until` value into a [`DateTime<Utc>`].
///
/// Accepts an ISO 8601 timestamp (e.g. `2026-04-30T12:00:00Z`).
pub fn parse_until(value: &str) -> Option<DateTime<Utc>> {
    value.parse::<DateTime<Utc>>().ok()
}

/// Parse a duration shorthand like `30m`, `2h`, `1d` into a [`chrono::Duration`].
fn parse_duration_shorthand(value: &str) -> Option<chrono::Duration> {
    let value = value.trim();
    if value.len() < 2 {
        return None;
    }
    let (num_str, suffix) = value.split_at(value.len() - 1);
    let num: i64 = num_str.parse().ok()?;
    match suffix {
        "s" => Some(chrono::Duration::seconds(num)),
        "m" => Some(chrono::Duration::minutes(num)),
        "h" => Some(chrono::Duration::hours(num)),
        "d" => Some(chrono::Duration::days(num)),
        _ => None,
    }
}

/// Check whether a log entry's timestamp falls within the `--since`/`--until` window.
pub fn is_within_time_range(
    entry_timestamp: &str,
    since: Option<&DateTime<Utc>>,
    until: Option<&DateTime<Utc>>,
) -> bool {
    let entry_dt = match entry_timestamp.parse::<DateTime<Utc>>() {
        Ok(dt) => dt,
        Err(_) => return true, // If we can't parse, include it.
    };
    if let Some(s) = since {
        if entry_dt < *s {
            return false;
        }
    }
    if let Some(u) = until {
        if entry_dt > *u {
            return false;
        }
    }
    true
}

/// Return a [`Style`] for the given event type string.
///
/// Known types get a distinct colour; unknown future types fall back
/// to white so the CLI can display them without a code change.
pub fn style_for_type(event_type: &str) -> Style {
    match event_type {
        "violation" => Style::new().red().bold(),
        "approval" => Style::new().yellow(),
        "budget" => Style::new().cyan(),
        _ => Style::new().white(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_types_get_distinct_styles() {
        // Ensure the function does not panic for each known type.
        let _ = style_for_type("violation");
        let _ = style_for_type("approval");
        let _ = style_for_type("budget");
    }

    #[test]
    fn unknown_type_returns_white_style() {
        let _ = style_for_type("tool_call");
        let _ = style_for_type("unknown_future_type");
    }

    fn sample_entry() -> LogLineData {
        LogLineData {
            timestamp: "2026-04-30T10:00:00Z".to_string(),
            event_type: "violation".to_string(),
            agent_id: "aa001".to_string(),
            message: "policy denied tool call".to_string(),
        }
    }

    #[test]
    fn format_log_line_no_color_contains_all_fields() {
        let line = format_log_line(&sample_entry(), false);
        assert!(line.contains("2026-04-30T10:00:00Z"));
        assert!(line.contains("[VIOLATION]"));
        assert!(line.contains("aa001"));
        assert!(line.contains("policy denied tool call"));
    }

    #[test]
    fn format_log_line_with_color_does_not_panic() {
        let _ = format_log_line(&sample_entry(), true);
    }

    #[test]
    fn format_log_line_strips_server_supplied_escapes() {
        let entry = LogLineData {
            timestamp: "2026-04-30T10:00:00Z".to_string(),
            event_type: "violation".to_string(),
            // A malicious agent embeds a CSI clear-line and an OSC-52 clipboard
            // write in the server-supplied fields.
            agent_id: "a\x1b[2Kfake".to_string(),
            message: "ok\x1b]52;c;ZXZpbA==\x07\ninjected".to_string(),
        };
        let line = format_log_line(&entry, false);
        assert!(!line.contains('\x1b'), "no ESC must survive: {line:?}");
        assert!(!line.contains('\n'), "no newline must survive: {line:?}");
        assert!(line.contains("afake"));
        assert!(line.contains("okinjected"));
    }

    #[test]
    fn format_log_json_produces_valid_json() {
        let json = format_log_json(&sample_entry());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["event_type"], "violation");
        assert_eq!(parsed["agent_id"], "aa001");
    }

    #[test]
    fn parse_since_duration_minutes() {
        let dt = parse_since("30m").unwrap();
        let diff = Utc::now() - dt;
        // Should be approximately 30 minutes (allow 5 sec tolerance).
        assert!((diff.num_seconds() - 1800).abs() < 5);
    }

    #[test]
    fn parse_since_duration_hours() {
        let dt = parse_since("2h").unwrap();
        let diff = Utc::now() - dt;
        assert!((diff.num_seconds() - 7200).abs() < 5);
    }

    #[test]
    fn parse_since_iso_timestamp() {
        let dt = parse_since("2026-04-30T10:00:00Z").unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-04-30T10:00:00+00:00");
    }

    #[test]
    fn parse_since_invalid_returns_none() {
        assert!(parse_since("invalid").is_none());
        assert!(parse_since("").is_none());
    }

    #[test]
    fn parse_until_iso_timestamp() {
        let dt = parse_until("2026-04-30T12:00:00Z").unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-04-30T12:00:00+00:00");
    }

    #[test]
    fn is_within_range_no_bounds() {
        assert!(is_within_time_range("2026-04-30T10:00:00Z", None, None));
    }

    #[test]
    fn is_within_range_since_filter() {
        let since = "2026-04-30T10:00:00Z".parse().unwrap();
        assert!(is_within_time_range("2026-04-30T11:00:00Z", Some(&since), None));
        assert!(!is_within_time_range("2026-04-30T09:00:00Z", Some(&since), None));
    }

    #[test]
    fn is_within_range_until_filter() {
        let until = "2026-04-30T12:00:00Z".parse().unwrap();
        assert!(is_within_time_range("2026-04-30T11:00:00Z", None, Some(&until)));
        assert!(!is_within_time_range("2026-04-30T13:00:00Z", None, Some(&until)));
    }

    #[test]
    fn is_within_range_both_bounds() {
        let since = "2026-04-30T10:00:00Z".parse().unwrap();
        let until = "2026-04-30T12:00:00Z".parse().unwrap();
        assert!(is_within_time_range("2026-04-30T11:00:00Z", Some(&since), Some(&until)));
        assert!(!is_within_time_range(
            "2026-04-30T09:00:00Z",
            Some(&since),
            Some(&until)
        ));
        assert!(!is_within_time_range(
            "2026-04-30T13:00:00Z",
            Some(&since),
            Some(&until)
        ));
    }
}
