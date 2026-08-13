//! Timeline renderer for session traces using ASCII bar charts.

use super::models::{SessionTrace, TraceEvent, TraceEventKind};
use super::tree::format_duration;
use crate::sanitize::sanitize_terminal;

/// Find the maximum duration among a flat list of events.
pub fn compute_max_duration(events: &[TraceEvent]) -> u64 {
    events.iter().map(|e| e.duration_ms).max().unwrap_or(0)
}

/// Render an ASCII bar whose width is proportional to `duration_ms` relative to `max_duration`.
///
/// Returns a string of `█` characters up to `max_width` wide.
pub fn render_bar(duration_ms: u64, max_duration: u64, max_width: usize) -> String {
    if max_duration == 0 {
        return String::new();
    }
    let width = ((duration_ms as f64 / max_duration as f64) * max_width as f64).round() as usize;
    let width = width.max(if duration_ms > 0 { 1 } else { 0 });
    "█".repeat(width)
}

/// Label prefix for timeline rows.
fn timeline_label(event: &TraceEvent) -> String {
    let kind_tag = match event.kind {
        TraceEventKind::Llm => "LLM",
        TraceEventKind::ToolCall => "TOOL",
        TraceEventKind::ToolResult => "RESULT",
        TraceEventKind::PolicyAllow => "ALLOW",
        TraceEventKind::PolicyDeny => "DENY",
    };
    // event.label is server-supplied; strip terminal escapes.
    format!("{kind_tag:<6} {:<20}", sanitize_terminal(&event.label))
}

/// Render one row of the timeline: label | bar | duration.
pub fn render_timeline_row(event: &TraceEvent, max_duration: u64, bar_width: usize) -> String {
    let label = timeline_label(event);
    let bar = render_bar(event.duration_ms, max_duration, bar_width);
    format!("{label} {bar:<bar_width$}  {}", format_duration(event.duration_ms))
}

/// Flatten a trace tree into a depth-first list of events (ignoring nesting).
fn flatten_events(events: &[TraceEvent]) -> Vec<&TraceEvent> {
    let mut flat = Vec::new();
    for event in events {
        flat.push(event);
        flat.extend(flatten_events(&event.children));
    }
    flat
}

/// Render a full session trace as a horizontal ASCII timeline.
///
/// `max_width` controls the total line width (default 80).
pub fn render_timeline(trace: &SessionTrace, max_width: usize) -> String {
    let mut output = format!("Timeline: {}\n", sanitize_terminal(&trace.session_id));

    let flat = flatten_events(&trace.events);
    if flat.is_empty() {
        output.push_str("(no events)\n");
        return output;
    }

    let max_duration = compute_max_duration(&flat.iter().map(|e| (*e).clone()).collect::<Vec<_>>());
    // Reserve ~30 chars for label, ~10 for duration suffix
    let bar_width = max_width.saturating_sub(40);

    for event in &flat {
        output.push_str(&render_timeline_row(event, max_duration, bar_width));
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(kind: TraceEventKind, label: &str, duration_ms: u64) -> TraceEvent {
        TraceEvent {
            kind,
            label: label.to_string(),
            duration_ms,
            children: vec![],
            violation_reason: None,
        }
    }

    #[test]
    fn compute_max_duration_returns_largest() {
        let events = vec![
            make_event(TraceEventKind::Llm, "a", 100),
            make_event(TraceEventKind::ToolCall, "b", 500),
            make_event(TraceEventKind::ToolResult, "c", 200),
        ];
        assert_eq!(compute_max_duration(&events), 500);
    }

    #[test]
    fn compute_max_duration_empty() {
        assert_eq!(compute_max_duration(&[]), 0);
    }

    #[test]
    fn render_bar_full_width_for_max_duration() {
        let bar = render_bar(1000, 1000, 40);
        // Full bar = 40 block characters
        assert_eq!(bar.chars().count(), 40);
    }

    #[test]
    fn render_bar_half_width() {
        let bar = render_bar(500, 1000, 40);
        assert_eq!(bar.chars().count(), 20);
    }

    #[test]
    fn render_bar_minimum_one_for_nonzero() {
        let bar = render_bar(1, 10000, 40);
        assert!(bar.chars().count() >= 1);
    }

    #[test]
    fn render_bar_zero_duration() {
        let bar = render_bar(0, 1000, 40);
        assert_eq!(bar.chars().count(), 0);
    }

    #[test]
    fn render_bar_zero_max_returns_empty() {
        let bar = render_bar(100, 0, 40);
        assert!(bar.is_empty());
    }

    #[test]
    fn render_timeline_fits_80_columns() {
        let trace = SessionTrace {
            session_id: "sess-80".to_string(),
            events: vec![
                make_event(TraceEventKind::Llm, "GPT-4o", 834),
                make_event(TraceEventKind::ToolCall, "query_db", 12),
                make_event(TraceEventKind::ToolResult, "3 records", 0),
            ],
        };
        let output = render_timeline(&trace, 80);
        for line in output.lines() {
            // Use char count (display width) — not byte len, since █ is multi-byte.
            let char_count = line.chars().count();
            assert!(char_count <= 80, "line exceeds 80 columns ({char_count} chars): {line}",);
        }
    }

    #[test]
    fn render_timeline_empty_trace() {
        let trace = SessionTrace {
            session_id: "sess-empty".to_string(),
            events: vec![],
        };
        let output = render_timeline(&trace, 80);
        assert!(output.contains("Timeline: sess-empty"));
        assert!(output.contains("(no events)"));
    }
}
