//! Tree renderer for session traces using box-drawing characters.

use colored::Colorize;

use super::models::{SessionTrace, TraceEvent, TraceEventKind};
use crate::sanitize::sanitize_terminal;

/// Format a duration in milliseconds into a human-readable string.
///
/// Examples: `0ms`, `142ms`, `1200ms`, `60000ms`.
pub fn format_duration(duration_ms: u64) -> String {
    format!("{duration_ms}ms")
}

/// Return the icon for a given event kind.
fn event_icon(kind: &TraceEventKind) -> &'static str {
    match kind {
        TraceEventKind::Llm => "●  LLM",
        TraceEventKind::ToolCall => "●  TOOL",
        TraceEventKind::ToolResult => "←  RESULT",
        TraceEventKind::PolicyAllow => "✅ ALLOW",
        TraceEventKind::PolicyDeny => "❌ DENY",
    }
}

/// Render a single event as a one-line string (without tree prefix).
///
/// Policy denials are highlighted in red with the violation reason appended.
pub fn render_event_line(event: &TraceEvent) -> String {
    // label and violation_reason are server-supplied; strip terminal escapes.
    let line = format!(
        "{} {}  {}",
        event_icon(&event.kind),
        sanitize_terminal(&event.label),
        format_duration(event.duration_ms),
    );

    if event.kind == TraceEventKind::PolicyDeny {
        let reason = sanitize_terminal(event.violation_reason.as_deref().unwrap_or("no reason provided"));
        format!("{}", format!("{line}  ({reason})").red())
    } else {
        line
    }
}

/// Recursively render a list of events as a tree with box-drawing prefixes.
///
/// `prefix` is the indentation string inherited from the parent level.
fn render_tree_recursive(events: &[TraceEvent], prefix: &str, output: &mut String) {
    let count = events.len();
    for (i, event) in events.iter().enumerate() {
        let is_last = i == count - 1;
        let connector = if is_last { "└─ " } else { "├─ " };
        let child_prefix = if is_last {
            format!("{prefix}   ")
        } else {
            format!("{prefix}│  ")
        };

        output.push_str(prefix);
        output.push_str(connector);
        output.push_str(&render_event_line(event));
        output.push('\n');

        if !event.children.is_empty() {
            render_tree_recursive(&event.children, &child_prefix, output);
        }
    }
}

/// Render a full session trace as an indented tree with box-drawing characters.
pub fn render_tree(trace: &SessionTrace) -> String {
    let mut output = format!("Trace: {}\n", sanitize_terminal(&trace.session_id));
    render_tree_recursive(&trace.events, "", &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_duration_zero() {
        assert_eq!(format_duration(0), "0ms");
    }

    #[test]
    fn format_duration_typical() {
        assert_eq!(format_duration(142), "142ms");
    }

    #[test]
    fn format_duration_large() {
        assert_eq!(format_duration(60000), "60000ms");
    }

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
    fn render_event_line_llm() {
        let event = make_event(TraceEventKind::Llm, "GPT-4o", 834);
        let line = render_event_line(&event);
        assert!(line.contains("LLM"));
        assert!(line.contains("GPT-4o"));
        assert!(line.contains("834ms"));
    }

    #[test]
    fn render_event_line_tool_call() {
        let event = make_event(TraceEventKind::ToolCall, "query_db", 12);
        let line = render_event_line(&event);
        assert!(line.contains("TOOL"));
        assert!(line.contains("query_db"));
        assert!(line.contains("12ms"));
    }

    #[test]
    fn render_tree_nested_events() {
        let trace = SessionTrace {
            session_id: "sess-001".to_string(),
            events: vec![TraceEvent {
                kind: TraceEventKind::Llm,
                label: "GPT-4o".to_string(),
                duration_ms: 834,
                children: vec![
                    make_event(TraceEventKind::ToolCall, "query_db", 12),
                    make_event(TraceEventKind::ToolResult, "3 records", 0),
                ],
                violation_reason: None,
            }],
        };
        let output = render_tree(&trace);
        assert!(output.contains("Trace: sess-001"));
        // Root uses └─ (only one root event)
        assert!(output.contains("└─"));
        // Children use ├─ and └─
        assert!(output.contains("├─"));
        assert!(output.contains("query_db"));
        assert!(output.contains("3 records"));
    }

    #[test]
    fn render_event_line_policy_deny_includes_reason() {
        // Force color output so ANSI codes are emitted regardless of TTY.
        colored::control::set_override(true);

        let event = TraceEvent {
            kind: TraceEventKind::PolicyDeny,
            label: "process_refund".to_string(),
            duration_ms: 1,
            children: vec![],
            violation_reason: Some("amount exceeds limit".to_string()),
        };
        let line = render_event_line(&event);
        assert!(line.contains("amount exceeds limit"));
        assert!(line.contains("DENY"));
        // ANSI red escape code
        assert!(line.contains("\x1b[31m"));

        colored::control::unset_override();
    }

    #[test]
    fn render_event_line_policy_deny_default_reason() {
        let event = TraceEvent {
            kind: TraceEventKind::PolicyDeny,
            label: "send_email".to_string(),
            duration_ms: 0,
            children: vec![],
            violation_reason: None,
        };
        let line = render_event_line(&event);
        assert!(line.contains("no reason provided"));
    }

    #[test]
    fn render_event_line_strips_server_supplied_escapes() {
        let event = TraceEvent {
            kind: TraceEventKind::ToolCall,
            // A malicious agent embeds a CSI clear-line in the operation label.
            label: "query\x1b[2K_db".to_string(),
            duration_ms: 5,
            children: vec![],
            violation_reason: None,
        };
        let line = render_event_line(&event);
        assert!(!line.contains('\x1b'), "no ESC must survive: {line:?}");
        assert!(line.contains("query_db"));
    }

    #[test]
    fn render_tree_strips_escapes_from_session_id() {
        let trace = SessionTrace {
            session_id: "sess\x1b]52;c;ZXZpbA==\x07-1".to_string(),
            events: vec![],
        };
        let output = render_tree(&trace);
        assert!(!output.contains('\x1b'), "no ESC must survive: {output:?}");
        assert!(output.contains("Trace: sess-1"));
    }

    #[test]
    fn render_tree_single_event_no_children() {
        let trace = SessionTrace {
            session_id: "sess-solo".to_string(),
            events: vec![make_event(TraceEventKind::Llm, "Claude", 500)],
        };
        let output = render_tree(&trace);
        assert!(output.contains("Trace: sess-solo"));
        assert!(output.contains("└─"));
        assert!(output.contains("Claude"));
        assert!(output.contains("500ms"));
        // No child connectors
        assert!(!output.contains("├─"));
    }
}
