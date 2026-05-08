//! TUI rendering — draws the 4-panel dashboard layout.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Gauge, List, ListItem, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::commands::approvals::models::{compute_timeout_color, format_countdown, TimeoutColor};

use super::state::{DashboardState, Panel};

/// Approval timeout in seconds (5 minutes, matching `approvals watch`).
const APPROVAL_TIMEOUT_SECS: i64 = 300;

/// Render the entire dashboard UI to the terminal frame.
pub fn draw(f: &mut Frame, state: &DashboardState) {
    let size = f.area();

    // Split vertically: top half and bottom half, plus a 1-line footer.
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
            Constraint::Min(1),
        ])
        .split(size);

    // Top: Agents (left) | Event Log (right)
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(outer[0]);

    // Bottom: Budget (left) | Approvals (right)
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(outer[1]);

    draw_agents_panel(f, top[0], state);
    draw_event_log_panel(f, top[1], state);
    draw_budget_panel(f, bottom[0], state);
    draw_approvals_panel(f, bottom[1], state);
    draw_footer(f, outer[2], state);

    if state.show_help {
        draw_help_overlay(f, size);
    }
    if state.show_inspect {
        draw_inspect_overlay(f, state);
    }
    if state.show_policy {
        draw_policy_overlay(f, state);
    }
}

/// Build a Block with a highlighted border when the panel is focused.
fn panel_block(title: &str, panel: Panel, state: &DashboardState) -> Block<'static> {
    let is_active = state.active_panel == panel;
    let border_style = if is_active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Block::default()
        .title(format!(" {title} "))
        .borders(Borders::ALL)
        .border_style(border_style)
}

/// Top-left: runtime health header + agents table.
fn draw_agents_panel(f: &mut Frame, area: Rect, state: &DashboardState) {
    let block = panel_block("Agents", Panel::Agents, state);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Reserve 2 lines for the health header.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(1)])
        .split(inner);

    // Health header line.
    let status_indicator = if state.runtime.reachable { "●" } else { "○" };
    let status_color = if state.runtime.reachable {
        Color::Green
    } else {
        Color::Red
    };
    let uptime = format_duration(state.runtime.uptime_secs);
    let header_line = Line::from(vec![
        Span::styled(format!("{status_indicator} "), Style::default().fg(status_color)),
        Span::raw(format!(
            "{} | up {} | {} conns | lag {}ms",
            state.runtime.status, uptime, state.runtime.active_connections, state.runtime.pipeline_lag_ms,
        )),
    ]);
    f.render_widget(Paragraph::new(header_line), chunks[0]);

    // Agents table.
    let header = Row::new(vec!["ID", "NAME", "STATUS", "FW", "SESS", "LAST EVT", "VIOL", "LAYER"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(0);

    let rows: Vec<Row> = state
        .agents
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let is_selected = i == state.agent_selected;
            let status_style = match a.status.as_str() {
                "Running" | "Active" => Style::default().fg(Color::Green),
                "Error" | "Failed" => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Yellow),
            };
            let row = Row::new(vec![
                Cell::from(truncate(&a.id, 8)),
                Cell::from(a.name.as_str()),
                Cell::from(a.status.as_str()).style(status_style),
                Cell::from(a.framework.as_str()),
                Cell::from(a.sessions.to_string()),
                Cell::from(a.last_event.as_str()),
                Cell::from(a.violations_today.to_string()),
                Cell::from(a.layer.as_str()),
            ]);
            if is_selected {
                row.style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            }
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Min(10),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Length(20),
            Constraint::Length(5),
            Constraint::Length(8),
        ],
    )
    .header(header);

    f.render_widget(table, chunks[1]);
}

/// Top-right: scrollable event log from the WebSocket stream.
fn draw_event_log_panel(f: &mut Frame, area: Rect, state: &DashboardState) {
    let block = panel_block("Event Log", Panel::EventLog, state);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let items: Vec<ListItem> = state
        .event_log
        .iter()
        .rev()
        .map(|e| {
            let type_color = match e.event_type.as_str() {
                "violation" => Color::Red,
                "approval" => Color::Yellow,
                "budget" => Color::Magenta,
                _ => Color::White,
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{}] ", short_timestamp(&e.timestamp)),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(format!("{:<10} ", e.event_type), Style::default().fg(type_color)),
                Span::raw(&e.message),
            ]))
        })
        .collect();

    let list = List::new(items);
    f.render_widget(list, inner);
}

/// Bottom-right: pending approval requests with countdown timers and selection highlight.
fn draw_approvals_panel(f: &mut Frame, area: Rect, state: &DashboardState) {
    let title = format!("Approvals ({} pending)", state.approvals_summary.pending_count);
    let block = panel_block(&title, Panel::Approvals, state);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.pending_approvals.is_empty() {
        let msg = Paragraph::new("No pending approvals").style(Style::default().fg(Color::DarkGray));
        f.render_widget(msg, inner);
        return;
    }

    let now = chrono::Utc::now().timestamp();

    let items: Vec<ListItem> = state
        .pending_approvals
        .iter()
        .enumerate()
        .map(|(i, ap)| {
            let style = if i == state.approval_selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Compute countdown timer.
            let submitted = chrono::DateTime::parse_from_rfc3339(&ap.created_at)
                .map(|dt| dt.timestamp())
                .unwrap_or(0);
            let remaining = (submitted + APPROVAL_TIMEOUT_SECS) - now;
            let countdown = format_countdown(remaining);
            let countdown_color = match compute_timeout_color(remaining) {
                TimeoutColor::Red => Color::Red,
                TimeoutColor::Yellow => Color::Yellow,
                TimeoutColor::Green => Color::Green,
            };

            let routing_label = if !ap.routing_status.is_empty() {
                format!(" [{}]", ap.routing_status)
            } else {
                String::new()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{countdown:<8} "), Style::default().fg(countdown_color)),
                Span::raw(format!("{} — {}{}", ap.agent_id, ap.action, routing_label)),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items);
    f.render_widget(list, inner);
}

/// Bottom-left: budget utilization bars per agent.
fn draw_budget_panel(f: &mut Frame, area: Rect, state: &DashboardState) {
    let block = panel_block("Budget", Panel::Budget, state);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let agent_count = state.budget.per_agent.len();
    // Reserve 3 lines for the total gauge, then 1 line per agent bar.
    let mut constraints: Vec<Constraint> = vec![Constraint::Length(3)];
    for _ in 0..agent_count {
        constraints.push(Constraint::Length(1));
    }
    constraints.push(Constraint::Min(0)); // absorb remaining space
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    // Total daily spend gauge.
    let (ratio, label) = compute_budget_ratio(state);
    let gauge_color = if ratio > 0.9 {
        Color::Red
    } else if ratio > 0.7 {
        Color::Yellow
    } else {
        Color::Green
    };
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(gauge_color))
        .ratio(ratio)
        .label(label);
    f.render_widget(gauge, chunks[0]);

    // Per-agent utilization bars.
    let daily_limit: f64 = state
        .budget
        .daily_limit_usd
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    for (i, entry) in state.budget.per_agent.iter().enumerate() {
        let spend: f64 = entry.daily_spend_usd.parse().unwrap_or(0.0);
        let agent_ratio = if daily_limit > 0.0 {
            (spend / daily_limit).min(1.0)
        } else {
            0.0
        };
        let bar_width = chunks[1 + i].width.saturating_sub(2) as usize; // leave margins
        let filled = ((agent_ratio * bar_width as f64) as usize).min(bar_width);
        let empty = bar_width.saturating_sub(filled);
        let bar_color = if agent_ratio > 0.5 { Color::Yellow } else { Color::Green };
        let label = format!("{:<8} ", truncate(&entry.agent_id, 8));
        let bar_line = Line::from(vec![
            Span::raw(label),
            Span::styled("█".repeat(filled), Style::default().fg(bar_color)),
            Span::styled("░".repeat(empty), Style::default().fg(Color::DarkGray)),
            Span::raw(format!(" ${}", entry.daily_spend_usd)),
        ]);
        f.render_widget(Paragraph::new(bar_line), chunks[1 + i]);
    }
}

/// Footer bar with keyboard shortcuts.
fn draw_footer(f: &mut Frame, area: Rect, _state: &DashboardState) {
    let footer = Line::from(vec![
        Span::styled(" Tab", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" panel  "),
        Span::styled("↑↓", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" scroll  "),
        Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" inspect  "),
        Span::styled("a", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("/"),
        Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" approve/reject  "),
        Span::styled("p", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" policy  "),
        Span::styled("?", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" help  "),
        Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" quit"),
    ]);
    f.render_widget(Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)), area);
}

/// Render a centered help overlay listing all keyboard shortcuts.
fn draw_help_overlay(f: &mut Frame, area: Rect) {
    let overlay = centered_rect(60, 60, area);
    f.render_widget(Clear, overlay);

    let block = Block::default()
        .title(" Help — Keyboard Shortcuts ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(overlay);
    f.render_widget(block, overlay);

    let lines = vec![
        Line::from(vec![
            Span::styled("Tab      ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Next panel"),
        ]),
        Line::from(vec![
            Span::styled("Shift+Tab", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Previous panel"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("↑ / k    ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Scroll up / select previous"),
        ]),
        Line::from(vec![
            Span::styled("↓ / j    ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Scroll down / select next"),
        ]),
        Line::from(vec![
            Span::styled("Enter    ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Inspect selected agent/approval"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("a        ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Approve selected request"),
        ]),
        Line::from(vec![
            Span::styled("r        ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Reject selected request"),
        ]),
        Line::from(vec![
            Span::styled("p        ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("View active policy"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("?        ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Toggle this help overlay"),
        ]),
        Line::from(vec![
            Span::styled("q / Esc  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Quit dashboard"),
        ]),
    ];

    let help = Paragraph::new(lines);
    f.render_widget(help, inner);
}

/// Render a centered inspect overlay showing details of the selected agent or approval.
pub fn draw_inspect_overlay(f: &mut Frame, state: &DashboardState) {
    let area = f.area();
    let overlay = centered_rect(70, 60, area);
    f.render_widget(Clear, overlay);

    match state.active_panel {
        Panel::Agents => {
            let block = Block::default()
                .title(" Agent Detail ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan));
            let inner = block.inner(overlay);
            f.render_widget(block, overlay);

            if let Some(agent) = state.agents.get(state.agent_selected) {
                let lines = vec![
                    Line::from(vec![
                        Span::styled("ID:          ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&agent.id),
                    ]),
                    Line::from(vec![
                        Span::styled("Name:        ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&agent.name),
                    ]),
                    Line::from(vec![
                        Span::styled("Framework:   ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&agent.framework),
                    ]),
                    Line::from(vec![
                        Span::styled("Status:      ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::styled(
                            &agent.status,
                            match agent.status.as_str() {
                                "Running" | "Active" => Style::default().fg(Color::Green),
                                "Error" | "Failed" => Style::default().fg(Color::Red),
                                _ => Style::default().fg(Color::Yellow),
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Sessions:    ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(agent.sessions.to_string()),
                    ]),
                    Line::from(vec![
                        Span::styled("Violations:  ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(agent.violations_today.to_string()),
                    ]),
                    Line::from(vec![
                        Span::styled("Layer:       ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&agent.layer),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled("Press Esc to close", Style::default().fg(Color::DarkGray))),
                ];
                f.render_widget(Paragraph::new(lines), inner);
            }
        }
        Panel::Approvals => {
            let block = Block::default()
                .title(" Approval Detail ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan));
            let inner = block.inner(overlay);
            f.render_widget(block, overlay);

            if let Some(ap) = state.pending_approvals.get(state.approval_selected) {
                let team_display = if ap.team_id.is_empty() { "(none)".to_string() } else { ap.team_id.clone() };
                let routing_display = if ap.routing_status.is_empty() { "(unknown)".to_string() } else { ap.routing_status.clone() };
                let lines = vec![
                    Line::from(vec![
                        Span::styled("ID:          ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&ap.id),
                    ]),
                    Line::from(vec![
                        Span::styled("Agent:       ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&ap.agent_id),
                    ]),
                    Line::from(vec![
                        Span::styled("Action:      ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&ap.action),
                    ]),
                    Line::from(vec![
                        Span::styled("Reason:      ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&ap.reason),
                    ]),
                    Line::from(vec![
                        Span::styled("Status:      ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&ap.status),
                    ]),
                    Line::from(vec![
                        Span::styled("Team:        ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::styled(team_display, Style::default().fg(Color::Cyan)),
                    ]),
                    Line::from(vec![
                        Span::styled("Routing:     ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::styled(routing_display, Style::default().fg(Color::Yellow)),
                    ]),
                    Line::from(vec![
                        Span::styled("Created:     ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(&ap.created_at),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled("Press Esc to close", Style::default().fg(Color::DarkGray))),
                ];
                f.render_widget(Paragraph::new(lines), inner);
            }
        }
        _ => {
            // No inspect for EventLog or Budget panels.
        }
    }
}

/// Render a centered policy viewer overlay showing policy YAML content.
pub fn draw_policy_overlay(f: &mut Frame, state: &DashboardState) {
    let area = f.area();
    let overlay = centered_rect(75, 80, area);
    f.render_widget(Clear, overlay);

    let block = Block::default()
        .title(" Policy Viewer ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(overlay);
    f.render_widget(block, overlay);

    let content = match &state.policy_yaml {
        Some(yaml) => yaml.as_str(),
        None => "(loading policy…)",
    };

    let paragraph = Paragraph::new(content).wrap(Wrap { trim: false });
    f.render_widget(paragraph, inner);
}

/// Compute a centered rectangle within `area`.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1]);

    horizontal[1]
}

/// Compute the budget gauge ratio and label string.
fn compute_budget_ratio(state: &DashboardState) -> (f64, String) {
    let spend: f64 = state.budget.daily_spend_usd.parse().unwrap_or(0.0);

    let limit: Option<f64> = state.budget.daily_limit_usd.as_deref().and_then(|s| s.parse().ok());

    match limit {
        Some(lim) if lim > 0.0 => {
            let ratio = (spend / lim).min(1.0);
            (ratio, format!("${spend:.2} / ${lim:.2}"))
        }
        _ => (0.0, format!("${spend:.2} (no limit set)")),
    }
}

/// Truncate a string to `max` characters, appending "…" if shortened.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

/// Extract HH:MM:SS from an ISO timestamp for compact display.
fn short_timestamp(ts: &str) -> &str {
    // "2026-04-30T10:00:00Z" → "10:00:00"
    if ts.len() >= 19 {
        &ts[11..19]
    } else {
        ts
    }
}

/// Format seconds into a human-readable duration string.
fn format_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("abc", 5), "abc");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        assert_eq!(truncate("abcdef", 4), "abc…");
    }

    #[test]
    fn short_timestamp_extracts_time() {
        assert_eq!(short_timestamp("2026-04-30T10:15:30Z"), "10:15:30");
    }

    #[test]
    fn short_timestamp_returns_input_if_too_short() {
        assert_eq!(short_timestamp("short"), "short");
    }

    #[test]
    fn format_duration_hours_and_minutes() {
        assert_eq!(format_duration(3661), "1h 1m");
    }

    #[test]
    fn format_duration_minutes_only() {
        assert_eq!(format_duration(300), "5m");
    }

    #[test]
    fn compute_budget_ratio_with_limit() {
        let state = DashboardState::new();
        let mut state = state;
        state.budget.daily_spend_usd = "50.00".to_string();
        state.budget.daily_limit_usd = Some("100.00".to_string());
        let (ratio, label) = compute_budget_ratio(&state);
        assert!((ratio - 0.5).abs() < 0.01);
        assert!(label.contains("50.00"));
        assert!(label.contains("100.00"));
    }

    #[test]
    fn compute_budget_ratio_no_limit() {
        let state = DashboardState::new();
        let (ratio, label) = compute_budget_ratio(&state);
        assert!((ratio - 0.0).abs() < 0.01);
        assert!(label.contains("no limit"));
    }

    #[test]
    fn compute_budget_ratio_capped_at_one() {
        let mut state = DashboardState::new();
        state.budget.daily_spend_usd = "150.00".to_string();
        state.budget.daily_limit_usd = Some("100.00".to_string());
        let (ratio, _) = compute_budget_ratio(&state);
        assert!((ratio - 1.0).abs() < 0.01);
    }
}
