//! Confirmation dialog overlay for approve/reject actions.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::commands::status::models::ApprovalResponse;

/// Which action the dialog is confirming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogAction {
    Approve,
    Reject,
}

/// Render a centered confirmation dialog over the dashboard.
pub fn draw_confirm_dialog(f: &mut Frame, approval: &ApprovalResponse, action: DialogAction) {
    let area = centered_rect(50, 30, f.area());

    // Clear the area behind the dialog.
    f.render_widget(Clear, area);

    let (title, color) = match action {
        DialogAction::Approve => ("Approve?", Color::Green),
        DialogAction::Reject => ("Reject?", Color::Red),
    };

    let block = Block::default()
        .title(format!(" {title} "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(2)])
        .split(inner);

    // Summary of what is being approved/rejected.
    let summary = Paragraph::new(vec![
        Line::from(format!("ID:     {}", approval.id)),
        Line::from(format!("Agent:  {}", approval.agent_id)),
        Line::from(format!("Action: {}", approval.action)),
        Line::from(format!("Reason: {}", approval.reason)),
    ]);
    f.render_widget(summary, chunks[0]);

    // Instruction line.
    let instruction = Paragraph::new(Line::from(vec![
        ratatui::text::Span::styled("y", Style::default().add_modifier(Modifier::BOLD)),
        ratatui::text::Span::raw(" confirm  "),
        ratatui::text::Span::styled("n", Style::default().add_modifier(Modifier::BOLD)),
        ratatui::text::Span::raw("/"),
        ratatui::text::Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
        ratatui::text::Span::raw(" cancel"),
    ]))
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(instruction, chunks[1]);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centered_rect_produces_inner_rect() {
        let area = Rect::new(0, 0, 100, 50);
        let center = centered_rect(50, 40, area);
        // Should be roughly centered.
        assert!(center.x > 0);
        assert!(center.y > 0);
        assert!(center.width > 0);
        assert!(center.height > 0);
        assert!(center.x + center.width <= area.width);
        assert!(center.y + center.height <= area.height);
    }

    fn sample_approval() -> ApprovalResponse {
        ApprovalResponse {
            id: "ap-123".to_string(),
            agent_id: "agent-x".to_string(),
            action: "process_refund".to_string(),
            reason: "amount exceeds $100".to_string(),
            status: "pending".to_string(),
            created_at: "2026-04-30T10:00:00Z".to_string(),
            team_id: "team-x".to_string(),
            routing_status: "routed:team-x".to_string(),
        }
    }

    fn render_dialog(action: DialogAction) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let approval = sample_approval();
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw_confirm_dialog(f, &approval, action)).unwrap();
        terminal.backend().buffer().content.iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn draw_approve_dialog_shows_title_and_summary() {
        let text = render_dialog(DialogAction::Approve);
        assert!(text.contains("Approve?"));
        assert!(text.contains("ap-123"));
        assert!(text.contains("process_refund"));
        assert!(text.contains("confirm"));
    }

    #[test]
    fn draw_reject_dialog_shows_reject_title() {
        let text = render_dialog(DialogAction::Reject);
        assert!(text.contains("Reject?"));
        assert!(text.contains("agent-x"));
    }
}
