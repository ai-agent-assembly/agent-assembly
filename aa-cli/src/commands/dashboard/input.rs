//! Keyboard input handling for the TUI dashboard.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::state::{DashboardState, Panel};

/// The action the caller should take after handling a key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAction {
    /// Nothing special — just redraw.
    None,
    /// The user wants to approve the selected approval.
    Approve,
    /// The user wants to reject the selected approval.
    Reject,
    /// The user pressed Enter to inspect the selected item.
    Inspect,
    /// The user pressed `p` to open the policy viewer.
    PolicyView,
}

/// Process a single key event against the current dashboard state.
///
/// Returns an `InputAction` indicating whether any follow-up is needed.
pub fn handle_key(state: &mut DashboardState, key: KeyEvent) -> InputAction {
    // Global shortcuts — work regardless of panel focus.
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            state.should_quit = true;
            return InputAction::None;
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.should_quit = true;
            return InputAction::None;
        }
        KeyCode::Char('?') => {
            state.show_help = !state.show_help;
            return InputAction::None;
        }
        KeyCode::Char('p') => {
            return InputAction::PolicyView;
        }
        KeyCode::Tab => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                state.active_panel = state.active_panel.prev();
            } else {
                state.active_panel = state.active_panel.next();
            }
            return InputAction::None;
        }
        KeyCode::BackTab => {
            state.active_panel = state.active_panel.prev();
            return InputAction::None;
        }
        _ => {}
    }

    // Panel-specific shortcuts.
    match state.active_panel {
        Panel::Agents => handle_agents_key(state, key),
        Panel::EventLog => handle_event_log_key(state, key),
        Panel::Approvals => handle_approvals_key(state, key),
        Panel::Budget => InputAction::None,
    }
}

/// Handle keys when the agents panel is focused.
fn handle_agents_key(state: &mut DashboardState, key: KeyEvent) -> InputAction {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            state.agent_selected = state.agent_selected.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if !state.agents.is_empty() => {
            state.agent_selected = (state.agent_selected + 1).min(state.agents.len() - 1);
        }
        KeyCode::Enter if !state.agents.is_empty() => {
            return InputAction::Inspect;
        }
        _ => {}
    }
    InputAction::None
}

/// Handle keys when the event log panel is focused.
fn handle_event_log_key(state: &mut DashboardState, key: KeyEvent) -> InputAction {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            state.event_log_scroll = state.event_log_scroll.saturating_add(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.event_log_scroll = state.event_log_scroll.saturating_sub(1);
        }
        _ => {}
    }
    InputAction::None
}

/// Handle keys when the approvals panel is focused.
fn handle_approvals_key(state: &mut DashboardState, key: KeyEvent) -> InputAction {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            state.approval_selected = state.approval_selected.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if !state.pending_approvals.is_empty() => {
            state.approval_selected = (state.approval_selected + 1).min(state.pending_approvals.len() - 1);
        }
        KeyCode::Char('a') if !state.pending_approvals.is_empty() => {
            return InputAction::Approve;
        }
        KeyCode::Char('r') if !state.pending_approvals.is_empty() => {
            return InputAction::Reject;
        }
        KeyCode::Enter if !state.pending_approvals.is_empty() => {
            return InputAction::Inspect;
        }
        _ => {}
    }
    InputAction::None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn make_key_with_mod(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn quit_on_q() {
        let mut state = DashboardState::new();
        handle_key(&mut state, make_key(KeyCode::Char('q')));
        assert!(state.should_quit);
    }

    #[test]
    fn quit_on_esc() {
        let mut state = DashboardState::new();
        handle_key(&mut state, make_key(KeyCode::Esc));
        assert!(state.should_quit);
    }

    #[test]
    fn quit_on_ctrl_c() {
        let mut state = DashboardState::new();
        handle_key(&mut state, make_key_with_mod(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(state.should_quit);
    }

    #[test]
    fn toggle_help() {
        let mut state = DashboardState::new();
        assert!(!state.show_help);
        handle_key(&mut state, make_key(KeyCode::Char('?')));
        assert!(state.show_help);
        handle_key(&mut state, make_key(KeyCode::Char('?')));
        assert!(!state.show_help);
    }

    #[test]
    fn tab_cycles_panels() {
        let mut state = DashboardState::new();
        assert_eq!(state.active_panel, Panel::Agents);
        handle_key(&mut state, make_key(KeyCode::Tab));
        assert_eq!(state.active_panel, Panel::EventLog);
        handle_key(&mut state, make_key(KeyCode::Tab));
        assert_eq!(state.active_panel, Panel::Approvals);
    }

    #[test]
    fn backtab_cycles_backwards() {
        let mut state = DashboardState::new();
        handle_key(&mut state, make_key(KeyCode::BackTab));
        assert_eq!(state.active_panel, Panel::Budget);
    }

    #[test]
    fn shift_tab_cycles_backwards() {
        let mut state = DashboardState::new();
        handle_key(&mut state, make_key_with_mod(KeyCode::Tab, KeyModifiers::SHIFT));
        assert_eq!(state.active_panel, Panel::Budget);
    }

    #[test]
    fn event_log_scroll_up_down() {
        let mut state = DashboardState::new();
        state.active_panel = Panel::EventLog;
        handle_key(&mut state, make_key(KeyCode::Up));
        assert_eq!(state.event_log_scroll, 1);
        handle_key(&mut state, make_key(KeyCode::Down));
        assert_eq!(state.event_log_scroll, 0);
        // Cannot go below 0.
        handle_key(&mut state, make_key(KeyCode::Down));
        assert_eq!(state.event_log_scroll, 0);
    }

    #[test]
    fn approval_selection_navigation() {
        let mut state = DashboardState::new();
        state.active_panel = Panel::Approvals;
        state.pending_approvals = vec![
            crate::commands::status::models::ApprovalResponse {
                id: "1".to_string(),
                agent_id: "a1".to_string(),
                action: "act".to_string(),
                reason: "r".to_string(),
                status: "pending".to_string(),
                created_at: "2026-04-30T10:00:00Z".to_string(),
                team_id: String::new(),
                routing_status: String::new(),
            },
            crate::commands::status::models::ApprovalResponse {
                id: "2".to_string(),
                agent_id: "a2".to_string(),
                action: "act2".to_string(),
                reason: "r2".to_string(),
                status: "pending".to_string(),
                created_at: "2026-04-30T11:00:00Z".to_string(),
                team_id: String::new(),
                routing_status: String::new(),
            },
        ];
        assert_eq!(state.approval_selected, 0);
        handle_key(&mut state, make_key(KeyCode::Down));
        assert_eq!(state.approval_selected, 1);
        // Cannot go beyond list length.
        handle_key(&mut state, make_key(KeyCode::Down));
        assert_eq!(state.approval_selected, 1);
        handle_key(&mut state, make_key(KeyCode::Up));
        assert_eq!(state.approval_selected, 0);
    }

    #[test]
    fn approve_action_returned() {
        let mut state = DashboardState::new();
        state.active_panel = Panel::Approvals;
        state.pending_approvals = vec![crate::commands::status::models::ApprovalResponse {
            id: "1".to_string(),
            agent_id: "a1".to_string(),
            action: "act".to_string(),
            reason: "r".to_string(),
            status: "pending".to_string(),
            created_at: "2026-04-30T10:00:00Z".to_string(),
            team_id: String::new(),
            routing_status: String::new(),
        }];
        let action = handle_key(&mut state, make_key(KeyCode::Char('a')));
        assert_eq!(action, InputAction::Approve);
    }

    #[test]
    fn reject_action_returned() {
        let mut state = DashboardState::new();
        state.active_panel = Panel::Approvals;
        state.pending_approvals = vec![crate::commands::status::models::ApprovalResponse {
            id: "1".to_string(),
            agent_id: "a1".to_string(),
            action: "act".to_string(),
            reason: "r".to_string(),
            status: "pending".to_string(),
            created_at: "2026-04-30T10:00:00Z".to_string(),
            team_id: String::new(),
            routing_status: String::new(),
        }];
        let action = handle_key(&mut state, make_key(KeyCode::Char('r')));
        assert_eq!(action, InputAction::Reject);
    }

    #[test]
    fn approve_noop_when_no_approvals() {
        let mut state = DashboardState::new();
        state.active_panel = Panel::Approvals;
        let action = handle_key(&mut state, make_key(KeyCode::Char('a')));
        assert_eq!(action, InputAction::None);
    }

    #[test]
    fn p_key_returns_policy_view() {
        let mut state = DashboardState::new();
        let action = handle_key(&mut state, make_key(KeyCode::Char('p')));
        assert_eq!(action, InputAction::PolicyView);
    }

    #[test]
    fn enter_on_agents_returns_inspect() {
        let mut state = DashboardState::new();
        state.active_panel = Panel::Agents;
        state.agents = vec![crate::commands::status::models::AgentRow {
            id: "a1".to_string(),
            name: "agent".to_string(),
            framework: "fw".to_string(),
            status: "Running".to_string(),
            sessions: 0,
            violations_today: 0,
            last_event: "-".to_string(),
            layer: "-".to_string(),
        }];
        let action = handle_key(&mut state, make_key(KeyCode::Enter));
        assert_eq!(action, InputAction::Inspect);
    }

    #[test]
    fn enter_on_approvals_returns_inspect() {
        let mut state = DashboardState::new();
        state.active_panel = Panel::Approvals;
        state.pending_approvals = vec![crate::commands::status::models::ApprovalResponse {
            id: "1".to_string(),
            agent_id: "a1".to_string(),
            action: "act".to_string(),
            reason: "r".to_string(),
            status: "pending".to_string(),
            created_at: "2026-04-30T10:00:00Z".to_string(),
            team_id: String::new(),
            routing_status: String::new(),
        }];
        let action = handle_key(&mut state, make_key(KeyCode::Enter));
        assert_eq!(action, InputAction::Inspect);
    }

    #[test]
    fn agent_selection_navigation() {
        let mut state = DashboardState::new();
        state.active_panel = Panel::Agents;
        state.agents = vec![
            crate::commands::status::models::AgentRow {
                id: "a1".to_string(),
                name: "agent1".to_string(),
                framework: "fw".to_string(),
                status: "Running".to_string(),
                sessions: 0,
                violations_today: 0,
                last_event: "-".to_string(),
                layer: "-".to_string(),
            },
            crate::commands::status::models::AgentRow {
                id: "a2".to_string(),
                name: "agent2".to_string(),
                framework: "fw".to_string(),
                status: "Running".to_string(),
                sessions: 0,
                violations_today: 0,
                last_event: "-".to_string(),
                layer: "-".to_string(),
            },
        ];
        assert_eq!(state.agent_selected, 0);
        handle_key(&mut state, make_key(KeyCode::Down));
        assert_eq!(state.agent_selected, 1);
        handle_key(&mut state, make_key(KeyCode::Down));
        assert_eq!(state.agent_selected, 1); // clamped
        handle_key(&mut state, make_key(KeyCode::Up));
        assert_eq!(state.agent_selected, 0);
    }
}
