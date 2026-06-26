//! `aasm dashboard` — governance dashboard: interactive TUI and embedded web server.

pub mod dialog;
pub mod feed;
pub mod input;
pub mod open;
pub mod pid;
pub mod start;
pub mod state;
pub mod stop;
pub mod ui;

use std::io::{self, stdout};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Subcommand};
use crossterm::event::{self as ct_event, DisableMouseCapture, EnableMouseCapture, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use crate::commands::approvals::client as approvals_client;
use crate::config::ResolvedContext;

use self::dialog::DialogAction;
use self::feed::FeedMessage;
use self::input::InputAction;
use self::state::DashboardState;

/// Web-server subcommands for `aasm dashboard`.
#[derive(Debug, Subcommand)]
pub enum DashboardCommands {
    /// Serve the embedded SPA at http://127.0.0.1:<port>. Blocks until Ctrl-C.
    Start(start::StartArgs),
    /// Open the browser to an already-running dashboard.
    Open(open::OpenArgs),
    /// Stop a dashboard server started with `aasm dashboard start`.
    Stop,
}

/// Arguments for the `aasm dashboard` subcommand.
#[derive(Debug, Args)]
pub struct DashboardArgs {
    #[command(subcommand)]
    pub command: Option<DashboardCommands>,
}

/// Entry point for `aasm dashboard [start|open|stop]`.
pub fn dispatch(args: DashboardArgs, ctx: &ResolvedContext) -> ExitCode {
    match args.command {
        None => {
            // No subcommand: run the interactive TUI (existing behaviour).
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(async { run_tui(ctx).await })
        }
        Some(DashboardCommands::Start(start_args)) => {
            let cfg = crate::config::load().unwrap_or_default();
            start::dispatch(start_args, ctx, &cfg)
        }
        Some(DashboardCommands::Open(open_args)) => {
            let cfg = crate::config::load().unwrap_or_default();
            open::dispatch(open_args, &cfg)
        }
        Some(DashboardCommands::Stop) => stop::dispatch(),
    }
}

/// Set up the terminal, run the TUI dashboard, and restore the terminal on exit.
async fn run_tui(ctx: &ResolvedContext) -> ExitCode {
    // Install a panic hook that restores the terminal before printing the panic.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore_terminal();
        original_hook(info);
    }));

    if let Err(e) = setup_terminal() {
        eprintln!("error: failed to initialise terminal: {e}");
        return ExitCode::FAILURE;
    }

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(e) => {
            let _ = restore_terminal();
            eprintln!("error: failed to create terminal: {e}");
            return ExitCode::FAILURE;
        }
    };

    terminal.clear().ok();

    let mut state = DashboardState::new();

    // Spawn background data tasks.
    let (tx, mut rx) = mpsc::unbounded_channel::<FeedMessage>();
    feed::spawn_rest_poller(&ctx.api_url, tx.clone());
    feed::spawn_ws_listener(&ctx.api_url, tx);

    // Main event loop: poll terminal events and feed messages.
    loop {
        // Draw the current state, with optional dialog overlay.
        let confirm_dialog = state.confirm_dialog;
        let dialog_approval =
            confirm_dialog.and_then(|_| state.pending_approvals.get(state.approval_selected).cloned());
        terminal
            .draw(|f| {
                ui::draw(f, &state);
                if let (Some(action), Some(ref approval)) = (confirm_dialog, &dialog_approval) {
                    dialog::draw_confirm_dialog(f, approval, action);
                }
            })
            .ok();

        // Check for terminal input events (non-blocking, 50ms timeout).
        if ct_event::poll(Duration::from_millis(50)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = ct_event::read() {
                handle_key_event(&mut state, ctx, key, dialog_approval.as_ref()).await;
            }
        }

        // Drain all pending feed messages.
        while let Ok(msg) = rx.try_recv() {
            apply_feed_message(&mut state, msg);
        }

        if state.should_quit {
            break;
        }
    }

    let _ = restore_terminal();
    ExitCode::SUCCESS
}

/// Handle one terminal key event against the dashboard `state`.
///
/// Overlay state takes precedence: when the inspect or policy overlay is open,
/// `Esc`/`q` dismisses it and the key is consumed. When a confirm dialog is
/// open, `y` commits the pending approve/reject over the API, `n`/`Esc`
/// cancels. Otherwise the key is dispatched to [`input::handle_key`] and the
/// resulting [`InputAction`] is applied.
async fn handle_key_event(
    state: &mut DashboardState,
    ctx: &ResolvedContext,
    key: crossterm::event::KeyEvent,
    dialog_approval: Option<&crate::commands::status::models::ApprovalResponse>,
) {
    // If an overlay is showing, Esc dismisses it.
    if state.show_inspect {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
            state.show_inspect = false;
        }
        return;
    }
    if state.show_policy {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
            state.show_policy = false;
        }
        return;
    }
    // If a confirm dialog is showing, intercept y/n/Esc.
    if let Some(dialog_action) = state.confirm_dialog {
        handle_confirm_dialog_key(state, ctx, key, dialog_action, dialog_approval).await;
        return;
    }

    match input::handle_key(state, key) {
        InputAction::Approve => {
            state.confirm_dialog = Some(DialogAction::Approve);
        }
        InputAction::Reject => {
            state.confirm_dialog = Some(DialogAction::Reject);
        }
        InputAction::Inspect => {
            state.show_inspect = true;
        }
        InputAction::PolicyView => {
            // Fetch policy YAML in background if not cached.
            if state.policy_yaml.is_none() {
                state.policy_yaml = fetch_policy_yaml();
            }
            state.show_policy = true;
        }
        InputAction::None => {}
    }
}

/// Handle a key while the approve/reject confirm dialog is open. `y` commits the
/// pending `dialog_action` over the API (when an approval is selected); `n`/`Esc`
/// cancels. Any handled key clears the dialog; other keys are ignored.
async fn handle_confirm_dialog_key(
    state: &mut DashboardState,
    ctx: &ResolvedContext,
    key: crossterm::event::KeyEvent,
    dialog_action: DialogAction,
    dialog_approval: Option<&crate::commands::status::models::ApprovalResponse>,
) {
    match key.code {
        KeyCode::Char('y') => {
            if let Some(approval) = dialog_approval {
                match dialog_action {
                    DialogAction::Approve => {
                        let _ =
                            approvals_client::approve_action(ctx, &approval.id, Some("approved via dashboard")).await;
                    }
                    DialogAction::Reject => {
                        let _ = approvals_client::reject_action(ctx, &approval.id, "rejected via dashboard").await;
                    }
                }
            }
            state.confirm_dialog = None;
        }
        KeyCode::Char('n') | KeyCode::Esc => {
            state.confirm_dialog = None;
        }
        _ => {}
    }
}

/// Apply a single background [`FeedMessage`] to the dashboard `state`.
///
/// A `StatusUpdate` replaces the live snapshot and clamps the agent/approval
/// selection indices to the new bounds; `Event` appends to the event log; a
/// WS disconnect is a no-op (the REST poller keeps the snapshot fresh).
fn apply_feed_message(state: &mut DashboardState, msg: FeedMessage) {
    match msg {
        FeedMessage::StatusUpdate {
            runtime,
            agents,
            approvals_summary,
            pending_approvals,
            budget,
        } => {
            state.runtime = runtime;
            state.agents = agents;
            state.approvals_summary = approvals_summary;
            state.pending_approvals = pending_approvals;
            state.budget = budget;
            // Clamp selections to valid range.
            if !state.agents.is_empty() {
                state.agent_selected = state.agent_selected.min(state.agents.len() - 1);
            } else {
                state.agent_selected = 0;
            }
            if !state.pending_approvals.is_empty() {
                state.approval_selected = state.approval_selected.min(state.pending_approvals.len() - 1);
            } else {
                state.approval_selected = 0;
            }
        }
        FeedMessage::Event(entry) => {
            state.push_event(entry);
        }
        FeedMessage::WsDisconnected => {
            // WS dropped — REST poller keeps going, so just note it.
        }
    }
}

/// Attempt to load the active policy YAML from the local policy history store.
fn fetch_policy_yaml() -> Option<String> {
    use aa_gateway::policy::history::{FsHistoryStore, HistoryConfig, PolicyHistoryStore};

    let config = HistoryConfig::default_config();
    let store = FsHistoryStore::new(config);

    let rt = tokio::runtime::Handle::current();
    let versions = rt.block_on(store.list(1)).ok()?;
    let latest = versions.first()?;
    let snapshot = rt.block_on(store.get(&latest.sha256)).ok()?;
    Some(snapshot.yaml_content)
}

/// Enter raw mode and alternate screen for the TUI.
fn setup_terminal() -> io::Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    Ok(())
}

/// Restore the terminal to its original state.
fn restore_terminal() -> io::Result<()> {
    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::dashboard::state::EventEntry;
    use crate::commands::status::models::{AgentRow, ApprovalResponse, ApprovalsSummary, BudgetRow, RuntimeHealth};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_context(api_url: &str) -> ResolvedContext {
        ResolvedContext {
            name: None,
            api_url: api_url.to_string(),
            api_key: None,
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn pending_approval(id: &str) -> ApprovalResponse {
        ApprovalResponse {
            id: id.to_string(),
            agent_id: "agent-x".to_string(),
            action: "refund".to_string(),
            reason: "needs review".to_string(),
            status: "pending".to_string(),
            created_at: "2026-04-30T10:00:00Z".to_string(),
            team_id: String::new(),
            routing_status: String::new(),
        }
    }

    fn agent_row(id: &str) -> AgentRow {
        AgentRow {
            id: id.to_string(),
            name: "agent".to_string(),
            framework: "fw".to_string(),
            status: "Running".to_string(),
            sessions: 0,
            violations_today: 0,
            last_event: "-".to_string(),
            layer: "-".to_string(),
        }
    }

    // ── apply_feed_message ────────────────────────────────────────────────

    #[test]
    fn status_update_replaces_snapshot_and_clamps_selection() {
        let mut state = DashboardState::new();
        // Selections pointing past the end of the incoming snapshot.
        state.agent_selected = 9;
        state.approval_selected = 9;

        apply_feed_message(
            &mut state,
            FeedMessage::StatusUpdate {
                runtime: RuntimeHealth {
                    reachable: true,
                    status: "ok".to_string(),
                    uptime_secs: 1,
                    active_connections: 2,
                    pipeline_lag_ms: 3,
                },
                agents: vec![agent_row("a1"), agent_row("a2")],
                approvals_summary: ApprovalsSummary {
                    pending_count: 1,
                    oldest_pending_age: None,
                },
                pending_approvals: vec![pending_approval("ap1")],
                budget: BudgetRow {
                    daily_spend_usd: "1.00".to_string(),
                    monthly_spend_usd: None,
                    daily_limit_usd: None,
                    monthly_limit_usd: None,
                    date: "2026-04-30".to_string(),
                    per_agent: vec![],
                },
            },
        );

        assert!(state.runtime.reachable);
        assert_eq!(state.agents.len(), 2);
        // Clamped to last valid index.
        assert_eq!(state.agent_selected, 1);
        assert_eq!(state.approval_selected, 0);
    }

    #[test]
    fn status_update_resets_selection_when_lists_empty() {
        let mut state = DashboardState::new();
        state.agent_selected = 4;
        state.approval_selected = 4;
        let runtime = state.runtime.clone();
        let budget = state.budget.clone();
        apply_feed_message(
            &mut state,
            FeedMessage::StatusUpdate {
                runtime,
                agents: vec![],
                approvals_summary: ApprovalsSummary {
                    pending_count: 0,
                    oldest_pending_age: None,
                },
                pending_approvals: vec![],
                budget,
            },
        );
        assert_eq!(state.agent_selected, 0);
        assert_eq!(state.approval_selected, 0);
    }

    #[test]
    fn event_message_appends_to_log() {
        let mut state = DashboardState::new();
        apply_feed_message(
            &mut state,
            FeedMessage::Event(EventEntry {
                timestamp: "2026-04-30T10:00:00Z".to_string(),
                event_type: "violation".to_string(),
                agent_id: "a1".to_string(),
                message: "blocked".to_string(),
            }),
        );
        assert_eq!(state.event_log.len(), 1);
        assert_eq!(state.event_log.back().unwrap().message, "blocked");
    }

    #[test]
    fn ws_disconnected_is_noop() {
        let mut state = DashboardState::new();
        apply_feed_message(&mut state, FeedMessage::WsDisconnected);
        assert!(state.event_log.is_empty());
    }

    // ── handle_key_event ──────────────────────────────────────────────────

    #[tokio::test]
    async fn inspect_overlay_dismissed_by_esc() {
        let mut state = DashboardState::new();
        state.show_inspect = true;
        let ctx = make_context("http://127.0.0.1:1");
        handle_key_event(&mut state, &ctx, key(KeyCode::Esc), None).await;
        assert!(!state.show_inspect);
    }

    #[tokio::test]
    async fn policy_overlay_dismissed_by_q() {
        let mut state = DashboardState::new();
        state.show_policy = true;
        let ctx = make_context("http://127.0.0.1:1");
        handle_key_event(&mut state, &ctx, key(KeyCode::Char('q')), None).await;
        assert!(!state.show_policy);
    }

    #[tokio::test]
    async fn approve_key_opens_confirm_dialog() {
        let mut state = DashboardState::new();
        state.active_panel = state::Panel::Approvals;
        state.pending_approvals = vec![pending_approval("ap1")];
        let ctx = make_context("http://127.0.0.1:1");
        handle_key_event(&mut state, &ctx, key(KeyCode::Char('a')), None).await;
        assert_eq!(state.confirm_dialog, Some(DialogAction::Approve));
    }

    #[tokio::test]
    async fn enter_on_agents_opens_inspect() {
        let mut state = DashboardState::new();
        state.active_panel = state::Panel::Agents;
        state.agents = vec![agent_row("a1")];
        let ctx = make_context("http://127.0.0.1:1");
        handle_key_event(&mut state, &ctx, key(KeyCode::Enter), None).await;
        assert!(state.show_inspect);
    }

    // ── handle_confirm_dialog_key ─────────────────────────────────────────

    #[tokio::test]
    async fn confirm_dialog_cancelled_by_n() {
        let mut state = DashboardState::new();
        state.confirm_dialog = Some(DialogAction::Approve);
        let ctx = make_context("http://127.0.0.1:1");
        handle_key_event(&mut state, &ctx, key(KeyCode::Char('n')), None).await;
        assert!(state.confirm_dialog.is_none());
    }

    #[tokio::test]
    async fn confirm_dialog_approve_commits_and_clears() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let approval = pending_approval("ap1");
        let mut state = DashboardState::new();
        state.confirm_dialog = Some(DialogAction::Approve);
        let ctx = make_context(&server.uri());
        handle_confirm_dialog_key(
            &mut state,
            &ctx,
            key(KeyCode::Char('y')),
            DialogAction::Approve,
            Some(&approval),
        )
        .await;
        assert!(state.confirm_dialog.is_none());
    }

    #[tokio::test]
    async fn confirm_dialog_reject_commits_and_clears() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let approval = pending_approval("ap2");
        let mut state = DashboardState::new();
        state.confirm_dialog = Some(DialogAction::Reject);
        let ctx = make_context(&server.uri());
        handle_confirm_dialog_key(
            &mut state,
            &ctx,
            key(KeyCode::Char('y')),
            DialogAction::Reject,
            Some(&approval),
        )
        .await;
        assert!(state.confirm_dialog.is_none());
    }

    #[tokio::test]
    async fn confirm_dialog_y_without_approval_just_clears() {
        let mut state = DashboardState::new();
        state.confirm_dialog = Some(DialogAction::Approve);
        let ctx = make_context("http://127.0.0.1:1");
        handle_confirm_dialog_key(&mut state, &ctx, key(KeyCode::Char('y')), DialogAction::Approve, None).await;
        assert!(state.confirm_dialog.is_none());
    }
}
