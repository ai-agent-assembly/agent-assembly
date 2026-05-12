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
                // If an overlay is showing, Esc dismisses it.
                if state.show_inspect {
                    if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                        state.show_inspect = false;
                    }
                    continue;
                }
                if state.show_policy {
                    if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                        state.show_policy = false;
                    }
                    continue;
                }
                // If a confirm dialog is showing, intercept y/n/Esc.
                if let Some(dialog_action) = state.confirm_dialog {
                    match key.code {
                        KeyCode::Char('y') => {
                            if let Some(ref approval) = dialog_approval {
                                match dialog_action {
                                    DialogAction::Approve => {
                                        let _ = approvals_client::approve_action(
                                            ctx,
                                            &approval.id,
                                            Some("approved via dashboard"),
                                        )
                                        .await;
                                    }
                                    DialogAction::Reject => {
                                        let _ = approvals_client::reject_action(
                                            ctx,
                                            &approval.id,
                                            "rejected via dashboard",
                                        )
                                        .await;
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
                } else {
                    let action = input::handle_key(&mut state, key);
                    match action {
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
            }
        }

        // Drain all pending feed messages.
        while let Ok(msg) = rx.try_recv() {
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

        if state.should_quit {
            break;
        }
    }

    let _ = restore_terminal();
    ExitCode::SUCCESS
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
