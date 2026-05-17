//! `aasm approvals watch` — live-updating approval request stream.

use std::io::Write;
use std::time::Duration;

use chrono::Utc;
use clap::Args;
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use crossterm::terminal;
use futures_util::{FutureExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use super::models::{compute_timeout_color, format_countdown, TimeoutColor};

use crate::config::ResolvedContext;
use crate::error::CliError;

use super::client;
use super::models::ApprovalResponse;

/// Type alias for the WebSocket stream used by the watch command.
pub type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Arguments for the `aasm approvals watch` subcommand.
#[derive(Debug, Args)]
pub struct WatchArgs {
    /// Enable interactive mode with keyboard shortcuts (a=approve, r=reject, q=quit).
    #[arg(long, short)]
    pub interactive: bool,
}

/// Establish a WebSocket connection to the approval events endpoint.
pub async fn connect_approval_ws(ctx: &ResolvedContext) -> Result<WsStream, CliError> {
    let url = client::build_ws_url(&ctx.api_url, "approval_required")?;
    let (ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .map_err(|e| CliError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e)))?;
    Ok(ws)
}

/// Mutable state for the interactive watch mode.
///
/// Tracks the list of pending approvals and the user's current selection.
pub struct InteractiveState {
    /// Currently pending approval items.
    pub items: Vec<ApprovalResponse>,
    /// Index of the currently selected item in `items`.
    pub selected: usize,
    /// Whether the view needs to be redrawn.
    pub dirty: bool,
}

impl Default for InteractiveState {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractiveState {
    /// Create a new empty interactive state.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            selected: 0,
            dirty: true,
        }
    }

    /// Move selection up by one.
    pub fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.dirty = true;
        }
    }

    /// Move selection down by one.
    pub fn select_next(&mut self) {
        if !self.items.is_empty() && self.selected < self.items.len() - 1 {
            self.selected += 1;
            self.dirty = true;
        }
    }

    /// Return the ID of the currently selected item, if any.
    pub fn selected_id(&self) -> Option<&str> {
        self.items.get(self.selected).map(|i| i.id.as_str())
    }
}

/// Actions that can result from a keypress in interactive mode.
pub enum KeyAction {
    /// Approve the currently selected item.
    Approve,
    /// Reject the currently selected item (will prompt for reason).
    Reject,
    /// Quit the interactive watch.
    Quit,
    /// No action needed (navigation was handled internally).
    None,
}

/// Handle a keypress event in interactive mode.
///
/// Arrow keys adjust the selection. `a` triggers approve, `r` triggers reject,
/// `q` quits.
pub fn handle_keypress(key: KeyEvent, state: &mut InteractiveState) -> KeyAction {
    match key.code {
        KeyCode::Up => {
            state.select_prev();
            KeyAction::None
        }
        KeyCode::Down => {
            state.select_next();
            KeyAction::None
        }
        KeyCode::Char('a') | KeyCode::Char('A') => KeyAction::Approve,
        KeyCode::Char('r') | KeyCode::Char('R') => KeyAction::Reject,
        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => KeyAction::Quit,
        _ => KeyAction::None,
    }
}

/// Render the interactive view to stdout.
///
/// Clears the terminal and draws the approval list with the current selection
/// highlighted, plus a help bar at the bottom.
pub fn render_interactive_view(state: &InteractiveState) {
    let mut stdout = std::io::stdout();

    // Clear screen and move cursor to top-left.
    let _ = crossterm::execute!(
        stdout,
        terminal::Clear(terminal::ClearType::All),
        crossterm::cursor::MoveTo(0, 0)
    );

    println!("  aasm approvals watch (interactive)");
    println!("  [a] approve  [r] reject  [Up/Down] navigate  [q] quit");
    println!();

    if state.items.is_empty() {
        println!("  No pending approvals.");
        let _ = stdout.flush();
        return;
    }

    let now = Utc::now().timestamp();

    for (i, item) in state.items.iter().enumerate() {
        let marker = if i == state.selected { ">" } else { " " };
        let submitted_epoch = chrono::DateTime::parse_from_rfc3339(&item.created_at)
            .map(|dt| dt.timestamp())
            .unwrap_or(0);
        let remaining = (submitted_epoch + 300) - now;
        let color_code = match compute_timeout_color(remaining) {
            TimeoutColor::Red => "\x1b[31m",
            TimeoutColor::Yellow => "\x1b[33m",
            TimeoutColor::Green => "\x1b[32m",
        };
        let countdown = format_countdown(remaining);

        println!(
            "  {marker} {id}  {agent:<20} {action:<30} {color}{cd}\x1b[0m",
            id = &item.id[..8.min(item.id.len())],
            agent = item.agent_id,
            action = item.action,
            color = color_code,
            cd = countdown,
        );
    }

    let _ = stdout.flush();
}

/// Run the watch stream in non-interactive mode, printing events as they arrive.
pub async fn run_watch_stream(mut ws: WsStream) {
    println!("Watching for approval requests... (Ctrl+C to stop)");
    println!();

    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(approval) = serde_json::from_str::<ApprovalResponse>(&text) {
                    println!(
                        "  \x1b[1;33mNEW\x1b[0m  {} | agent={} | action={} | condition={}",
                        approval.id, approval.agent_id, approval.action, approval.reason
                    );
                    println!("        run: aasm approvals approve {} --reason \"...\"", approval.id);
                    println!();
                }
            }
            Ok(Message::Close(_)) => {
                println!("Connection closed by server.");
                break;
            }
            Err(e) => {
                eprintln!("WebSocket error: {e}");
                break;
            }
            _ => {}
        }
    }
}

/// Run the watch in interactive mode with keyboard shortcuts.
///
/// Combines WebSocket event streaming with `crossterm` raw terminal input.
/// The user navigates with arrow keys, approves with `a`, rejects with `r`,
/// and quits with `q`.
pub async fn run_watch_interactive(mut ws: WsStream, ctx: &ResolvedContext) {
    let mut state = InteractiveState::new();

    // Pre-populate with current pending approvals.
    if let Ok(paginated) = client::list_approvals(ctx, None, None).await {
        state.items = paginated.items;
        state.dirty = true;
    }

    terminal::enable_raw_mode().expect("failed to enable raw terminal mode");
    render_interactive_view(&state);

    loop {
        // Poll for keyboard events with a short timeout so we can also check WebSocket.
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                match handle_keypress(key, &mut state) {
                    KeyAction::Approve => {
                        if let Some(id) = state.selected_id().map(String::from) {
                            terminal::disable_raw_mode().ok();
                            let result = client::approve_action(ctx, &id, Some("approved via watch")).await;
                            match result {
                                Ok(_) => {
                                    state.items.retain(|i| i.id != id);
                                    if state.selected > 0 && state.selected >= state.items.len() {
                                        state.selected = state.items.len().saturating_sub(1);
                                    }
                                }
                                Err(e) => eprintln!("approve error: {e}"),
                            }
                            terminal::enable_raw_mode().ok();
                            state.dirty = true;
                        }
                    }
                    KeyAction::Reject => {
                        if let Some(id) = state.selected_id().map(String::from) {
                            terminal::disable_raw_mode().ok();
                            print!("Rejection reason: ");
                            std::io::stdout().flush().ok();
                            let mut reason = String::new();
                            std::io::stdin().read_line(&mut reason).ok();
                            let reason = reason.trim();
                            if !reason.is_empty() {
                                let result = client::reject_action(ctx, &id, reason).await;
                                match result {
                                    Ok(_) => {
                                        state.items.retain(|i| i.id != id);
                                        if state.selected > 0 && state.selected >= state.items.len() {
                                            state.selected = state.items.len().saturating_sub(1);
                                        }
                                    }
                                    Err(e) => eprintln!("reject error: {e}"),
                                }
                            }
                            terminal::enable_raw_mode().ok();
                            state.dirty = true;
                        }
                    }
                    KeyAction::Quit => break,
                    KeyAction::None => {}
                }
            }
        }

        // Check for new WebSocket messages (non-blocking).
        match ws.next().now_or_never() {
            Some(Some(Ok(Message::Text(text)))) => {
                if let Ok(approval) = serde_json::from_str::<ApprovalResponse>(&text) {
                    state.items.push(approval);
                    state.dirty = true;
                }
            }
            Some(Some(Ok(Message::Close(_)))) | Some(None) => break,
            _ => {}
        }

        if state.dirty {
            render_interactive_view(&state);
            state.dirty = false;
        }
    }

    terminal::disable_raw_mode().ok();
    println!();
}

/// Execute the `aasm approvals watch` subcommand.
///
/// Routes to interactive or stream mode based on the `--interactive` flag.
pub fn run_watch(args: WatchArgs, ctx: &ResolvedContext) -> std::process::ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let result = rt.block_on(async {
        let ws = connect_approval_ws(ctx).await?;
        if args.interactive {
            run_watch_interactive(ws, ctx).await;
        } else {
            run_watch_stream(ws).await;
        }
        Ok::<(), CliError>(())
    });

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
