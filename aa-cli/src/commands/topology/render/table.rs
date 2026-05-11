//! Table rendering for topology responses.

use comfy_table::Color;

/// Map an agent status string to a terminal colour.
pub fn status_color(status: &str) -> Color {
    match status.to_lowercase().as_str() {
        "active" => Color::Green,
        s if s.starts_with("suspended") => Color::Yellow,
        "deregistered" => Color::Red,
        _ => Color::Reset,
    }
}
