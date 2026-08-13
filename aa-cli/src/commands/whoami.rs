//! `aasm whoami` — show the active session identity, scopes, and expiry (AAASM-5510).
//!
//! `whoami` is a read/status command: being logged out is a normal state, not an
//! error, so it exits `0` either way. The critical invariant is that it must
//! **never** surface bearer material — neither the JWT (`token`) nor the full
//! `source_key` it was minted from. Everything the command emits (Table, JSON,
//! YAML) is built from a purpose-made [`WhoamiView`] that carries only a truncated
//! hint of `source_key`, so [`Session`]'s secret fields cannot leak by being
//! serialized directly.

use std::process::ExitCode;

use clap::Args;
use serde::Serialize;

use crate::auth::session::{self, now_unix, Session};
use crate::config::ResolvedContext;
use crate::output::OutputFormat;

/// Arguments for `aasm whoami`.
#[derive(Args)]
pub struct WhoamiArgs {}

/// How many leading characters of `source_key` the hint reveals. Enough to
/// disambiguate which key minted the session without exposing enough to be
/// usable as a credential.
const SOURCE_KEY_HINT_PREFIX: usize = 10;

/// The secret-free projection of a [`Session`] that every output format renders.
///
/// Deliberately omits `token` and the full `source_key`: it is the only shape
/// that reaches `serde_json`/`serde_yaml`, so no output path can emit bearer
/// material even if [`Session`] gains more secret fields later.
#[derive(Debug, Serialize)]
struct WhoamiView {
    logged_in: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
    api_url: String,
    scopes: Vec<String>,
    expires_at: u64,
    expires_in_secs: i64,
    expired: bool,
    /// Non-secret indicator of which source key minted the session: a short
    /// prefix plus an ellipsis, never the full key.
    source_key_hint: String,
}

/// Redact `source_key` to a short, non-usable indicator: the first
/// [`SOURCE_KEY_HINT_PREFIX`] chars plus an ellipsis. Keys at or below that
/// length are already too short to be worth hinting, so only their length is
/// reported — the raw key is never returned.
fn source_key_hint(source_key: &str) -> String {
    let char_count = source_key.chars().count();
    if char_count <= SOURCE_KEY_HINT_PREFIX {
        return format!("({char_count} chars)");
    }
    let prefix: String = source_key.chars().take(SOURCE_KEY_HINT_PREFIX).collect();
    format!("{prefix}…")
}

/// Build the secret-free view for a live session. `ctx` supplies the context
/// name; the session's own `api_url` is preferred over `ctx.api_url` since it
/// records the gateway the session actually authenticates against.
fn view_for_session(session: &Session, ctx: &ResolvedContext, now: u64) -> WhoamiView {
    WhoamiView {
        logged_in: true,
        context: ctx.name.clone(),
        api_url: session.api_url.clone(),
        scopes: session.scopes.clone(),
        expires_at: session.expires_at,
        expires_in_secs: session.expires_in_secs(now),
        expired: session.is_expired(now),
        source_key_hint: source_key_hint(&session.source_key),
    }
}

/// Format a signed seconds-until-expiry as a human relative hint: `EXPIRED`
/// once non-positive, else a coarse `in Xh Ym` / `in Ym Zs` / `in Zs`.
fn format_relative(expires_in_secs: i64) -> String {
    if expires_in_secs <= 0 {
        return "EXPIRED".to_string();
    }
    let secs = expires_in_secs;
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("in {hours}h {minutes}m")
    } else if minutes > 0 {
        format!("in {minutes}m {seconds}s")
    } else {
        format!("in {seconds}s")
    }
}

/// Render a live session's view as human-readable lines.
fn render_table(view: &WhoamiView) {
    let context = view.context.as_deref().unwrap_or("(none)");
    let scopes = if view.scopes.is_empty() {
        "(none)".to_string()
    } else {
        view.scopes.join(", ")
    };
    println!("Logged in");
    println!("  context:    {context}");
    println!("  api_url:    {}", view.api_url);
    println!("  scopes:     {scopes}");
    println!(
        "  expires_at: {} ({})",
        view.expires_at,
        format_relative(view.expires_in_secs)
    );
    println!("  source_key: {}", view.source_key_hint);
}

/// Run `aasm whoami`.
pub fn run(_args: WhoamiArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let key = session::session_key(ctx);

    let Some(session) = session::load_session(&key) else {
        match output {
            OutputFormat::Table => println!("Not logged in (run 'aasm login')."),
            OutputFormat::Json => match serde_json::to_string_pretty(&LoggedOutView::default()) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("error serializing JSON: {e}"),
            },
            OutputFormat::Yaml => match serde_yaml::to_string(&LoggedOutView::default()) {
                Ok(yaml) => print!("{yaml}"),
                Err(e) => eprintln!("error serializing YAML: {e}"),
            },
        }
        return ExitCode::SUCCESS;
    };

    let view = view_for_session(&session, ctx, now_unix());
    match output {
        OutputFormat::Table => render_table(&view),
        OutputFormat::Json => match serde_json::to_string_pretty(&view) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("error serializing JSON: {e}"),
        },
        OutputFormat::Yaml => match serde_yaml::to_string(&view) {
            Ok(yaml) => print!("{yaml}"),
            Err(e) => eprintln!("error serializing YAML: {e}"),
        },
    }

    ExitCode::SUCCESS
}

/// The machine-readable shape for the not-logged-in state (`{ logged_in: false }`).
///
/// `logged_in` derives to `false` via [`Default`], which is exactly the
/// not-logged-in value, so the derive is the intended default.
#[derive(Debug, Default, Serialize)]
struct LoggedOutView {
    logged_in: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "jwt.header.payloadsignature.secret";
    const SOURCE_KEY: &str = "aa_live_supersecretsourcekey_1234567890";

    fn sample() -> Session {
        Session {
            token: TOKEN.to_string(),
            expires_at: 1_000_000,
            scopes: vec!["read".to_string(), "write".to_string()],
            source_key: SOURCE_KEY.to_string(),
            api_url: "https://api.example.com".to_string(),
        }
    }

    fn ctx() -> ResolvedContext {
        ResolvedContext {
            name: Some("production".to_string()),
            api_url: "https://ctx.example.com".to_string(),
            api_key: None,
        }
    }

    #[test]
    fn view_never_contains_token_or_full_source_key() {
        let view = view_for_session(&sample(), &ctx(), 999_000);
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains(TOKEN), "JSON must not leak the token");
        assert!(!json.contains(SOURCE_KEY), "JSON must not leak the full source key");
        let yaml = serde_yaml::to_string(&view).unwrap();
        assert!(!yaml.contains(TOKEN), "YAML must not leak the token");
        assert!(!yaml.contains(SOURCE_KEY), "YAML must not leak the full source key");
    }

    #[test]
    fn source_key_hint_truncates_long_keys() {
        let hint = source_key_hint(SOURCE_KEY);
        assert_eq!(hint, "aa_live_su…");
        assert!(!hint.contains(SOURCE_KEY));
    }

    #[test]
    fn source_key_hint_reports_length_for_short_keys() {
        assert_eq!(source_key_hint("short"), "(5 chars)");
    }

    #[test]
    fn view_prefers_session_api_url_over_ctx() {
        let view = view_for_session(&sample(), &ctx(), 999_000);
        assert_eq!(view.api_url, "https://api.example.com");
    }

    #[test]
    fn relative_expiry_future_is_hours_minutes() {
        // 23h 41m = 85_260s.
        assert_eq!(format_relative(85_260), "in 23h 41m");
        assert_eq!(format_relative(90), "in 1m 30s");
        assert_eq!(format_relative(42), "in 42s");
    }

    #[test]
    fn relative_expiry_expired_is_marked() {
        assert_eq!(format_relative(0), "EXPIRED");
        assert_eq!(format_relative(-10), "EXPIRED");
    }

    #[test]
    fn view_marks_expired_session() {
        let view = view_for_session(&sample(), &ctx(), 1_000_050);
        assert!(view.expired);
        assert!(view.expires_in_secs < 0);
        assert_eq!(format_relative(view.expires_in_secs), "EXPIRED");
    }

    #[test]
    fn json_view_has_expected_fields() {
        let view = view_for_session(&sample(), &ctx(), 999_000);
        let json = serde_json::to_string(&view).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["logged_in"], true);
        assert_eq!(parsed["context"], "production");
        assert_eq!(parsed["api_url"], "https://api.example.com");
        assert_eq!(parsed["scopes"][0], "read");
        assert_eq!(parsed["scopes"][1], "write");
        assert_eq!(parsed["expires_at"], 1_000_000);
        assert_eq!(parsed["expires_in_secs"], 1_000);
        assert_eq!(parsed["expired"], false);
        assert_eq!(parsed["source_key_hint"], "aa_live_su…");
    }

    #[test]
    fn yaml_view_has_expected_fields() {
        let view = view_for_session(&sample(), &ctx(), 999_000);
        let yaml = serde_yaml::to_string(&view).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed["logged_in"].as_bool(), Some(true));
        assert_eq!(parsed["context"].as_str(), Some("production"));
        assert_eq!(parsed["api_url"].as_str(), Some("https://api.example.com"));
        assert_eq!(parsed["expires_in_secs"].as_i64(), Some(1_000));
        assert_eq!(parsed["source_key_hint"].as_str(), Some("aa_live_su…"));
    }

    #[test]
    fn logged_out_view_serializes_logged_in_false() {
        let json = serde_json::to_string(&LoggedOutView::default()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["logged_in"], false);
    }
}
