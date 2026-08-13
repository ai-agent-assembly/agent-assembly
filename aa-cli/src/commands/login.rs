//! `aasm login` — exchange an API key for a scoped session token (AAASM-5507).
//!
//! The API key is the long-lived operator bearer; the session is the short-lived
//! scoped JWT the rest of the CLI actually presents. This command mints that
//! session and persists it per-context so subsequent commands authenticate
//! without re-prompting. The key is resolved without ever appearing in argv —
//! either from the already-resolved context (env/config/flag, handled upstream)
//! or from a hidden interactive prompt — and neither the key nor the minted JWT
//! is ever echoed back to the user.

use std::process::ExitCode;

use clap::Args;
use console::Term;

use crate::auth;
use crate::auth::session::now_unix;
use crate::config::ResolvedContext;
use crate::error::CliError;

/// Arguments for `aasm login`.
#[derive(Args)]
pub struct LoginArgs {
    /// Requested scope for the session (defaults to the caller's full scopes).
    #[arg(long, value_parser = ["read", "write", "admin"])]
    pub scope: Option<String>,
}

/// Run `aasm login`.
///
/// Resolves the API key (context first, then a hidden prompt), exchanges it for a
/// scoped session at `ctx.api_url`, persists the session under [`session_key`],
/// and prints a confirmation that names the context, the granted scopes, and a
/// relative expiry hint. Never prints the key or the JWT. Returns
/// [`ExitCode::FAILURE`] with an actionable stderr message on any error.
///
/// [`session_key`]: crate::auth::session::session_key
pub fn run(args: LoginArgs, ctx: &ResolvedContext) -> ExitCode {
    let key = match resolve_key(ctx) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let requested_scopes = args.scope.map(|s| vec![s]);

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let session = match rt.block_on(auth::token::exchange(&ctx.api_url, &key, requested_scopes)) {
        Ok(s) => s,
        Err(CliError::AuthRequired) => {
            eprintln!("authentication failed: the API key was rejected");
            return ExitCode::FAILURE;
        }
        Err(CliError::ScopeDenied(msg)) => {
            eprintln!("{msg}");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = auth::session::save_session(&auth::session::session_key(ctx), &session) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    println!("{}", success_line(ctx, &session, now_unix()));
    ExitCode::SUCCESS
}

/// Resolve the API key without leaking it into argv.
///
/// Prefers the key already resolved into the context (from `--api-key`,
/// `AASM_API_KEY`, or config — main did that resolution and its precedence).
/// Falling back to a **hidden** terminal prompt keeps the secret off the command
/// line entirely. An empty entry is rejected so a bare Enter doesn't attempt an
/// exchange with a blank credential.
fn resolve_key(ctx: &ResolvedContext) -> Result<String, CliError> {
    if let Some(key) = &ctx.api_key {
        return Ok(key.clone());
    }
    // Prompt on stderr so stdout stays clean for the success line / any piping.
    eprint!("API key: ");
    let entered = Term::stdout().read_secure_line().map_err(CliError::Io)?;
    let key = entered.trim().to_string();
    if key.is_empty() {
        return Err(CliError::NoApiKey);
    }
    Ok(key)
}

/// Format the human-readable expiry hint (e.g. `expires in 24h`).
///
/// Coarsens to the largest sensible unit so the hint reads at a glance rather
/// than as raw seconds. An already-expired timestamp — possible if the server
/// returns a past expiry or the clock skews — degrades to `already expired`
/// instead of a negative duration.
fn expiry_hint(session: &auth::session::Session, now: u64) -> String {
    let secs = session.expires_in_secs(now);
    if secs <= 0 {
        return "already expired".to_string();
    }
    let secs = secs as u64;
    let value = if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3_600 {
        format!("{}h", secs / 3_600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    };
    format!("expires in {value}")
}

/// Build the success confirmation line.
///
/// Names the context by its friendly name when set, else by URL, so the user can
/// tell which gateway they logged into; lists granted scopes and the expiry hint.
/// Deliberately omits the JWT and the API key.
fn success_line(ctx: &ResolvedContext, session: &auth::session::Session, now: u64) -> String {
    let target = ctx.name.as_deref().unwrap_or(&ctx.api_url);
    format!(
        "Logged in to {target} (scopes: {}; {}).",
        session.scopes.join(", "),
        expiry_hint(session, now)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::Session;

    fn session_with(scopes: Vec<&str>, expires_at: u64) -> Session {
        Session {
            token: "jwt.value".to_string(),
            expires_at,
            scopes: scopes.into_iter().map(String::from).collect(),
            source_key: "aa_key".to_string(),
            api_url: "http://localhost:8080".to_string(),
        }
    }

    fn ctx(name: Option<&str>) -> ResolvedContext {
        ResolvedContext {
            name: name.map(String::from),
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        }
    }

    #[test]
    fn scope_arg_builds_singleton_vec() {
        let args = LoginArgs {
            scope: Some("read".to_string()),
        };
        assert_eq!(args.scope.map(|s| vec![s]), Some(vec!["read".to_string()]));
    }

    /// An empty prompt reports "no API key provided" verbatim — not the
    /// "token exchange failed:" wording, since no exchange is attempted. Renders
    /// via `run`'s `eprintln!("error: {e}")` as the documented `error: no API
    /// key provided` (AAASM-5560).
    #[test]
    fn no_api_key_error_message_matches_docs() {
        assert_eq!(CliError::NoApiKey.to_string(), "no API key provided");
    }

    #[test]
    fn scope_none_requests_full_scopes() {
        let args = LoginArgs { scope: None };
        assert_eq!(args.scope.map(|s| vec![s]), None);
    }

    #[test]
    fn expiry_hint_coarsens_to_largest_unit() {
        let now = 1_000_000;
        assert_eq!(expiry_hint(&session_with(vec![], now + 172_800), now), "expires in 2d");
        assert_eq!(expiry_hint(&session_with(vec![], now + 7_200), now), "expires in 2h");
        assert_eq!(expiry_hint(&session_with(vec![], now + 120), now), "expires in 2m");
        assert_eq!(expiry_hint(&session_with(vec![], now + 45), now), "expires in 45s");
    }

    #[test]
    fn expiry_hint_handles_expired() {
        let now = 1_000_000;
        assert_eq!(expiry_hint(&session_with(vec![], now), now), "already expired");
        assert_eq!(expiry_hint(&session_with(vec![], now - 10), now), "already expired");
    }

    #[test]
    fn success_line_uses_context_name_when_present() {
        let now = 1_000_000;
        let line = success_line(
            &ctx(Some("production")),
            &session_with(vec!["read", "write"], now + 86_400),
            now,
        );
        assert_eq!(line, "Logged in to production (scopes: read, write; expires in 1d).");
    }

    #[test]
    fn success_line_falls_back_to_url_when_unnamed() {
        let now = 1_000_000;
        let line = success_line(&ctx(None), &session_with(vec!["admin"], now + 3_600), now);
        assert_eq!(
            line,
            "Logged in to http://localhost:8080 (scopes: admin; expires in 1h)."
        );
    }

    #[test]
    fn success_line_never_leaks_token_or_key() {
        let now = 1_000_000;
        let line = success_line(&ctx(Some("prod")), &session_with(vec!["read"], now + 60), now);
        assert!(!line.contains("jwt.value"), "success line must not print the JWT");
        assert!(!line.contains("aa_key"), "success line must not print the source key");
    }

    #[test]
    fn resolve_key_prefers_context_key() {
        let _guard = crate::test_support::env_guard();
        let mut c = ctx(Some("prod"));
        c.api_key = Some("ctx-key".to_string());
        assert_eq!(resolve_key(&c).unwrap(), "ctx-key");
    }
}
