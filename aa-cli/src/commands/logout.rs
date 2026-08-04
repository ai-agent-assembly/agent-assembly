//! `aasm logout` — end the local session for the active context (AAASM-5509).
//!
//! Logout is **local-only**: it removes the session credential from
//! `~/.aa/credentials.yaml` on disk but does **not** revoke the underlying API
//! key server-side. The source API key the session was minted from stays valid
//! at the gateway — revoking it is a separate IAM operation
//! (`POST /iam/api-keys/{id}/revoke`), deliberately kept distinct so that
//! logging out of one machine never invalidates a key still in use elsewhere.
//!
//! Logout is idempotent: clearing a context with no active session is a
//! success, not a failure, so scripts can call it unconditionally.

use std::process::ExitCode;

use clap::Args;

use crate::auth::session;
use crate::config::ResolvedContext;

/// Arguments for `aasm logout`.
///
/// `logout` acts on the resolved active context (name or `--api-url`); it takes
/// no arguments of its own — the context is selected by the global flags.
///
/// Logout is LOCAL-ONLY: it deletes the session credential from disk but does
/// NOT revoke the underlying API key server-side. Server-side revocation is a
/// separate IAM operation (`POST /iam/api-keys/{id}/revoke`).
#[derive(Args)]
pub struct LogoutArgs {}

/// Human-readable label for the context a message is about.
///
/// Prefers the context name (what the operator reasons about — "production")
/// and falls back to the raw URL for an unnamed context, mirroring how
/// [`session::session_key`] chooses its storage key.
fn label(ctx: &ResolvedContext) -> String {
    match &ctx.name {
        Some(name) => name.clone(),
        None => ctx.api_url.clone(),
    }
}

/// Run `aasm logout`: clear the local session for the active context.
///
/// Removes the credential from `~/.aa/credentials.yaml` only — see the module
/// docs on why this does not revoke the source API key server-side.
pub fn run(_args: LogoutArgs, ctx: &ResolvedContext) -> ExitCode {
    let key = session::session_key(ctx);
    let name = label(ctx);
    match session::clear_session(&key) {
        Ok(true) => {
            println!("Logged out of context '{name}'.");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            // Idempotent no-op: nothing to clear is still success.
            println!("No active session for '{name}'.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named() -> ResolvedContext {
        ResolvedContext {
            name: Some("production".to_string()),
            api_url: "https://api.example.com".to_string(),
            api_key: None,
        }
    }

    fn unnamed() -> ResolvedContext {
        ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        }
    }

    #[test]
    fn label_prefers_name() {
        assert_eq!(label(&named()), "production");
    }

    #[test]
    fn label_falls_back_to_url_when_unnamed() {
        assert_eq!(label(&unnamed()), "http://localhost:8080");
    }

    #[test]
    fn label_matches_session_key() {
        // logout's message label and the store key must describe the same
        // context, else the user is told about a different one than was cleared.
        assert_eq!(label(&named()), session::session_key(&named()));
        assert_eq!(label(&unnamed()), session::session_key(&unnamed()));
    }
}
