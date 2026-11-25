//! The elevation seam between a runtime that must place one root-owned file and
//! the client that owns the terminal the operator is sitting at (AAASM-6491).
//!
//! # Why this lives in `aa-core`
//!
//! The runtime applies a plan inside a detached daemon whose stdio is null, so
//! it can never prompt for a password itself. The client (`aasm`) owns the
//! controlling terminal. While a request is in flight the runtime hands the one
//! privileged operation to whoever implements [`ElevationBroker`]; in the
//! shipped runtime that is the connection back to the client, which runs `sudo`
//! in its own terminal. The trait is here — not in a devtool crate — because
//! devtool crates are stripped from published builds, and the runtime's server
//! side must compile without them.
//!
//! # What crosses this seam
//!
//! Paths and digests only ([`ElevatedOperation`]). Never a password, never file
//! content, never a command line: the client derives the command from the closed
//! set of operations below, against its own copy of the target path.

use std::path::PathBuf;

/// How the operator asked for administrator authorization to be obtained.
///
/// Decided by the client, recorded in the reviewed plan, and re-checked at
/// apply so a plan reviewed under one method can never run under another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AuthorizationMethod {
    /// `sudo` in the terminal that ran the command.
    Terminal,
    /// The macOS GUI authorization dialog; explicit opt-in only.
    Gui,
    /// The caller stated nothing (a pre-DI-API-8 client).
    #[default]
    Unstated,
}

impl AuthorizationMethod {
    /// The stable wire/CLI token, or `None` for [`Unstated`](Self::Unstated).
    pub fn token(self) -> Option<&'static str> {
        match self {
            Self::Terminal => Some("terminal"),
            Self::Gui => Some("gui"),
            Self::Unstated => None,
        }
    }

    /// Parse a wire/CLI token. Unknown tokens are refused (`Err`), never mapped.
    ///
    /// # Errors
    ///
    /// The unrecognised token, echoed back for the caller's message.
    pub fn parse(token: &str) -> Result<Self, String> {
        match token {
            "" => Ok(Self::Unstated),
            "terminal" => Ok(Self::Terminal),
            "gui" => Ok(Self::Gui),
            other => Err(other.to_string()),
        }
    }
}

/// Which single privileged operation is requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevatedKind {
    /// Place `staged` at `target`, owned by root.
    InstallFile,
    /// Delete `target`.
    DeleteFile,
}

/// Why the operation is being requested, so the operator sees what they are
/// authorizing and the client can apply the right digest check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationPurpose {
    /// The reviewed plan's content is being placed.
    PlaceReviewed,
    /// A backed-up prior file is being restored by a rollback.
    RestoreBackup,
    /// The managed file is being removed.
    Remove,
}

/// One elevated operation. Paths and digests only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevatedOperation {
    /// Place or delete.
    pub kind: ElevatedKind,
    /// Why.
    pub purpose: ElevationPurpose,
    /// The runtime's idea of the target. Informational for the client, which
    /// always acts on its own canonical constant.
    pub target: PathBuf,
    /// The unprivileged staged copy, for an install.
    pub staged: Option<PathBuf>,
    /// SHA-256 (hex) of the staged bytes, for an install.
    pub staged_sha256: Option<String>,
}

/// What happened to a requested operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevationOutcome {
    /// The operation ran and `sudo` reported success.
    Completed,
    /// Authentication was refused (wrong password, policy).
    Denied(String),
    /// The operator cancelled, or the channel closed or timed out.
    Cancelled(String),
    /// No mechanism is available on this host or in this terminal.
    Unavailable(String),
    /// There is no terminal to ask on.
    NonInteractive(String),
}

/// Performs one elevated operation on the operator's behalf. Blocking: the
/// caller is on a blocking thread and waits for the operator.
pub trait ElevationBroker: Send + Sync + std::fmt::Debug {
    /// Run `operation`, returning only after the operator has answered.
    fn perform(&self, operation: &ElevatedOperation) -> ElevationOutcome;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_tokens_round_trip_and_unknown_is_refused() {
        assert_eq!(
            AuthorizationMethod::parse("terminal"),
            Ok(AuthorizationMethod::Terminal)
        );
        assert_eq!(AuthorizationMethod::parse("gui"), Ok(AuthorizationMethod::Gui));
        assert_eq!(AuthorizationMethod::parse(""), Ok(AuthorizationMethod::Unstated));
        assert_eq!(AuthorizationMethod::parse("sudo"), Err("sudo".to_string()));
        assert_eq!(AuthorizationMethod::Terminal.token(), Some("terminal"));
        assert_eq!(AuthorizationMethod::Unstated.token(), None);
    }
}
