//! Fail-closed resolution of a runtime policy-query outcome (AAASM-3958).
//!
//! [`AssemblyClient::query_policy`](crate::client::AssemblyClient::query_policy)
//! is intentionally low-level: it returns the runtime's [`CheckActionResponse`]
//! on success and a non-OK [`SdkClientError`] sentinel
//! (`QueryFailed`/`ChannelClosed`/`Shutdown`) when the runtime is unreachable,
//! slow, or the session is gone. It never fabricates a decision.
//!
//! Turning that outcome into a final [`Decision`] a pre-exec gate can act on is
//! an *enforcement-mode* choice, and it must be identical across every language
//! FFI shim (`aa-ffi-go`, `aa-ffi-python`, `aa-ffi-node`) — otherwise each shim
//! re-derives the fold and they drift. [`resolve_decision`] is that single,
//! FFI-agnostic mapping, so the shims (which pin this crate by git-SHA) share
//! one tested source of truth instead of each re-implementing it (AAASM-3920
//! fixed the shims; this makes the fix durable at the source, AAASM-3958).
//!
//! # Contract
//!
//! Under **fail-closed** (enforce) the SDK pre-exec gate must never downgrade to
//! allow-on-failure: a stalled or killed sidecar (unreachable runtime) and a
//! held-for-approval (`PENDING`) action both resolve to [`Decision::Deny`]. Only
//! when fail-closed is explicitly disabled (observe mode) is the historical
//! fail-open preserved. A runtime `DENY`/`REDACT` is honoured verbatim in both
//! modes, and an `UNSPECIFIED`/unknown code is never treated as a block (it
//! folds to [`Decision::Allow`]) so the SDK cannot silently wedge on a decision
//! it cannot interpret.
//!
//! The SDK remains advisory: `aa-runtime` / proxy / eBPF are the authoritative
//! enforcement points. This is a defense-in-depth posture, not the primary gate.

use aa_proto::assembly::common::v1::Decision;
use aa_proto::assembly::policy::v1::CheckActionResponse;

use crate::error::SdkClientError;

/// Resolve a runtime policy-query outcome into the [`Decision`] an FFI shim
/// should enforce, applying the fail-closed contract described in the
/// [module docs](self).
///
/// `result` is exactly what
/// [`query_policy`](crate::client::AssemblyClient::query_policy) returned.
/// `fail_closed` mirrors the go SDK's `WithFailClosed` (and the Python
/// enforce-mode guard): `true` denies on runtime-unreachable and on `PENDING`;
/// `false` preserves the advisory fail-open.
///
/// | outcome | `fail_closed == true` | `fail_closed == false` |
/// |---|---|---|
/// | `Err(_)` (unreachable / closed / shutdown) | `Deny` | `Allow` |
/// | `Ok(DENY)` | `Deny` | `Deny` |
/// | `Ok(PENDING)` | `Deny` | `Pending` |
/// | `Ok(REDACT)` | `Redact` | `Redact` |
/// | `Ok(ALLOW)` | `Allow` | `Allow` |
/// | `Ok(UNSPECIFIED)` / unknown code | `Allow` | `Allow` |
pub fn resolve_decision(result: &Result<CheckActionResponse, SdkClientError>, fail_closed: bool) -> Decision {
    match result {
        Ok(resp) => match Decision::try_from(resp.decision) {
            Ok(Decision::Deny) => Decision::Deny,
            // A held-for-approval action is not an allow: under enforce the gate
            // must block rather than proceed (go WaitForApproval equivalent).
            Ok(Decision::Pending) => {
                if fail_closed {
                    Decision::Deny
                } else {
                    Decision::Pending
                }
            }
            Ok(Decision::Redact) => Decision::Redact,
            Ok(Decision::Allow) => Decision::Allow,
            // Unspecified or an unknown/garbled code is not a deny signal; never
            // silently block on a decision the SDK cannot interpret.
            Ok(Decision::Unspecified) | Err(_) => Decision::Allow,
        },
        // Runtime unreachable / slow / closed session: fail closed under enforce
        // so a stalled or killed sidecar cannot turn deny-on-failure into
        // allow-on-failure. Preserve the advisory fail-open only when explicitly
        // disabled (observe mode).
        Err(_) => {
            if fail_closed {
                Decision::Deny
            } else {
                Decision::Allow
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runtime response carrying `decision`.
    fn answered(decision: Decision) -> Result<CheckActionResponse, SdkClientError> {
        Ok(CheckActionResponse {
            decision: decision as i32,
            ..Default::default()
        })
    }

    /// A response with a raw (possibly out-of-range) decision code.
    fn answered_raw(decision: i32) -> Result<CheckActionResponse, SdkClientError> {
        Ok(CheckActionResponse {
            decision,
            ..Default::default()
        })
    }

    // --- runtime unreachable: the core AAASM-3920 regression ---
    // Mirrors go-sdk `query_policy_fails_closed_with_no_server`: with no
    // reachable runtime the query yields a non-OK sentinel, and under
    // fail-closed the SDK must deny rather than synthesize Allow.

    #[test]
    fn query_failed_denies_when_fail_closed() {
        assert_eq!(
            resolve_decision(&Err(SdkClientError::QueryFailed), true),
            Decision::Deny
        );
    }

    #[test]
    fn channel_closed_denies_when_fail_closed() {
        assert_eq!(
            resolve_decision(&Err(SdkClientError::ChannelClosed), true),
            Decision::Deny
        );
    }

    #[test]
    fn shutdown_denies_when_fail_closed() {
        assert_eq!(resolve_decision(&Err(SdkClientError::Shutdown), true), Decision::Deny);
    }

    #[test]
    fn unreachable_allows_when_fail_open() {
        // Fail-open is preserved only when fail-closed is explicitly disabled.
        assert_eq!(
            resolve_decision(&Err(SdkClientError::QueryFailed), false),
            Decision::Allow
        );
        assert_eq!(
            resolve_decision(&Err(SdkClientError::ChannelClosed), false),
            Decision::Allow
        );
        assert_eq!(resolve_decision(&Err(SdkClientError::Shutdown), false), Decision::Allow);
    }

    // --- PENDING -> deny under enforce (go WaitForApproval equivalent) ---

    #[test]
    fn pending_denies_when_fail_closed() {
        assert_eq!(resolve_decision(&answered(Decision::Pending), true), Decision::Deny);
    }

    #[test]
    fn pending_preserved_when_fail_open() {
        assert_eq!(resolve_decision(&answered(Decision::Pending), false), Decision::Pending);
    }

    // --- reachable-runtime path is behavior-preserving in both modes ---

    #[test]
    fn deny_preserved_in_both_modes() {
        assert_eq!(resolve_decision(&answered(Decision::Deny), true), Decision::Deny);
        assert_eq!(resolve_decision(&answered(Decision::Deny), false), Decision::Deny);
    }

    #[test]
    fn allow_preserved_in_both_modes() {
        assert_eq!(resolve_decision(&answered(Decision::Allow), true), Decision::Allow);
        assert_eq!(resolve_decision(&answered(Decision::Allow), false), Decision::Allow);
    }

    #[test]
    fn redact_preserved_in_both_modes() {
        assert_eq!(resolve_decision(&answered(Decision::Redact), true), Decision::Redact);
        assert_eq!(resolve_decision(&answered(Decision::Redact), false), Decision::Redact);
    }

    // --- an uninterpretable decision never silently blocks ---

    #[test]
    fn unspecified_allows_even_when_fail_closed() {
        assert_eq!(
            resolve_decision(&answered(Decision::Unspecified), true),
            Decision::Allow
        );
    }

    #[test]
    fn unknown_code_allows_even_when_fail_closed() {
        // A garbled/out-of-range code is not a deny signal.
        assert_eq!(resolve_decision(&answered_raw(9999), true), Decision::Allow);
    }
}
