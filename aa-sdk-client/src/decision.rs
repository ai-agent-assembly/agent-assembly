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
//! allow-on-failure: a stalled or killed sidecar (unreachable runtime), a
//! held-for-approval (`PENDING`) action, and an `UNSPECIFIED`/unknown code all
//! resolve to [`Decision::Deny`]. Only when fail-closed is explicitly disabled
//! (observe mode) is the historical fail-open preserved. A runtime `DENY`/
//! `REDACT` is honoured verbatim in both modes.
//!
//! Denying the uninterpretable case under enforce closes a forward-compatibility
//! downgrade (AAASM-3996): a future, more-restrictive `Decision` variant that an
//! older SDK sees as an unknown code must not silently fold to `Allow` while the
//! operator believes enforce is active. In observe mode the code still folds to
//! `Allow` so the SDK cannot wedge on a decision it cannot interpret.
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
/// | `Ok(UNSPECIFIED)` / unknown code | `Deny` | `Allow` |
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
            // Unspecified or an unknown/garbled code is uninterpretable. Under
            // enforce we deny it so a future restrictive Decision variant an old
            // SDK cannot decode is not silently downgraded to Allow (AAASM-3996);
            // in observe mode we preserve the historical fail-open.
            Ok(Decision::Unspecified) | Err(_) => {
                if fail_closed {
                    Decision::Deny
                } else {
                    Decision::Allow
                }
            }
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

    // --- an uninterpretable decision denies under enforce (AAASM-3996) ---

    #[test]
    fn unspecified_denies_when_fail_closed() {
        // Under enforce, a decision the SDK cannot interpret must not proceed:
        // this closes the fwd-compat downgrade of a future restrictive variant.
        assert_eq!(resolve_decision(&answered(Decision::Unspecified), true), Decision::Deny);
    }

    #[test]
    fn unspecified_allows_when_fail_open() {
        assert_eq!(
            resolve_decision(&answered(Decision::Unspecified), false),
            Decision::Allow
        );
    }

    #[test]
    fn unknown_code_denies_when_fail_closed() {
        // A garbled/out-of-range code (e.g. a variant added after this SDK was
        // built) denies under enforce rather than downgrading to Allow.
        assert_eq!(resolve_decision(&answered_raw(9999), true), Decision::Deny);
    }

    #[test]
    fn unknown_code_allows_when_fail_open() {
        assert_eq!(resolve_decision(&answered_raw(9999), false), Decision::Allow);
    }
}
