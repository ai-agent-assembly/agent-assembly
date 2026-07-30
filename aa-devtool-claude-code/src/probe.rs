//! Producing traffic on the protected path, and refusing to guess what happened
//! to it.
//!
//! # Why this is a seam and not a function
//!
//! Only **exercised** evidence can raise the protection ladder to
//! [`GatewayProtected`](aa_devtool_contract::ProtectionLevel::GatewayProtected),
//! and exercised means traffic was produced *and adjudicated*. Producing it is
//! easy; adjudicating it means knowing what the provider actually received,
//! which a client sitting on the near side of the proxy cannot see. A probe that
//! sent a synthetic secret through the proxy and then reported
//! [`Redacted`](aa_devtool_contract::ExerciseOutcome::Redacted) because nothing
//! obviously failed would be exactly the vacuous pass the evidence model exists
//! to prevent.
//!
//! So the probe is an injected capability. The default,
//! [`UnadjudicatedProbe`], reports
//! [`Inconclusive`](aa_devtool_contract::ExerciseOutcome::Inconclusive) with the
//! reason — which is not protective, so `verify` does not pass and the level
//! does not rise. A deployment that *can* observe the forwarded payload supplies
//! a probe that adjudicates, and only then does `GatewayProtected` become
//! reachable.

use std::path::PathBuf;

use aa_devtool_contract::ExerciseOutcome;
use async_trait::async_trait;

/// The synthetic secret probes carry.
///
/// Shaped to match `aa_security`'s `sk-ant-` literal pattern so the deterministic
/// scanner genuinely matches it, and unmistakably fabricated: the ticket id is in
/// the token body and the value appears nowhere else. It is not, and has never
/// been, a credential.
pub const SYNTHETIC_SECRET: &str = "sk-ant-api03-AAASM5281SYNTHETICDONOTUSE0000000000000000000000000000000000AA";

/// Everything a probe needs to reach the protected path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest {
    /// Proxy the tool's traffic is routed through, as a URL.
    pub proxy_url: String,
    /// The trust material the tool was given, so the probe can trust the same
    /// certificate authority the tool does.
    pub ca_pem: PathBuf,
    /// Host the model-bound request is addressed to.
    pub target_host: String,
    /// The value the scanner is expected to find and act on.
    pub synthetic_secret: String,
}

/// What a probe established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// What the core did with the probe traffic.
    pub outcome: ExerciseOutcome,
    /// What happened, in words a user can act on. Never contains the secret.
    pub detail: String,
}

/// Produces traffic on the protected path and reports what became of it.
#[async_trait]
pub trait ProtectionProbe: Send + Sync {
    /// Run one probe.
    ///
    /// Implementations must never report a protective outcome they did not
    /// observe; [`ExerciseOutcome::Inconclusive`] is the correct answer for
    /// "the traffic went out and I could not see what arrived".
    async fn run(&self, request: &ProbeRequest) -> ProbeReport;
}

/// The default probe: honest about what it cannot establish.
///
/// It produces no traffic, because producing traffic it cannot adjudicate would
/// send a synthetic secret to a real provider for no evidential gain.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnadjudicatedProbe;

#[async_trait]
impl ProtectionProbe for UnadjudicatedProbe {
    async fn run(&self, request: &ProbeRequest) -> ProbeReport {
        ProbeReport {
            outcome: ExerciseOutcome::Inconclusive,
            detail: format!(
                "no adjudicating protection probe is configured for {}, so the model path was \
                 configured but never exercised. Interception is wired ({} with the Agent Assembly \
                 certificate authority at {}), and configuration alone is not evidence that anything \
                 inspected the traffic",
                request.target_host,
                request.proxy_url,
                request.ca_pem.display(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ProbeRequest {
        ProbeRequest {
            proxy_url: "http://127.0.0.1:8899".to_string(),
            ca_pem: PathBuf::from("/tmp/aasm-proxy-ca.pem"),
            target_host: "api.anthropic.com".to_string(),
            synthetic_secret: SYNTHETIC_SECRET.to_string(),
        }
    }

    #[tokio::test]
    async fn the_default_probe_is_never_protective() {
        let report = UnadjudicatedProbe.run(&request()).await;
        assert_eq!(report.outcome, ExerciseOutcome::Inconclusive);
        assert!(
            !report.outcome.is_protective(),
            "a probe that adjudicated nothing must not read as protection"
        );
        assert!(report.detail.contains("never exercised"), "{}", report.detail);
    }

    #[tokio::test]
    async fn no_probe_report_may_carry_the_secret() {
        let report = UnadjudicatedProbe.run(&request()).await;
        assert!(!report.detail.contains(SYNTHETIC_SECRET), "{}", report.detail);
    }

    #[test]
    fn the_synthetic_secret_is_obviously_fabricated() {
        assert!(
            SYNTHETIC_SECRET.starts_with("sk-ant-"),
            "the scanner pattern must match"
        );
        assert!(SYNTHETIC_SECRET.contains("AAASM5281SYNTHETICDONOTUSE"));
    }
}
