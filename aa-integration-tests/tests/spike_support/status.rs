//! Protection-level reporting model for the AAASM-5276 Spike.
//!
//! The product brief's rule (§7, restated in §11's design rule) is the whole
//! point of this module:
//!
//! > A scenario passes on observed behaviour, never on the presence of
//! > configuration.
//!
//! So [`ProtectionLevel::GatewayProtected`] is unreachable from configuration
//! alone. It requires an [`Evidence::Exercised`] entry — a record that traffic
//! actually flowed through the interception path and the scanner acted on it.
//! Configuration that has never been exercised tops out at
//! [`ProtectionLevel::Integrated`], and `Integrated` explicitly does not claim
//! sensitive-data protection.
//!
//! Host-level enforcement (macOS Endpoint Security / Network Extension) is out
//! of scope for this Spike and unimplemented in the tree, so it is reported as
//! [`HostEnforcement::Unavailable`] rather than omitted — omitting it would let
//! a reader assume it was covered.
//!
//! Spike scaffolding; AAASM-5278 owns the productised status surface.

use serde::{Deserialize, Serialize};

use super::receipt::DriftFinding;

/// Reported protection level, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProtectionLevel {
    /// No protection. Either nothing is installed, or the core is unreachable.
    NotProtected,
    /// Managed configuration is installed, but protection has never been
    /// exercised. Must not claim sensitive-data protection.
    Integrated,
    /// Protection was exercised: traffic traversed the interception path and
    /// the scanner acted on it.
    GatewayProtected,
}

impl ProtectionLevel {
    /// Stable label for user-visible output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotProtected => "Not protected",
            Self::Integrated => "Integrated",
            Self::GatewayProtected => "Gateway Protected",
        }
    }
}

/// Host-level enforcement availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostEnforcement {
    /// Not available on this platform / build. Always reported, never omitted.
    Unavailable,
}

impl HostEnforcement {
    /// Stable label for user-visible output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "Host Enforced: unavailable on this platform",
        }
    }
}

/// How a mechanism's state was established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    /// Confirmed by reading configuration. Never sufficient for
    /// [`ProtectionLevel::GatewayProtected`].
    ReadBack {
        /// Mechanism name.
        mechanism: String,
    },
    /// Confirmed by observing behaviour — traffic flowed and was acted upon.
    Exercised {
        /// Mechanism name.
        mechanism: String,
        /// What was observed, e.g. `"1 request forwarded redacted"`.
        observation: String,
    },
}

impl Evidence {
    /// Mechanism this evidence concerns.
    pub fn mechanism(&self) -> &str {
        match self {
            Self::ReadBack { mechanism } | Self::Exercised { mechanism, .. } => mechanism,
        }
    }
}

/// Inputs a status computation needs. Every field is an *observation*, not a
/// configuration read, except `installed` — which is why `installed` alone can
/// never raise the level past `Integrated`.
#[derive(Debug, Clone, Default)]
pub struct StatusInputs {
    /// Managed configuration is present and matches the receipt.
    pub installed: bool,
    /// The AASM core (proxy) answered a liveness probe just now.
    pub core_reachable: bool,
    /// Enforcement is set to observe-only, so decisions are computed and
    /// audited but nothing is enforced.
    pub observe_only: bool,
    /// Evidence gathered, in order.
    pub evidence: Vec<Evidence>,
    /// Drift detected against the receipt.
    pub drift: Vec<DriftFinding>,
    /// Launches seen outside the managed path.
    pub unmanaged_launches: u32,
}

/// A rendered status report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    /// Computed protection level.
    pub level: ProtectionLevel,
    /// Always present, never omitted.
    pub host_enforcement: HostEnforcement,
    /// Mechanisms confirmed by observing behaviour.
    pub confirmed_by_exercise: Vec<String>,
    /// Mechanisms confirmed only by reading configuration.
    pub confirmed_by_read_back: Vec<String>,
    /// Drift findings, expected-versus-actual per mechanism.
    pub drift: Vec<DriftFinding>,
    /// Standing warnings, e.g. the observe-only not-enforcing warning.
    pub warnings: Vec<String>,
    /// Bypasses observed — attributed to the user going around AASM, not to
    /// AASM failing.
    pub bypasses: Vec<String>,
}

impl StatusReport {
    /// Compute a status report from observations.
    ///
    /// Level rules, in order:
    /// 1. Nothing installed, or the core is unreachable → `NotProtected`.
    ///    Unreachable core is explicitly *not protected*, never "unknown".
    /// 2. Observe-only → at most `Integrated`, plus a standing warning.
    /// 3. Drift present → at most `Integrated`; the level drops before repair.
    /// 4. Exercised evidence present → `GatewayProtected`.
    /// 5. Otherwise → `Integrated`.
    pub fn compute(inputs: &StatusInputs) -> Self {
        let confirmed_by_exercise: Vec<String> = inputs
            .evidence
            .iter()
            .filter(|e| matches!(e, Evidence::Exercised { .. }))
            .map(|e| e.mechanism().to_owned())
            .collect();
        let confirmed_by_read_back: Vec<String> = inputs
            .evidence
            .iter()
            .filter(|e| matches!(e, Evidence::ReadBack { .. }))
            .map(|e| e.mechanism().to_owned())
            .collect();

        let mut warnings = Vec::new();
        let mut bypasses = Vec::new();

        let level = if !inputs.installed || !inputs.core_reachable {
            if inputs.installed && !inputs.core_reachable {
                warnings.push("AASM core is not reachable — sessions are NOT protected".to_owned());
            }
            ProtectionLevel::NotProtected
        } else if inputs.observe_only {
            warnings.push(
                "Observe only: decisions are computed and audited but NOT enforced — this is monitoring, \
                 not protection"
                    .to_owned(),
            );
            ProtectionLevel::Integrated
        } else if !inputs.drift.is_empty() {
            warnings.push(format!(
                "{} managed mechanism(s) have drifted — run repair",
                inputs
                    .drift
                    .iter()
                    .map(|d| d.mechanism)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            ));
            ProtectionLevel::Integrated
        } else if confirmed_by_exercise.is_empty() {
            ProtectionLevel::Integrated
        } else {
            ProtectionLevel::GatewayProtected
        };

        if inputs.unmanaged_launches > 0 {
            bypasses.push(format!(
                "{} session(s) launched outside the managed path — those sessions are unprotected. \
                 This is a bypass, not an AASM failure",
                inputs.unmanaged_launches,
            ));
        }

        Self {
            level,
            host_enforcement: HostEnforcement::Unavailable,
            confirmed_by_exercise,
            confirmed_by_read_back,
            drift: inputs.drift.clone(),
            warnings,
            bypasses,
        }
    }

    /// Whether this report claims sensitive-data protection.
    ///
    /// Only `GatewayProtected` may. `Integrated` must never, which is what
    /// scenario 11.8(a) and 11.10 assert.
    pub fn claims_sensitive_data_protection(&self) -> bool {
        self.level == ProtectionLevel::GatewayProtected
    }

    /// Render the report the way a `status` command would.
    pub fn render(&self) -> String {
        let mut out = format!(
            "Protection: {}\n{}\n",
            self.level.as_str(),
            self.host_enforcement.as_str()
        );
        if !self.confirmed_by_exercise.is_empty() {
            out.push_str(&format!(
                "Confirmed by exercise: {}\n",
                self.confirmed_by_exercise.join(", ")
            ));
        }
        if !self.confirmed_by_read_back.is_empty() {
            out.push_str(&format!(
                "Confirmed by read-back only: {}\n",
                self.confirmed_by_read_back.join(", ")
            ));
        }
        for d in &self.drift {
            out.push_str(&format!(
                "DRIFT [{}] {}: expected {} actual {}\n",
                d.mechanism.as_str(),
                d.key,
                d.expected,
                d.actual,
            ));
        }
        for w in &self.warnings {
            out.push_str(&format!("WARNING: {w}\n"));
        }
        for b in &self.bypasses {
            out.push_str(&format!("BYPASS: {b}\n"));
        }
        out
    }
}
