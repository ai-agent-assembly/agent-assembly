//! SDK identity classification (AAASM-3621).
//!
//! A pure, no-I/O classifier that compares the SDK identity an agent *claimed*
//! on the wire (the **observed** signal, attacker-controlled) against the
//! identity an authenticated channel *established* (the **verified** signal,
//! from the AAASM-3569 IPC handshake) and produces an [`SdkIdentityVerdict`].
//!
//! ## Why this is its own pure module
//!
//! The trusted enforcement layers must **never trust an SDK-supplied identity**
//! at face value — they recompute the verdict from inputs they control
//! (extends the AAASM-2569 no-trust-marker principle). Centralising that
//! decision here, with zero I/O and no `tokio` / `aa-proto` dependency, keeps
//! the forged / downgraded logic exhaustively unit-testable without a running
//! runtime. The module mirrors the leaf placement of [`scanner`](crate::scanner)
//! and [`redaction`](crate::redaction).
//!
//! ## What a "version" is here
//!
//! Versions are compared as dot-separated numeric components (a simple
//! `semver`-ish ordering) without pulling in a `semver` crate — the leaf crate
//! stays dependency-light. Non-numeric / malformed components fail closed:
//! an unparseable observed version that has a minimum to clear is treated as a
//! downgrade rather than silently passing.

/// The SDK identity an agent **claimed** on the wire.
///
/// This is the *observed* (untrusted) channel: it is read out of the
/// attacker-controlled `AuditEvent.labels` map by the runtime ingest stage
/// (AAASM-3625). Nothing downstream may grant trust based on these values
/// alone — they exist only to be recomputed against a [`VerifiedSdkIdentity`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ObservedSdkIdentity {
    /// Whether the SDK presented an identity signal at all (the reserved
    /// `aa.sdk_version` label was present). `false` means the agent connected
    /// without claiming any SDK identity — a stripped / bypassed SDK.
    pub present: bool,
    /// The SDK version string the agent claimed, when present.
    pub version: Option<String>,
}

impl ObservedSdkIdentity {
    /// An observed identity that presented a version claim.
    pub fn present(version: impl Into<String>) -> Self {
        Self {
            present: true,
            version: Some(version.into()),
        }
    }

    /// An observed identity with no SDK signal at all (stripped / bypassed SDK).
    pub fn missing() -> Self {
        Self {
            present: false,
            version: None,
        }
    }
}

/// The SDK identity an authenticated channel **established**.
///
/// This is the *verified* counterpart, populated from the AAASM-3569 IPC
/// handshake (which authenticates the agent's Ed25519 identity bound to its
/// configured agent id). When no authenticated version reference is available
/// — no handshake completed, or the handshake carries no version — the fields
/// are `None` and the classifier returns [`SdkIdentityVerdict::Unverifiable`]
/// rather than guessing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifiedSdkIdentity {
    /// The SDK version established over the authenticated channel, when the
    /// channel carries one. `None` when only presence (not a version) was
    /// authenticated, or when no handshake completed.
    pub version: Option<String>,
}

impl VerifiedSdkIdentity {
    /// No verified signal is available (no handshake / unsupported). Classifies
    /// version comparisons as [`SdkIdentityVerdict::Unverifiable`].
    pub fn none() -> Self {
        Self { version: None }
    }

    /// A verified identity carrying an authenticated version reference.
    pub fn with_version(version: impl Into<String>) -> Self {
        Self {
            version: Some(version.into()),
        }
    }

    /// Whether any verified reference is available to compare against.
    pub fn is_available(&self) -> bool {
        self.version.is_some()
    }
}

/// The server-recomputed verdict on an agent's presented SDK identity.
///
/// Ordered so the most security-relevant tampering signals are distinct enum
/// variants the audit / metric layer (AAASM-3637) can label by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SdkIdentityVerdict {
    /// Identity present, matches the verified reference (or no minimum to
    /// clear), and is at or above the minimum supported version.
    Ok,
    /// No SDK identity was presented — a stripped / bypassed SDK.
    Missing,
    /// A version below the minimum supported version was presented (an old /
    /// downgraded SDK build).
    VersionDowngraded,
    /// The observed version contradicts the version established over the
    /// authenticated channel — an impersonation / forgery attempt.
    Forged,
    /// An identity was presented but there is no verified reference to compare
    /// it against (handshake absent / unsupported). Not itself a tamper signal.
    Unverifiable,
}

impl SdkIdentityVerdict {
    /// A stable lowercase label for metric / audit dimensions. Never carries
    /// any agent-supplied free text.
    pub fn as_str(&self) -> &'static str {
        match self {
            SdkIdentityVerdict::Ok => "ok",
            SdkIdentityVerdict::Missing => "missing",
            SdkIdentityVerdict::VersionDowngraded => "downgraded",
            SdkIdentityVerdict::Forged => "forged",
            SdkIdentityVerdict::Unverifiable => "unverifiable",
        }
    }

    /// Whether this verdict is a tamper signal worth a distinct audit record
    /// and metric. `Ok` and `Unverifiable` are not — they are the steady-state
    /// outcomes for a well-behaved or not-yet-attested SDK.
    pub fn is_suspected_tamper(&self) -> bool {
        matches!(
            self,
            SdkIdentityVerdict::Missing | SdkIdentityVerdict::VersionDowngraded | SdkIdentityVerdict::Forged
        )
    }
}

/// Recompute the SDK-identity verdict from inputs the server controls.
///
/// Precedence (most severe first):
/// 1. **`Missing`** — the agent presented no SDK identity at all.
/// 2. **`Forged`** — a verified version reference exists and the observed
///    version contradicts it.
/// 3. **`VersionDowngraded`** — the observed version is below
///    `min_supported_version` (or is unparseable while a minimum is required).
/// 4. **`Unverifiable`** — an identity was presented but there is no verified
///    reference and no minimum to clear.
/// 5. **`Ok`** — otherwise.
///
/// `min_supported_version` is `None` when the operator imposes no floor.
pub fn classify(
    observed: &ObservedSdkIdentity,
    verified: &VerifiedSdkIdentity,
    min_supported_version: Option<&str>,
) -> SdkIdentityVerdict {
    if !observed.present {
        return SdkIdentityVerdict::Missing;
    }

    // Forgery: the claim contradicts what the authenticated channel established.
    if let (Some(claimed), Some(attested)) = (observed.version.as_deref(), verified.version.as_deref()) {
        if !versions_equal(claimed, attested) {
            return SdkIdentityVerdict::Forged;
        }
    }

    // Downgrade: below the operator-configured minimum.
    if let Some(min) = min_supported_version {
        match observed.version.as_deref() {
            Some(claimed) if version_at_least(claimed, min) => {}
            // A claimed-but-unparseable or below-minimum version is a downgrade
            // (fail closed — never pass an unparseable version against a floor).
            _ => return SdkIdentityVerdict::VersionDowngraded,
        }
    }

    // Present, consistent with any verified reference, but no verified reference
    // and no floor cleared by comparison: nothing left to attest against.
    if !verified.is_available() && min_supported_version.is_none() {
        return SdkIdentityVerdict::Unverifiable;
    }

    SdkIdentityVerdict::Ok
}

/// Compare two dot-separated numeric version strings for equality, padding the
/// shorter with implicit zero components (`"1.2" == "1.2.0"`).
fn versions_equal(a: &str, b: &str) -> bool {
    matches!(compare_versions(a, b), Some(std::cmp::Ordering::Equal))
}

/// `true` when `version >= min`. An unparseable `version` or `min` yields
/// `false` (fail closed against the floor).
fn version_at_least(version: &str, min: &str) -> bool {
    matches!(
        compare_versions(version, min),
        Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
    )
}

/// Compare two dot-separated numeric versions component-by-component.
///
/// Returns `None` when either side has a non-numeric component, so callers can
/// fail closed on malformed input rather than treating it as comparable.
fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    let pa = parse_components(a)?;
    let pb = parse_components(b)?;
    let len = pa.len().max(pb.len());
    for i in 0..len {
        let ca = pa.get(i).copied().unwrap_or(0);
        let cb = pb.get(i).copied().unwrap_or(0);
        match ca.cmp(&cb) {
            std::cmp::Ordering::Equal => continue,
            other => return Some(other),
        }
    }
    Some(std::cmp::Ordering::Equal)
}

/// Parse `"1.2.3"` into `[1, 2, 3]`. Returns `None` on any non-numeric or empty
/// component so malformed versions are not silently treated as comparable.
fn parse_components(v: &str) -> Option<Vec<u64>> {
    if v.is_empty() {
        return None;
    }
    v.split('.').map(|c| c.parse::<u64>().ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_when_not_present() {
        let observed = ObservedSdkIdentity::missing();
        let verdict = classify(&observed, &VerifiedSdkIdentity::none(), Some("1.0.0"));
        assert_eq!(verdict, SdkIdentityVerdict::Missing);
    }

    #[test]
    fn missing_takes_precedence_over_a_verified_reference() {
        // No identity presented at all, even if a verified version exists.
        let observed = ObservedSdkIdentity::missing();
        let verified = VerifiedSdkIdentity::with_version("2.0.0");
        assert_eq!(classify(&observed, &verified, None), SdkIdentityVerdict::Missing);
    }

    #[test]
    fn forged_when_observed_version_mismatches_verified() {
        let observed = ObservedSdkIdentity::present("9.9.9");
        let verified = VerifiedSdkIdentity::with_version("1.2.3");
        assert_eq!(classify(&observed, &verified, None), SdkIdentityVerdict::Forged);
    }

    #[test]
    fn forged_beats_downgrade_when_both_apply() {
        // Observed contradicts the verified reference AND is below the floor:
        // the impersonation signal (Forged) is the more severe verdict.
        let observed = ObservedSdkIdentity::present("0.1.0");
        let verified = VerifiedSdkIdentity::with_version("2.0.0");
        assert_eq!(
            classify(&observed, &verified, Some("1.0.0")),
            SdkIdentityVerdict::Forged
        );
    }

    #[test]
    fn ok_when_observed_matches_verified() {
        let observed = ObservedSdkIdentity::present("1.2.3");
        let verified = VerifiedSdkIdentity::with_version("1.2.3");
        assert_eq!(classify(&observed, &verified, None), SdkIdentityVerdict::Ok);
    }

    #[test]
    fn ok_when_observed_matches_verified_with_zero_padding() {
        // "1.2" and "1.2.0" are equal under implicit-zero padding, so a match
        // is not flagged as forged.
        let observed = ObservedSdkIdentity::present("1.2");
        let verified = VerifiedSdkIdentity::with_version("1.2.0");
        assert_eq!(classify(&observed, &verified, None), SdkIdentityVerdict::Ok);
    }

    #[test]
    fn version_downgraded_below_minimum() {
        let observed = ObservedSdkIdentity::present("0.9.0");
        let verdict = classify(&observed, &VerifiedSdkIdentity::none(), Some("1.0.0"));
        assert_eq!(verdict, SdkIdentityVerdict::VersionDowngraded);
    }

    #[test]
    fn ok_at_exactly_the_minimum() {
        let observed = ObservedSdkIdentity::present("1.0.0");
        let verdict = classify(&observed, &VerifiedSdkIdentity::none(), Some("1.0.0"));
        assert_eq!(verdict, SdkIdentityVerdict::Ok);
    }

    #[test]
    fn ok_above_the_minimum() {
        let observed = ObservedSdkIdentity::present("1.5.2");
        let verdict = classify(&observed, &VerifiedSdkIdentity::none(), Some("1.0.0"));
        assert_eq!(verdict, SdkIdentityVerdict::Ok);
    }

    #[test]
    fn unparseable_version_against_a_floor_fails_closed_as_downgrade() {
        // A non-numeric claimed version must never silently pass a floor.
        let observed = ObservedSdkIdentity::present("not-a-version");
        let verdict = classify(&observed, &VerifiedSdkIdentity::none(), Some("1.0.0"));
        assert_eq!(verdict, SdkIdentityVerdict::VersionDowngraded);
    }

    #[test]
    fn unverifiable_when_present_but_no_verified_reference_and_no_floor() {
        let observed = ObservedSdkIdentity::present("1.2.3");
        let verdict = classify(&observed, &VerifiedSdkIdentity::none(), None);
        assert_eq!(verdict, SdkIdentityVerdict::Unverifiable);
    }

    #[test]
    fn present_without_a_claimed_version_and_no_floor_is_unverifiable() {
        // present == true but no version string and nothing to compare against.
        let observed = ObservedSdkIdentity {
            present: true,
            version: None,
        };
        let verdict = classify(&observed, &VerifiedSdkIdentity::none(), None);
        assert_eq!(verdict, SdkIdentityVerdict::Unverifiable);
    }

    #[test]
    fn as_str_labels_are_stable() {
        assert_eq!(SdkIdentityVerdict::Ok.as_str(), "ok");
        assert_eq!(SdkIdentityVerdict::Missing.as_str(), "missing");
        assert_eq!(SdkIdentityVerdict::VersionDowngraded.as_str(), "downgraded");
        assert_eq!(SdkIdentityVerdict::Forged.as_str(), "forged");
        assert_eq!(SdkIdentityVerdict::Unverifiable.as_str(), "unverifiable");
    }

    #[test]
    fn only_missing_downgraded_forged_are_suspected_tamper() {
        assert!(SdkIdentityVerdict::Missing.is_suspected_tamper());
        assert!(SdkIdentityVerdict::VersionDowngraded.is_suspected_tamper());
        assert!(SdkIdentityVerdict::Forged.is_suspected_tamper());
        assert!(!SdkIdentityVerdict::Ok.is_suspected_tamper());
        assert!(!SdkIdentityVerdict::Unverifiable.is_suspected_tamper());
    }
}
