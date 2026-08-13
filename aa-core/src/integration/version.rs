//! Version representation and compatibility classification for Developer
//! Integrations.
//!
//! # Why a hand-rolled version type
//!
//! Version comparison is load-bearing for two ADR 0030 rules — Decision 2 row 1
//! ("only the adapter knows what a version *means* for its tool") and Decision 4's
//! `Incompatible` state, which must be **reportable** rather than silently
//! degrading. `aa-core` is the dependency-light domain crate every adapter links
//! transitively, so this module implements the small subset of ordering the
//! contract actually needs (`major.minor.patch` plus "a pre-release sorts below
//! its release") instead of pulling a general-purpose semver parser into it.
//!
//! # The fail-absent rule this module encodes
//!
//! [`SupportedToolVersions::classify`] never answers
//! [`VersionCompatibility::Compatible`] when the detected version is unknown. A
//! missing version is a **missing comparison**, not a pass — ADR 0029's rule 1,
//! transferred by ADR 0030 §3.4 rule 2.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wire-schema version of the Developer Integration lifecycle types in this
/// module tree.
///
/// Carried by [`IntegrationPlan`](crate::integration::IntegrationPlan) and
/// [`IntegrationReceipt`](crate::integration::IntegrationReceipt) so a receipt
/// written by a newer core can be detected — and reported as
/// [`ProtectionState::Incompatible`](crate::integration::ProtectionState::Incompatible)
/// — rather than misread by an older one (ADR 0030 §4.1).
pub const LIFECYCLE_SCHEMA_VERSION: u32 = 1;

/// Failure to parse a [`ToolVersion`] from a string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a recognisable version string: {input:?} ({detail})")]
pub struct VersionParseError {
    /// The string that could not be parsed.
    pub input: String,
    /// Why it could not be parsed.
    pub detail: &'static str,
}

/// A dotted numeric version with an optional pre-release tag.
///
/// Accepts `1`, `1.2`, `1.2.3`, `1.2.3-rc.6` and `1.2.3+build.7` (build metadata
/// is parsed and discarded, matching semver's rule that it does not participate
/// in ordering). Missing components default to zero, so `1.2` == `1.2.0`.
///
/// ## Ordering
///
/// Numeric components compare first. When they are equal, a version **with** a
/// pre-release tag sorts **below** the same version without one, so
/// `2.1.0-rc.1 < 2.1.0`. This is why [`Ord`] is implemented by hand: the derived
/// implementation would order `None < Some(_)` and invert that rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct ToolVersion {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<String>,
}

impl ToolVersion {
    /// Construct a release version (no pre-release tag).
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: None,
        }
    }

    /// Major component.
    pub const fn major(&self) -> u64 {
        self.major
    }

    /// Minor component.
    pub const fn minor(&self) -> u64 {
        self.minor
    }

    /// Patch component.
    pub const fn patch(&self) -> u64 {
        self.patch
    }

    /// Pre-release tag, if the version carried one (`rc.6` for `0.0.1-rc.6`).
    pub fn pre_release(&self) -> Option<&str> {
        self.pre.as_deref()
    }
}

impl fmt::Display for ToolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        match &self.pre {
            Some(pre) => write!(f, "-{pre}"),
            None => Ok(()),
        }
    }
}

impl Ord for ToolVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                // A release outranks its own pre-releases.
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(b),
            })
    }
}

impl PartialOrd for ToolVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FromStr for ToolVersion {
    type Err = VersionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim().trim_start_matches('v');
        // Build metadata never participates in ordering, so drop it up front.
        let without_build = trimmed.split('+').next().unwrap_or(trimmed);
        let (core, pre) = match without_build.split_once('-') {
            Some((core, pre)) if !pre.is_empty() => (core, Some(pre.to_string())),
            _ => (without_build, None),
        };

        let mut parts = core.split('.');
        let mut next = |detail: &'static str| -> Result<u64, VersionParseError> {
            match parts.next() {
                None => Ok(0),
                Some(raw) => raw.parse::<u64>().map_err(|_| VersionParseError {
                    input: s.to_string(),
                    detail,
                }),
            }
        };

        let major = next("major component is not a number")?;
        let minor = next("minor component is not a number")?;
        let patch = next("patch component is not a number")?;
        if parts.next().is_some() {
            return Err(VersionParseError {
                input: s.to_string(),
                detail: "more than three dotted numeric components",
            });
        }

        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl TryFrom<String> for ToolVersion {
    type Error = VersionParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<ToolVersion> for String {
    fn from(value: ToolVersion) -> Self {
        value.to_string()
    }
}

/// The `aa-core` version the running lifecycle implementation was built from.
///
/// # Panics
///
/// Panics if `aa-core`'s own `CARGO_PKG_VERSION` stops being parseable by
/// [`ToolVersion`]. That is a build-configuration error, not a runtime
/// condition, and is covered by a unit test in this module.
pub fn core_version() -> ToolVersion {
    env!("CARGO_PKG_VERSION")
        .parse()
        .expect("aa-core CARGO_PKG_VERSION must parse as a ToolVersion")
}

/// The range of tool versions one adapter claims to understand.
///
/// Owned by the adapter (ADR 0030 Decision 2, row 1): a generic comparator in
/// the service would have to encode per-tool knowledge, which is the adapter's
/// entire reason to exist.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SupportedToolVersions {
    /// Lowest tool version this adapter supports, inclusive. `None` means the
    /// adapter claims no known lower bound.
    ///
    /// A bound is `Option` on both ends rather than defaulting the lower one to
    /// `0.0.0`, because `0.0.0` is *not* the bottom of the ordering: a
    /// pre-release sorts below its release, so `0.0.0-sample` is below `0.0.0`
    /// and a "no lower bound" expressed as `0.0.0` would reject it. That is not
    /// hypothetical — it is exactly what `examples/aa-devtool-sample-myeditor`
    /// reports, and an adapter that has declared no range must not be able to
    /// call a version incompatible by accident.
    pub min: Option<ToolVersion>,
    /// First tool version this adapter does **not** support, exclusive. `None`
    /// means the adapter claims no known upper bound.
    pub max_exclusive: Option<ToolVersion>,
}

impl SupportedToolVersions {
    /// A range with no bound at either end — every version is inside it.
    pub fn any() -> Self {
        Self {
            min: None,
            max_exclusive: None,
        }
    }

    /// A range with a lower bound and no known upper bound.
    pub fn at_least(min: ToolVersion) -> Self {
        Self {
            min: Some(min),
            max_exclusive: None,
        }
    }

    /// A half-open range `[min, max_exclusive)`.
    pub fn between(min: ToolVersion, max_exclusive: ToolVersion) -> Self {
        Self {
            min: Some(min),
            max_exclusive: Some(max_exclusive),
        }
    }

    /// Whether `version` falls inside this range.
    pub fn contains(&self, version: &ToolVersion) -> bool {
        // `Option::is_none_or` would read better but is stable only from 1.82;
        // this crate's MSRV is 1.75.
        self.min.as_ref().map_or(true, |min| version >= min)
            && self.max_exclusive.as_ref().map_or(true, |max| version < max)
    }

    /// Classify a detected version against this range.
    ///
    /// A `detected` of `None` yields [`VersionCompatibility::Unknown`], **never**
    /// [`VersionCompatibility::Compatible`] — see the module docs.
    pub fn classify(&self, detected: Option<&ToolVersion>) -> VersionCompatibility {
        let Some(detected) = detected else {
            return VersionCompatibility::Unknown {
                reason: "the tool's version could not be determined; a missing version is a \
                         missing comparison, not a pass"
                    .to_string(),
            };
        };

        if self.contains(detected) {
            return VersionCompatibility::Compatible {
                detected: detected.clone(),
            };
        }

        let below_min = self.min.as_ref().is_some_and(|min| detected < min);
        let remediation = if below_min {
            format!(
                "upgrade the tool to {} or newer",
                self.min.as_ref().expect("below_min implies a lower bound")
            )
        } else {
            format!(
                "this Agent Assembly build supports tool versions below {}; upgrade Agent Assembly",
                self.max_exclusive
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "the adapter's upper bound".to_string())
            )
        };

        VersionCompatibility::Incompatible {
            detected: Some(detected.clone()),
            supported: self.clone(),
            remediation,
        }
    }
}

/// Outcome of comparing a detected tool version against an adapter's supported
/// range.
///
/// `Unknown` exists as a distinct variant precisely so that "we could not tell"
/// can never be rendered as "compatible".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum VersionCompatibility {
    /// The detected version is inside the adapter's supported range.
    Compatible {
        /// The version that was detected and compared.
        detected: ToolVersion,
    },
    /// No comparison could be made. Resolves **downward** wherever a protection
    /// state is derived (ADR 0030 §4.2 rule 2).
    Unknown {
        /// User-facing explanation of why the comparison could not be made.
        reason: String,
    },
    /// The detected version is outside the adapter's supported range.
    Incompatible {
        /// The version that was detected, when one was.
        detected: Option<ToolVersion>,
        /// The range the adapter claims to support.
        supported: SupportedToolVersions,
        /// Actionable text telling the user which side to upgrade.
        remediation: String,
    },
}

impl VersionCompatibility {
    /// True only for [`Compatible`](Self::Compatible). `Unknown` is deliberately
    /// not compatible.
    pub fn is_compatible(&self) -> bool {
        matches!(self, Self::Compatible { .. })
    }

    /// True for [`Incompatible`](Self::Incompatible).
    pub fn is_incompatible(&self) -> bool {
        matches!(self, Self::Incompatible { .. })
    }
}

/// The versions of every component that participates in one integration.
///
/// Recorded in [`IntegrationReceipt`](crate::integration::IntegrationReceipt) so
/// a later status read can tell "verified by an older core" from "verified by
/// this one".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ComponentVersions {
    /// `aa-core` version the lifecycle implementation was built from.
    pub core: ToolVersion,
    /// The adapter crate's own version.
    pub adapter: ToolVersion,
    /// [`LIFECYCLE_SCHEMA_VERSION`] the adapter was compiled against.
    pub lifecycle_schema: u32,
}

/// Everything an adapter declares about versions, returned as one value so the
/// lifecycle trait needs a single accessor rather than three.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VersionSupport {
    /// The adapter crate's own version.
    pub adapter_version: ToolVersion,
    /// [`LIFECYCLE_SCHEMA_VERSION`] the adapter was compiled against.
    pub lifecycle_schema_version: u32,
    /// Tool versions this adapter claims to understand.
    pub supported_tool_versions: SupportedToolVersions,
}

impl VersionSupport {
    /// Combine the adapter's declaration with the running [`core_version`].
    pub fn component_versions(&self) -> ComponentVersions {
        ComponentVersions {
            core: core_version(),
            adapter: self.adapter_version.clone(),
            lifecycle_schema: self.lifecycle_schema_version,
        }
    }

    /// Whether the adapter's schema version is one this core can read.
    ///
    /// An adapter compiled against a *newer* schema than the running core is
    /// reported as incompatible rather than read optimistically.
    pub fn is_schema_readable(&self) -> bool {
        self.lifecycle_schema_version <= LIFECYCLE_SCHEMA_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_shapes_real_tools_report() {
        // Claude Code 2.1.220, measured in the AAASM-5276 spike.
        assert_eq!("2.1.220".parse::<ToolVersion>().unwrap(), ToolVersion::new(2, 1, 220));
        assert_eq!("v1.4".parse::<ToolVersion>().unwrap(), ToolVersion::new(1, 4, 0));
        assert_eq!("3".parse::<ToolVersion>().unwrap(), ToolVersion::new(3, 0, 0));

        let rc: ToolVersion = "0.0.1-rc.6".parse().unwrap();
        assert_eq!(rc.pre_release(), Some("rc.6"));
        assert_eq!(rc.to_string(), "0.0.1-rc.6");

        // Build metadata parses but does not survive into the value.
        assert_eq!(
            "1.2.3+build.9".parse::<ToolVersion>().unwrap(),
            ToolVersion::new(1, 2, 3)
        );
    }

    #[test]
    fn rejects_non_numeric_and_over_long_versions() {
        assert!("1.x.3".parse::<ToolVersion>().is_err());
        assert!("1.2.3.4".parse::<ToolVersion>().is_err());
    }

    #[test]
    fn a_pre_release_sorts_below_its_release() {
        let rc: ToolVersion = "2.1.0-rc.1".parse().unwrap();
        let release = ToolVersion::new(2, 1, 0);
        assert!(rc < release, "{rc} must sort below {release}");
        assert!(ToolVersion::new(2, 0, 9) < rc);
    }

    #[test]
    fn core_version_is_parseable() {
        // Guards the documented panic in `core_version`.
        let v = core_version();
        assert!(v.to_string().starts_with(&format!("{}.", v.major())));
    }

    #[test]
    fn unknown_version_is_never_compatible() {
        let supported = SupportedToolVersions::at_least(ToolVersion::new(2, 0, 0));
        let classified = supported.classify(None);
        assert!(!classified.is_compatible());
        assert!(matches!(classified, VersionCompatibility::Unknown { .. }));
    }

    #[test]
    fn classify_reports_which_side_to_upgrade() {
        let supported = SupportedToolVersions::between(ToolVersion::new(2, 0, 0), ToolVersion::new(3, 0, 0));

        assert!(supported.classify(Some(&ToolVersion::new(2, 1, 220))).is_compatible());

        match supported.classify(Some(&ToolVersion::new(1, 9, 0))) {
            VersionCompatibility::Incompatible { remediation, .. } => {
                assert!(remediation.contains("upgrade the tool"), "{remediation}");
            }
            other => panic!("expected Incompatible, got {other:?}"),
        }

        match supported.classify(Some(&ToolVersion::new(3, 0, 0))) {
            VersionCompatibility::Incompatible { remediation, .. } => {
                assert!(remediation.contains("upgrade Agent Assembly"), "{remediation}");
            }
            other => panic!("expected Incompatible, got {other:?}"),
        }
    }

    #[test]
    fn an_unbounded_range_accepts_pre_releases_below_zero() {
        // `0.0.0` is not the bottom of the ordering: a pre-release sorts below
        // its release. An adapter that declared no range must not reject the
        // public sample's own "0.0.0-sample".
        let any = SupportedToolVersions::any();
        let sample: ToolVersion = "0.0.0-sample".parse().unwrap();
        assert!(any.contains(&sample));
        assert!(any.classify(Some(&sample)).is_compatible());

        // Whereas an explicit `>= 0.0.0` genuinely does exclude it.
        assert!(!SupportedToolVersions::at_least(ToolVersion::new(0, 0, 0)).contains(&sample));
    }

    #[test]
    fn version_support_flags_a_newer_schema_as_unreadable() {
        let support = VersionSupport {
            adapter_version: ToolVersion::new(1, 0, 0),
            lifecycle_schema_version: LIFECYCLE_SCHEMA_VERSION + 1,
            supported_tool_versions: SupportedToolVersions::at_least(ToolVersion::new(1, 0, 0)),
        };
        assert!(!support.is_schema_readable());
        assert_eq!(support.component_versions().core, core_version());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn tool_version_round_trips_as_a_string() {
        let original: ToolVersion = "2.1.220-rc.6".parse().unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"2.1.220-rc.6\"");
        assert_eq!(serde_json::from_str::<ToolVersion>(&json).unwrap(), original);
    }
}
