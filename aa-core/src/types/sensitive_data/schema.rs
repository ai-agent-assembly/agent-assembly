//! The version stamped on every sensitive-data record, and the rule for reading
//! a record written by a different build.

/// The schema version a sensitive-data record was written against.
///
/// Every record in this module carries one, because these records outlive the
/// process that wrote them: an audit row read a year later has to be
/// interpretable by whatever build is reading it, and "whatever build" is not
/// necessarily the one that wrote it.
///
/// # Compatibility rule
///
/// A **major** bump means a reader of the old major cannot interpret the record
/// — a field changed meaning, or a required field was removed. A **minor** bump
/// means fields were only added.
///
/// [`is_readable_by`](Self::is_readable_by) therefore compares majors and
/// ignores minors in *both* directions. A newer writer's record is readable by
/// an older reader, which is the property AAASM-5356 depends on: it adds an
/// optional `sensitive_data_disposition` field to
/// [`SensitiveDataDecisionEvent`](super::SensitiveDataDecisionEvent) as a
/// `1.1` minor bump, and every `1.0` reader must keep working. That is also why
/// none of the types in this module use `serde(deny_unknown_fields)`, unlike
/// [`AuditEvent`](crate::types::AuditEvent) — a strict reader would reject the
/// newer writer's event outright and turn an additive change into a breaking
/// one.
///
/// # Wire format
///
/// A two-field object rather than a `"1.0"` string, so a reader compares
/// integers instead of parsing:
///
/// ```json
/// { "major": 1, "minor": 0 }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct SchemaVersion {
    /// Incompatible revision. A reader of a different major must refuse the record.
    pub major: u16,
    /// Additive revision. Ignored when deciding readability.
    pub minor: u16,
}

impl SchemaVersion {
    /// Name a version.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Whether a record stamped `self` can be interpreted by a `reader` build.
    ///
    /// True exactly when the majors agree. The minor is deliberately not
    /// compared: a newer minor only adds fields, and refusing it would make an
    /// additive change breaking — see the type documentation.
    pub const fn is_readable_by(self, reader: Self) -> bool {
        self.major == reader.major
    }
}

/// The version this build writes and the one it reads natively.
///
/// `1.0` is the initial shape. AAASM-5356's disposition field is the first
/// planned change and is a minor bump.
pub const SENSITIVE_DATA_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

#[cfg(test)]
mod tests {
    use super::*;

    /// A newer writer's record stays readable by an older reader.
    ///
    /// This is the whole reason the minor is ignored. If this regresses,
    /// AAASM-5356 adding `sensitive_data_disposition` as a `1.1` field silently
    /// becomes a breaking change for every `1.0` consumer.
    #[test]
    fn a_newer_minor_is_readable_by_an_older_reader() {
        assert!(SchemaVersion::new(1, 7).is_readable_by(SchemaVersion::new(1, 0)));
    }

    /// The converse: a build that knows `1.1` reads a record written at `1.0`,
    /// treating the absent field as absent rather than as malformed.
    #[test]
    fn an_older_minor_is_readable_by_a_newer_reader() {
        assert!(SchemaVersion::new(1, 0).is_readable_by(SchemaVersion::new(1, 1)));
    }

    /// A major bump is refused in both directions — that is what distinguishes
    /// it from a minor and the only thing that makes the rule load-bearing.
    #[test]
    fn a_differing_major_is_refused_in_both_directions() {
        assert!(!SchemaVersion::new(2, 0).is_readable_by(SchemaVersion::new(1, 9)));
        assert!(!SchemaVersion::new(1, 9).is_readable_by(SchemaVersion::new(2, 0)));
    }

    /// The constant this build stamps. Pinned so a bump is a deliberate edit
    /// with a reviewer looking at it, not a side effect of an unrelated change.
    #[test]
    fn this_build_writes_one_dot_zero() {
        assert_eq!(SENSITIVE_DATA_SCHEMA_VERSION, SchemaVersion::new(1, 0));
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    /// The wire shape, pinned. A schema version that serialized as `"1.0"` in
    /// one build and `{"major":1,…}` in another would make version negotiation
    /// itself the thing that fails to negotiate.
    #[test]
    fn schema_version_serializes_as_a_major_minor_object() {
        assert_eq!(
            serde_json::to_string(&SENSITIVE_DATA_SCHEMA_VERSION).unwrap(),
            r#"{"major":1,"minor":0}"#
        );
    }

    #[test]
    fn schema_version_round_trips() {
        let json = serde_json::to_string(&SchemaVersion::new(3, 12)).unwrap();
        let restored: SchemaVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, SchemaVersion::new(3, 12));
    }
}
