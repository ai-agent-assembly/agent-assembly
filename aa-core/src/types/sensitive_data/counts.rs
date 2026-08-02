//! Finding counts, kept rigorously separate from event counts.

use alloc::vec::Vec;

use super::{CategoryLabel, SensitiveDataFindingRecord};

/// How many findings of one category an event carried.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct CategoryCount {
    /// The category counted.
    pub category: CategoryLabel,
    /// How many findings of it. Never zero in a tallied set.
    pub count: u32,
}

/// Why a set of counts was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CountsError {
    /// More findings were said to be transformed and blocked than exist.
    ///
    /// A finding is transformed or blocked, not both, so the two together
    /// cannot exceed the total. Left unchecked, this is how a prevention
    /// dashboard ends up reporting more blocked findings than findings.
    DispositionCountsExceedTotal,
}

impl core::fmt::Display for CountsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DispositionCountsExceedTotal => {
                f.write_str("transformed + blocked finding counts exceed the total finding count")
            }
        }
    }
}

impl std::error::Error for CountsError {}

/// The finding-level tallies for one inspected action.
///
/// # Findings are not events
///
/// ADR 0032 §8 and forbidden design #11: event counts and finding counts are
/// distinct metrics and may never be collapsed. One event carries many
/// findings, so the two answer different questions — "how many actions did we
/// block?" and "how much sensitive data did we stop?" — and a dashboard that
/// conflates them is wrong by a factor that varies per action.
///
/// **Nothing in this struct is an event count.** Every field here counts
/// findings; the event-level counts are
/// [`blocked_event_count`](super::SensitiveDataDecisionEvent::blocked_event_count)
/// and its neighbours, which live on the event and are named so the difference
/// is visible at the call site. The §8 worked example — three findings in one
/// blocked action gives `blocked_event_count = 1` and
/// `blocked_finding_count = 3` — is asserted on the event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct FindingCounts {
    /// Total findings in the inspected action.
    pub total: u32,
    /// Findings per category, in first-seen order.
    pub by_category: Vec<CategoryCount>,
    /// Findings whose value was rewritten — redacted, masked or tokenized — and
    /// then **forwarded**. A transformed finding is not a prevented one.
    pub transformed: u32,
    /// Findings whose action was refused outright.
    pub blocked: u32,
}

impl FindingCounts {
    /// Tally a set of finding rows.
    ///
    /// `total` and `by_category` are computed from `records`, so they cannot
    /// disagree with each other or with the rows they describe. `transformed`
    /// and `blocked` are supplied because they are properties of the
    /// enforcement decision, not of the findings.
    ///
    /// # Errors
    ///
    /// [`CountsError::DispositionCountsExceedTotal`] if `transformed + blocked`
    /// is greater than the number of records.
    pub fn tally(records: &[SensitiveDataFindingRecord], transformed: u32, blocked: u32) -> Result<Self, CountsError> {
        let total = u32::try_from(records.len()).unwrap_or(u32::MAX);
        if u64::from(transformed) + u64::from(blocked) > u64::from(total) {
            return Err(CountsError::DispositionCountsExceedTotal);
        }

        let mut by_category: Vec<CategoryCount> = Vec::new();
        for record in records {
            match by_category.iter_mut().find(|entry| entry.category == record.category) {
                Some(entry) => entry.count += 1,
                None => by_category.push(CategoryCount {
                    category: record.category.clone(),
                    count: 1,
                }),
            }
        }

        Ok(Self {
            total,
            by_category,
            transformed,
            blocked,
        })
    }

    /// Findings of one category, or zero if none were seen.
    pub fn of_category(&self, category: &CategoryLabel) -> u32 {
        self.by_category
            .iter()
            .find(|entry| &entry.category == category)
            .map_or(0, |entry| entry.count)
    }

    /// Whether the per-category breakdown accounts for exactly `total`.
    ///
    /// Always true for a tallied set. Worth asking of a deserialized one, which
    /// is whatever the writer stored.
    pub fn breakdown_is_complete(&self) -> bool {
        let summed: u64 = self.by_category.iter().map(|entry| u64::from(entry.count)).sum();
        summed == u64::from(self.total)
    }
}

#[cfg(test)]
mod tests {
    use aa_security::canonical::{
        ByteSpan, CanonicalCategory, CanonicalFinding, CategoryBase, ConfidenceBand, DetectionMethod, FindingStatus,
        Provenance, Recognizer, Severity,
    };

    use super::*;
    use crate::types::sensitive_data::FieldPath;

    fn record(category: CanonicalCategory, path: &str) -> SensitiveDataFindingRecord {
        let finding = CanonicalFinding::new(
            category,
            Severity::Critical,
            ConfidenceBand::High,
            ByteSpan::new(0, 8),
            DetectionMethod::Deterministic,
            Provenance::new(Recognizer::BuiltinScanner, "0.0.0-test"),
            FindingStatus::Confirmed,
        )
        .unwrap();
        SensitiveDataFindingRecord::from_finding(&finding, FieldPath::parse(path).unwrap()).unwrap()
    }

    #[test]
    fn a_tally_counts_each_category_separately() {
        let email = CanonicalCategory::unqualified(CategoryBase::EmailAddress);
        let token = CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access");
        let counts = FindingCounts::tally(
            &[
                record(email, "body.a"),
                record(email, "body.b"),
                record(token, "body.c"),
            ],
            0,
            3,
        )
        .unwrap();

        assert_eq!(counts.total, 3);
        assert_eq!(counts.of_category(&CategoryLabel::from(email)), 2);
        assert_eq!(counts.of_category(&CategoryLabel::from(token)), 1);
        assert!(counts.breakdown_is_complete());
    }

    /// A category nobody saw counts zero rather than being absent-and-awkward.
    #[test]
    fn an_unseen_category_counts_zero() {
        let counts = FindingCounts::tally(&[], 0, 0).unwrap();
        assert_eq!(
            counts.of_category(&CategoryLabel::from(CanonicalCategory::unqualified(
                CategoryBase::EmailAddress
            ))),
            0
        );
    }

    /// A finding is transformed or blocked, never both, so the two cannot
    /// exceed the total. Without this a prevention dashboard can report more
    /// blocked findings than there were findings.
    #[test]
    fn disposition_counts_cannot_exceed_the_total() {
        let email = CanonicalCategory::unqualified(CategoryBase::EmailAddress);
        let records = [record(email, "body.a"), record(email, "body.b")];

        assert_eq!(
            FindingCounts::tally(&records, 2, 1),
            Err(CountsError::DispositionCountsExceedTotal)
        );
        assert!(FindingCounts::tally(&records, 1, 1).is_ok());
        assert!(
            FindingCounts::tally(&records, 0, 0).is_ok(),
            "an action can leave findings neither transformed nor blocked"
        );
    }

    /// A breakdown that does not sum to the total is detectable. This can only
    /// arise from a deserialized record, which is exactly when it matters.
    #[test]
    fn an_inconsistent_breakdown_is_detectable() {
        let mut counts = FindingCounts::tally(&[], 0, 0).unwrap();
        counts.total = 5;
        assert!(!counts.breakdown_is_complete());
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn finding_counts_round_trip() {
        let counts = FindingCounts {
            total: 3,
            by_category: alloc::vec![CategoryCount {
                category: CategoryLabel::new("EMAIL_ADDRESS").unwrap(),
                count: 3,
            }],
            transformed: 0,
            blocked: 3,
        };
        let json = serde_json::to_string(&counts).unwrap();
        let restored: FindingCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, counts);
    }

    /// The counts are named on the wire, not positional, and `transformed` and
    /// `blocked` are separate keys. A single `disposition_count` would be the
    /// collapse ADR 0032 forbids.
    #[test]
    fn transformed_and_blocked_are_separate_wire_fields() {
        let json = serde_json::to_value(FindingCounts {
            total: 3,
            by_category: Vec::new(),
            transformed: 1,
            blocked: 2,
        })
        .unwrap();
        assert_eq!(json["total"], 3);
        assert_eq!(json["transformed"], 1);
        assert_eq!(json["blocked"], 2);
    }
}
