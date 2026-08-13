//! The ADR 0032 §8 metric dictionary, and the bounded label set §9 permits.
//!
//! # Why the counters are derived here and not read from a column
//!
//! Every counter below is computed from
//! [`SensitiveDataEventRow`](aa_gateway::storage::sensitive_data::SensitiveDataEventRow)
//! fields whose meaning is fixed by the projection, never from a stored
//! "blocked findings" total that a producer could disagree with. Two of them
//! deliberately do **not** read the column that shares their name:
//!
//! * `blocked_finding_count` sums `finding_count` over the events whose verdict
//!   is `deny`, because ADR 0032 §8 defines it that way — "an action containing
//!   three findings that is blocked increments `blocked_event_count` by 1 and
//!   `blocked_finding_count` by 3". The row's own `blocked_finding_count`
//!   column is the producer's finding-level disposition tally and is bound by
//!   `transformed + blocked <= total`
//!   ([`FindingCounts::disposition_counts_are_consistent`](aa_core::types::sensitive_data::FindingCounts::disposition_counts_are_consistent)),
//!   so on an action that redacted two findings and then refused the request it
//!   is at most 1. Summing that column would report one blocked finding for an
//!   action that carried three into a refusal.
//! * `redacted_finding_count` sums `transformed_finding_count` over **every**
//!   matching event, blocked ones included, because it counts *transformation
//!   operations performed*, not findings whose redacted form reached the wire.
//!   On a blocked action nothing reached the wire at all. A
//!   "redacted-and-delivered" figure is a different metric conditioned on
//!   execution evidence and is not offered here under a name that would be read
//!   as this one.
//!
//! # Why events and findings never share a counter
//!
//! ADR 0032 forbidden design #11. Every counter's name says which of the two it
//! measures, and the pairs are computed from different expressions rather than
//! one being derived from the other — so a reader cannot pick one and label it
//! the other, and a change that collapses them has to delete a field rather
//! than edit an expression.
//!
//! # Prevention needs evidence, and absence of evidence is not evidence
//!
//! `prevented_event_count` counts only rows for which
//! [`counts_as_prevented_transmission`](aa_gateway::storage::sensitive_data::SensitiveDataEventRow::counts_as_prevented_transmission)
//! holds — ADR 0032 §8's four conditions, conjoined in `aa-core` and re-derived
//! from the three stored evidence columns on every read. A row whose producer
//! recorded nothing (`transmission_evidence = not_recorded`, the honest default
//! of every path AAASM-5358 has not reached) can never satisfy it. This module
//! deliberately has no fallback that treats "we did not observe" as "it did not
//! happen".

use std::collections::BTreeMap;

use aa_core::types::sensitive_data::RuntimeVerdictLabel;
use aa_gateway::storage::sensitive_data::{SensitiveDataEventRow, SensitiveDataFindingRow};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The counters of the ADR 0032 §8 dictionary, over one filtered set of events.
///
/// All `u64`: an aggregate over a window can exceed `u32` where a single
/// event's tallies cannot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SensitiveDataCounters {
    /// **Events** inspected that carried at least one finding, within the
    /// filter. The denominator for every event-level rate below.
    pub event_count: u64,
    /// **Findings** those events carried in total. The denominator for every
    /// finding-level share below. Never interchangeable with `event_count`.
    pub finding_count: u64,
    /// **Events** whose action was refused outright (verdict `deny`).
    /// Denominator: `event_count`.
    pub blocked_event_count: u64,
    /// **Findings** carried by the events that were refused — the whole finding
    /// set of each blocked action, per ADR 0032 §8's worked example.
    /// Denominator: `finding_count`.
    pub blocked_finding_count: u64,
    /// **Events** whose payload was rewritten and then forwarded (verdict
    /// `scrub`). A redacted action is a transformed transmission, so a blocked
    /// action never contributes here however many of its findings were
    /// rewritten first. Denominator: `event_count`.
    pub redacted_event_count: u64,
    /// **Transformation operations performed**, across every matching event
    /// including blocked ones. Not "findings whose redacted form was
    /// transmitted" — see the module doc. Denominator: `finding_count`.
    pub redacted_finding_count: u64,
    /// **Events** meeting all four ADR 0032 §8 prevention conditions.
    /// Denominator: `event_count`.
    pub prevented_event_count: u64,
    /// **Findings** carried by those events. Denominator: `finding_count`.
    pub prevented_finding_count: u64,
    /// **Events** whose detection pass did not run to completion — failed open,
    /// failed closed, or answered from a reduced path. Never folded into a
    /// "clean" count (ADR 0032 forbidden design #2). Denominator: `event_count`.
    pub inspection_incomplete_event_count: u64,
    /// **Events** for which no transmission evidence was recorded at all, so
    /// they could not satisfy the prevention test whatever actually happened
    /// to the payload. Denominator: `event_count`.
    ///
    /// # Why this counter exists next to `prevented_event_count`
    ///
    /// Without it, `prevention_rate = 0` has two completely different meanings
    /// and renders identically: *"we prevented nothing"* and *"nothing measured
    /// whether we prevented anything."* That is the same distinction AAASM-5660
    /// drew for the proxy's evidence sink, arriving here.
    ///
    /// It is load-bearing right now, not hypothetical. The gateway producer
    /// writes `TransmissionEvidence::NotRecorded` unconditionally
    /// (`aa-gateway/src/engine/sensitive_data.rs`) — it decides, it does not
    /// observe the bytes — so **every** row this build can read has no
    /// transmission evidence, and `prevention_rate` is structurally `0`. A
    /// reader who cannot see that reads a truthful zero as a measured one.
    ///
    /// When this equals `event_count`, `prevention_rate` carries no information
    /// about prevention and must not be presented as though it does.
    pub unmeasured_transmission_event_count: u64,
}

/// The derived ratios, each `null` when its denominator is zero.
///
/// An absent rate is reported rather than `0.0`: over an empty window "we
/// blocked nothing" and "nothing happened" are different answers, and the
/// second one rendered as 0% is a fabricated posture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SensitiveDataRates {
    /// `blocked_event_count / event_count`.
    pub block_rate: Option<f64>,
    /// `redacted_event_count / event_count`.
    pub redaction_rate: Option<f64>,
    /// `prevented_event_count / event_count`. Never increments without
    /// execution evidence.
    pub prevention_rate: Option<f64>,
    /// `inspection_incomplete_event_count / event_count`.
    pub inspection_incomplete_rate: Option<f64>,
    /// `unmeasured_transmission_event_count / event_count` — the share of the
    /// window over which `prevention_rate` could not have been measured at all.
    ///
    /// At `1.0`, `prevention_rate` is a rate over an unmeasured denominator and
    /// says nothing about prevention. A consumer must read the two together;
    /// this field exists so it cannot fail to notice.
    pub unmeasured_transmission_rate: Option<f64>,
    /// `finding_count / event_count` — how much sensitive data an average
    /// inspected action carried. The one figure that makes the event/finding
    /// distinction visible on a dashboard.
    pub findings_per_event: Option<f64>,
    /// `blocked_finding_count / finding_count`.
    pub blocked_finding_share: Option<f64>,
    /// `redacted_finding_count / finding_count`.
    pub redacted_finding_share: Option<f64>,
}

/// Divide, or report absent when the denominator is zero.
fn rate(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        return None;
    }
    Some(numerator as f64 / denominator as f64)
}

impl SensitiveDataCounters {
    /// Tally the dictionary over a filtered set of event rows.
    ///
    /// Every row is counted exactly once per counter; the caller is responsible
    /// for having applied the filter, which is why this takes rows rather than
    /// a filter.
    pub fn tally<'a>(rows: impl IntoIterator<Item = &'a SensitiveDataEventRow>) -> Self {
        let mut counters = Self::default();
        for row in rows {
            counters.add(row);
            // Deliberately no early exit / cap: a governance counter that stops
            // at a fixed row ceiling under-reports silently, which is the
            // failure mode `get_agent_enforcement`'s 100 000-event truncation
            // has. The time window is the bound.
        }
        counters
    }

    /// Fold one row into the counters.
    fn add(&mut self, row: &SensitiveDataEventRow) {
        let findings = u64::from(row.finding_count);
        self.event_count += 1;
        self.finding_count += findings;

        let verdict = RuntimeVerdictLabel::from_wire(&row.verdict);
        if verdict == Some(RuntimeVerdictLabel::DENY) {
            self.blocked_event_count += 1;
            // §8: the whole finding set of a blocked action is blocked. Not the
            // row's own `blocked_finding_count`, which is capped by the
            // disposition invariant — see the module doc.
            self.blocked_finding_count += findings;
        }
        if verdict == Some(RuntimeVerdictLabel::SCRUB) {
            self.redacted_event_count += 1;
        }
        // Counted for every verdict: a transformation the pipeline performed
        // happened whether or not the action was ultimately refused.
        self.redacted_finding_count += u64::from(row.transformed_finding_count);

        if row.counts_as_prevented_transmission() {
            self.prevented_event_count += 1;
            self.prevented_finding_count += findings;
        }

        if row.inspection_failure_path != "completed" {
            self.inspection_incomplete_event_count += 1;
        }

        // Read from the stored column rather than from
        // `counts_as_prevented_transmission()` being false: that predicate is
        // false for many honest reasons (an allowed action, a post-transmission
        // decision), and only this one means "nothing observed the bytes".
        if row.transmission_evidence == "not_recorded" {
            self.unmeasured_transmission_event_count += 1;
        }
    }

    /// The derived ratios for these counters.
    pub fn rates(&self) -> SensitiveDataRates {
        SensitiveDataRates {
            block_rate: rate(self.blocked_event_count, self.event_count),
            redaction_rate: rate(self.redacted_event_count, self.event_count),
            prevention_rate: rate(self.prevented_event_count, self.event_count),
            inspection_incomplete_rate: rate(self.inspection_incomplete_event_count, self.event_count),
            unmeasured_transmission_rate: rate(self.unmeasured_transmission_event_count, self.event_count),
            findings_per_event: rate(self.finding_count, self.event_count),
            blocked_finding_share: rate(self.blocked_finding_count, self.finding_count),
            redacted_finding_share: rate(self.redacted_finding_count, self.finding_count),
        }
    }
}

/// A dimension a breakdown may group by.
///
/// **This enum is ADR 0032 §9's bounded label set, spelled as a type.** The
/// permitted names are exactly
/// [`SensitiveDataMetricLabels::LABEL_NAMES`], and
/// [`PERMITTED_NAMES_MATCH_THE_ADR`](Self::names) is asserted against that
/// constant rather than against a second hand-written list, so the two cannot
/// drift.
///
/// The forbidden dimensions — `agent_id`, `destination`, `session_id`,
/// `trace_id`, any fingerprint — have no variant, so `?group_by=agent_id`
/// cannot deserialize and the request is refused rather than answered with an
/// unbounded series. They remain available as **filters** and as drill-down
/// columns on the event surface, which is the queryable event store §9 sends
/// them to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MetricDimension {
    /// What was found, in provider-neutral terms.
    Category,
    /// How damaging exposure would be.
    Severity,
    /// How much the recognizer trusted the finding.
    ConfidenceBand,
    /// The enforcement outcome, as ADR 0018's frozen verdict.
    Outcome,
    /// The technique that produced the finding.
    DetectionMethod,
    /// Which recognizer produced it.
    ProviderId,
}

impl MetricDimension {
    /// Every dimension a breakdown may group by.
    pub const ALL: [Self; 6] = [
        Self::Category,
        Self::Severity,
        Self::ConfidenceBand,
        Self::Outcome,
        Self::DetectionMethod,
        Self::ProviderId,
    ];

    /// The wire spelling, which is also the §9 label name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Category => "category",
            Self::Severity => "severity",
            Self::ConfidenceBand => "confidence_band",
            Self::Outcome => "outcome",
            Self::DetectionMethod => "detection_method",
            Self::ProviderId => "provider_id",
        }
    }

    /// The names of every permitted dimension.
    pub fn names() -> [&'static str; 6] {
        [
            Self::Category.as_str(),
            Self::Severity.as_str(),
            Self::ConfidenceBand.as_str(),
            Self::Outcome.as_str(),
            Self::DetectionMethod.as_str(),
            Self::ProviderId.as_str(),
        ]
    }

    /// This dimension's value on one finding row.
    ///
    /// Reads the finding row rather than the event row because five of the six
    /// dimensions are finding-level; `outcome` is available on the finding row
    /// too, replicated from its parent by AAASM-5357 for exactly this reason.
    pub fn value_of(self, finding: &SensitiveDataFindingRow) -> &str {
        match self {
            Self::Category => &finding.category,
            Self::Severity => &finding.severity,
            Self::ConfidenceBand => &finding.confidence,
            Self::Outcome => &finding.verdict,
            Self::DetectionMethod => &finding.method,
            Self::ProviderId => &finding.recognizer,
        }
    }
}

/// One group of a breakdown, counted both ways.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DimensionBucket {
    /// The dimension value this group is keyed by.
    pub value: String,
    /// How many **findings** fell in this group.
    pub finding_count: u64,
    /// How many distinct **events** carried at least one. Frequently smaller
    /// than `finding_count`, and never the same measure.
    pub event_count: u64,
}

/// Group finding rows by one bounded dimension, reporting both counts.
///
/// Sorted by `finding_count` descending then by `value`, so a "top categories"
/// consumer gets the top N rather than the alphabetically-first N — the caveat
/// [`SensitiveDataEventFilter::limit`](aa_gateway::storage::sensitive_data::SensitiveDataEventFilter)
/// documents about the storage-side aggregate, resolved here where the whole
/// group set is in hand.
pub fn group_findings(dimension: MetricDimension, findings: &[SensitiveDataFindingRow]) -> Vec<DimensionBucket> {
    // BTreeMap over (value -> (finding tally, distinct event ids)) so the
    // event count is distinct-by-event rather than a second finding count.
    let mut groups: BTreeMap<&str, (u64, std::collections::BTreeSet<&str>)> = BTreeMap::new();
    for finding in findings {
        let entry = groups.entry(dimension.value_of(finding)).or_default();
        entry.0 += 1;
        entry.1.insert(finding.event_id.as_str());
    }

    let mut buckets: Vec<DimensionBucket> = groups
        .into_iter()
        .map(|(value, (finding_count, events))| DimensionBucket {
            value: value.to_string(),
            finding_count,
            event_count: events.len() as u64,
        })
        .collect();
    buckets.sort_by(|a, b| {
        b.finding_count
            .cmp(&a.finding_count)
            .then_with(|| a.value.cmp(&b.value))
    });
    buckets
}

#[cfg(test)]
mod tests {
    use aa_core::types::sensitive_data::SensitiveDataMetricLabels;

    use super::*;

    /// **ADR 0032 validation requirement 4 / AC4, at the type level.**
    ///
    /// The dimensions a caller may group by are exactly the six §9 permits, and
    /// the assertion is against `aa-core`'s own constant — not a second list
    /// typed here — so adding a seventh variant fails rather than silently
    /// widening the label set.
    #[test]
    fn the_group_by_dimensions_are_exactly_the_adr_0032_label_set() {
        assert_eq!(MetricDimension::names(), SensitiveDataMetricLabels::LABEL_NAMES);
        assert_eq!(MetricDimension::ALL.len(), SensitiveDataMetricLabels::LABEL_NAMES.len());
    }

    /// Each forbidden dimension fails to deserialize rather than being accepted
    /// and ignored — an ignored `group_by` would answer with the default
    /// grouping and look like a successful query.
    #[test]
    fn the_forbidden_dimensions_do_not_deserialize() {
        for forbidden in [
            "agent_id",
            "destination",
            "destination_id",
            "session_id",
            "trace_id",
            "tenant_id",
            "org_id",
            "team_id",
            "field_path",
            "fingerprint",
            "aggregate_key",
        ] {
            let parsed: Result<MetricDimension, _> =
                serde_json::from_value(serde_json::Value::String(forbidden.to_string()));
            assert!(
                parsed.is_err(),
                "`{forbidden}` deserialized into a group-by dimension; ADR 0032 §9 confines it to the event store"
            );
        }
    }

    /// Every permitted dimension round-trips through its own wire spelling, so
    /// the enum cannot carry a name the API does not accept.
    #[test]
    fn every_permitted_dimension_round_trips_through_its_wire_name() {
        for dimension in MetricDimension::ALL {
            let parsed: MetricDimension =
                serde_json::from_value(serde_json::Value::String(dimension.as_str().to_string()))
                    .expect("a permitted dimension parses from its own name");
            assert_eq!(parsed, dimension);
        }
    }

    /// A rate over an empty window is absent, not zero.
    #[test]
    fn rates_are_absent_rather_than_zero_when_nothing_matched() {
        let rates = SensitiveDataCounters::default().rates();
        assert_eq!(rates.block_rate, None);
        assert_eq!(rates.prevention_rate, None);
        assert_eq!(rates.findings_per_event, None);
        assert_eq!(rates.blocked_finding_share, None);
    }
}
