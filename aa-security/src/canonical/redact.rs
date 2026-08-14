//! Redacting text from canonical findings.
//!
//! [`ScanResult::redact`](crate::scanner::ScanResult::redact) can only redact
//! what a [`CredentialFinding`](crate::scanner::CredentialFinding) describes,
//! and a locale pack's findings are not that — they carry a category with no
//! `CredentialKind` (ADR 0032 §2 freezes `CredentialKind::ALL`). This is the
//! equivalent for [`CanonicalFinding`]s, and it deliberately reproduces that
//! function's two hard-won properties rather than reinventing them:
//!
//! - **Overlapping spans are coalesced before splicing.** Redacting overlapping
//!   spans one at a time leaves raw fragments of the value between the
//!   replacements and mangles the labels (AAASM-4093).
//! - **A span that cannot be spliced fails closed.** An out-of-range bound, or
//!   one that does not fall on a character boundary, still marks a region
//!   something flagged as sensitive. Skipping it would emit that region's raw
//!   bytes, so the whole value is replaced with an opaque label instead.

use super::{CanonicalCategory, CanonicalFinding};

/// One non-overlapping region to replace, and what to replace it with.
struct MergedSpan {
    start: usize,
    end: usize,
    /// `Some` while every finding merged into this span agrees on the category,
    /// `None` once two disagree.
    category: Option<CanonicalCategory>,
}

impl MergedSpan {
    /// The replacement text for this region.
    ///
    /// When two findings of different categories cover one region there is no
    /// single correct label, so the opaque `[REDACTED]` is emitted rather than
    /// picking a winner. Ranking them would need an order over
    /// [`ConfidenceBand`](super::ConfidenceBand), which is deliberately not
    /// `PartialOrd` — confidence is evidence, never an input to a decision (ADR
    /// 0032 §4) — and "top-scoring entity wins" is an explicitly forbidden
    /// design. Losing label precision on an overlap is the cheaper mistake; the
    /// bytes are gone either way.
    fn label(&self) -> String {
        match self.category {
            Some(category) => category.redaction_label(),
            None => "[REDACTED]".to_string(),
        }
    }
}

/// Return a copy of `text` with every finding's span replaced by its category's
/// redaction label.
///
/// `findings` need not be sorted and may overlap. Spans must be byte offsets
/// into `text`; a span that is out of range or lands mid-character makes the
/// whole result the opaque `[REDACTED]`, because a flagged region that cannot be
/// proved removed must never be returned intact.
///
/// A finding whose category has no [`CredentialKind`](crate::scanner::CredentialKind)
/// — every locale-pack finding — redacts to a bare `[REDACTED]`. Inventing a
/// `[REDACTED:NATIONAL_ID[zh-TW/arc_new]]` label would publish a pattern name
/// that `GET /api/v1/scrub/patterns` does not list, extending a frozen catalogue
/// by accident.
pub fn redact_findings(text: &str, findings: &[CanonicalFinding]) -> String {
    let mut sorted: Vec<&CanonicalFinding> = findings.iter().collect();
    sorted.sort_by_key(|f| (f.span().start(), f.span().end()));

    let mut merged: Vec<MergedSpan> = Vec::with_capacity(sorted.len());
    for finding in sorted {
        let (start, end) = (finding.span().start(), finding.span().end());
        match merged.last_mut() {
            Some(last) if start < last.end => {
                last.end = last.end.max(end);
                if last.category != Some(finding.category()) {
                    last.category = None;
                }
            }
            _ => merged.push(MergedSpan {
                start,
                end,
                category: Some(finding.category()),
            }),
        }
    }

    let mut result = text.to_string();
    // Reverse order, so each replacement leaves the earlier offsets valid.
    for span in merged.iter().rev() {
        if span.end <= result.len()
            && span.start <= span.end
            && result.is_char_boundary(span.start)
            && result.is_char_boundary(span.end)
        {
            result.replace_range(span.start..span.end, &span.label());
        } else {
            return "[REDACTED]".to_string();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{
        ByteSpan, CategoryBase, ConfidenceBand, DetectionMethod, FindingStatus, Severity, SCANNER_PROVENANCE,
    };
    use crate::locale::zh_tw;

    fn finding(category: CanonicalCategory, start: usize, end: usize) -> CanonicalFinding {
        CanonicalFinding::new(
            category,
            Severity::Medium,
            ConfidenceBand::Medium,
            ByteSpan::new(start, end),
            DetectionMethod::Deterministic,
            SCANNER_PROVENANCE,
            FindingStatus::Suspected,
        )
        .expect("well-formed span")
    }

    /// A locale finding redacts to the opaque label, and the identifier is gone.
    #[test]
    fn a_locale_finding_redacts_to_the_opaque_label() {
        let text = "統編12345675 已登記";
        let redacted = redact_findings(text, &zh_tw::scan(text));
        assert_eq!(redacted, "統編[REDACTED] 已登記");
        assert!(!redacted.contains("12345675"), "the identifier survived redaction");
    }

    /// A category that *does* have a detector keeps its published label, so this
    /// path can drive redaction for scanner findings too without moving the
    /// frozen label contract.
    #[test]
    fn a_category_with_a_detector_keeps_its_published_label() {
        let text = "ssn 123-45-6789 filed";
        let category = CanonicalCategory::with_locale(CategoryBase::NationalId, "en-US", "ssn");
        let redacted = redact_findings(text, &[finding(category, 4, 15)]);
        assert_eq!(redacted, "ssn [REDACTED:SsnPattern] filed");
    }

    /// Overlapping spans must be coalesced, or a fragment of the value survives
    /// between two replacements — the AAASM-4093 defect, in the canonical path.
    #[test]
    fn overlapping_findings_leave_no_fragment() {
        let text = "value ABCDEFGHIJ tail";
        let category = CanonicalCategory::unqualified(CategoryBase::HighEntropySecret);
        let redacted = redact_findings(text, &[finding(category, 6, 12), finding(category, 9, 16)]);
        assert_eq!(redacted, "value [REDACTED:GenericHighEntropy] tail");
        for fragment in ["ABCDEF", "GHIJ", "DEFGHI"] {
            assert!(!redacted.contains(fragment), "{fragment} survived");
        }
    }

    /// Two categories over one region have no single correct label, so the
    /// opaque one is used rather than a winner being picked.
    #[test]
    fn a_disputed_region_redacts_opaquely_rather_than_picking_a_winner() {
        let text = "value ABCDEFGHIJ tail";
        let redacted = redact_findings(
            text,
            &[
                finding(CanonicalCategory::unqualified(CategoryBase::HighEntropySecret), 6, 12),
                finding(CanonicalCategory::unqualified(CategoryBase::EmailAddress), 9, 16),
            ],
        );
        assert_eq!(redacted, "value [REDACTED] tail");
    }

    /// A span that cannot be spliced must not return the text intact.
    ///
    /// Both failures are unreachable for spans this crate produces, which is why
    /// they need a test: nothing else would notice if the guard were removed,
    /// and the consequence of removing it is a leak rather than a panic.
    #[test]
    fn an_unspliceable_span_fails_closed() {
        let text = "身分證 A200000003";
        let category = CanonicalCategory::with_locale(CategoryBase::NationalId, "zh-TW", "national_id");

        // Past the end of the text.
        assert_eq!(redact_findings(text, &[finding(category, 10, 9_999)]), "[REDACTED]");
        // Inside a multi-byte character: 身 occupies bytes 0..3.
        assert_eq!(redact_findings(text, &[finding(category, 1, 5)]), "[REDACTED]");
        // And the honest half — a valid span still redacts normally, so the
        // guard cannot be satisfied by refusing everything.
        assert_eq!(redact_findings(text, &[finding(category, 10, 20)]), "身分證 [REDACTED]");
    }

    /// No findings means the text is returned unchanged, not blanked.
    #[test]
    fn clean_text_is_returned_unchanged() {
        let text = "代理程式在執行工具前先詢問政策決策。";
        assert_eq!(redact_findings(text, &[]), text);
    }
}
