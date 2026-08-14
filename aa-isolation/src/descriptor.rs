//! The descriptors a child would inherit, and what the launch did about each.
//!
//! ADR 0035 §9 names *"open file descriptors, sockets and similar ambient
//! authority"* alongside environment secrets. A descriptor is the harder half:
//! an environment variable naming a socket can be removed and the socket becomes
//! unreachable, but an inherited descriptor **is** the socket. It carries its
//! authority across `exec` with no name attached, so nothing an environment plan
//! does touches it.
//!
//! # Why an inventory rather than a guarantee
//!
//! The honest states are not two. A launch can:
//!
//! * hand a descriptor over deliberately — standard input, output and error, which
//!   a governed launch of the operator's own program cannot take away without
//!   changing what running it means;
//! * arrange for a descriptor not to survive `exec`;
//! * find a descriptor it cannot act on; or
//! * be unable to enumerate descriptors at all on this host.
//!
//! The last two are [`DescriptorDisposition::ResidualUnclosable`] and
//! [`InventoryCompleteness::NotEnumerable`], and they exist so that the third
//! state cannot be rendered as the second. That is the same asymmetry
//! [`DescendantCoverage::Unmeasured`](crate::capability::DescendantCoverage::Unmeasured)
//! draws: *nobody looked* and *nothing was there* have to stay apart, because a
//! launch reporting the first as the second is asserting a clean boundary it
//! never established.
//!
//! [`DescriptorInventory::asserts_clean_boundary`] is the predicate that keeps
//! them apart, and it is false for an inventory that could not be taken —
//! whatever else is in it.
//!
//! # No platform vocabulary
//!
//! Nothing here names a syscall, a flag or a `/proc` path. A descriptor is a
//! non-negative integer and a description a human reads; *how* an inventory was
//! taken and *how* a descriptor was kept from surviving `exec` are backend
//! facts, and they travel in the backend's own words through
//! [`Lowering`](crate::plan::Lowering) and evidence.

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The three descriptors every ordinary program expects, with the words an
/// operator reads for them.
///
/// Named here so a backend does not spell them differently in each report, and
/// so the fact that a governed launch delegates all three is stated once.
pub const STANDARD_DESCRIPTORS: &[(u32, &str)] =
    &[(0, "standard input"), (1, "standard output"), (2, "standard error")];

/// What a launch did about one descriptor it would otherwise pass on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DescriptorDisposition {
    /// The child gets it, as a decision.
    Delegated {
        /// Why the launch hands it over.
        reason: String,
    },
    /// The launch arranged for it not to survive into the executed program.
    ClosedBeforeExec,
    /// It reaches the child, the launch did not intend it to, and this launch
    /// cannot stop it.
    ///
    /// Residual authority. Not a failure of the run — it is the honest report of
    /// one — but a launch with any of these is not least-authority and evidence
    /// must say so.
    ResidualUnclosable {
        /// What stops the launch from acting on it, in words an operator can
        /// act on.
        reason: String,
    },
    /// It exists and nothing established what it is or whether it survives.
    Unmeasured {
        /// Why nothing was established.
        reason: String,
    },
}

impl DescriptorDisposition {
    /// Whether the child ends up holding this descriptor without the launch
    /// having decided it should.
    ///
    /// [`Unmeasured`](Self::Unmeasured) counts: a descriptor nobody looked at is
    /// not a descriptor known to be absent.
    pub fn is_residual(&self) -> bool {
        matches!(self, Self::ResidualUnclosable { .. } | Self::Unmeasured { .. })
    }
}

/// One descriptor the child would inherit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InheritedDescriptor {
    /// The descriptor number.
    pub number: u32,
    /// What it refers to, in words an operator reads — a path, a socket
    /// description, or a statement that it could not be resolved.
    ///
    /// **Never a credential.** A descriptor's *target* can be a path holding
    /// secret material, and a path is not secret material; nothing here reads
    /// the descriptor's contents.
    pub description: String,
    /// What the launch did about it.
    pub disposition: DescriptorDisposition,
}

impl fmt::Display for InheritedDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match &self.disposition {
            DescriptorDisposition::Delegated { reason } => format!("delegated ({reason})"),
            DescriptorDisposition::ClosedBeforeExec => "closed before exec".to_string(),
            DescriptorDisposition::ResidualUnclosable { reason } => {
                format!("residual, could not be closed ({reason})")
            }
            DescriptorDisposition::Unmeasured { reason } => format!("unmeasured ({reason})"),
        };
        write!(f, "descriptor {} -> {}: {}", self.number, self.description, action)
    }
}

/// Whether the inventory saw everything there was to see.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum InventoryCompleteness {
    /// Every open descriptor was enumerated.
    Complete,
    /// The host offered no way to enumerate them here, so the descriptors listed
    /// — if any — are the ones the launch knows about by construction and not
    /// the ones that exist.
    NotEnumerable {
        /// Why, in words an operator can act on.
        reason: String,
    },
}

impl InventoryCompleteness {
    /// Whether the enumeration was complete.
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Everything a launch established about the descriptors its child inherits.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DescriptorInventory {
    descriptors: Vec<InheritedDescriptor>,
    completeness: InventoryCompleteness,
}

impl DescriptorInventory {
    /// An inventory in which every open descriptor was enumerated.
    pub fn enumerated(descriptors: Vec<InheritedDescriptor>) -> Self {
        Self {
            descriptors,
            completeness: InventoryCompleteness::Complete,
        }
    }

    /// An inventory that could not be taken on this host.
    ///
    /// `descriptors` is what the launch knows by construction — normally the
    /// three standard descriptors — and is *not* a claim that nothing else is
    /// open. [`asserts_clean_boundary`](Self::asserts_clean_boundary) is false
    /// for every inventory built this way, whatever it contains.
    pub fn not_enumerable(reason: impl Into<String>, descriptors: Vec<InheritedDescriptor>) -> Self {
        Self {
            descriptors,
            completeness: InventoryCompleteness::NotEnumerable { reason: reason.into() },
        }
    }

    /// Every descriptor, in the order recorded.
    pub fn descriptors(&self) -> &[InheritedDescriptor] {
        &self.descriptors
    }

    /// Whether the enumeration saw everything.
    pub fn completeness(&self) -> &InventoryCompleteness {
        &self.completeness
    }

    /// Descriptors that reach the child without the launch having decided they
    /// should.
    pub fn residual(&self) -> impl Iterator<Item = &InheritedDescriptor> {
        self.descriptors.iter().filter(|d| d.disposition.is_residual())
    }

    /// Whether this inventory justifies saying the child inherits only
    /// descriptors the launch chose to give it.
    ///
    /// Requires **both** that the enumeration was complete and that nothing
    /// residual came out of it. An incomplete enumeration can never make this
    /// true, however empty its list is: the emptiness is a property of what was
    /// looked at, not of what exists.
    pub fn asserts_clean_boundary(&self) -> bool {
        self.completeness.is_complete() && self.residual().next().is_none()
    }

    /// One line per fact an operator needs, for an evidence record.
    ///
    /// Always non-empty. An inventory that rendered to nothing would read, in
    /// an audit trail, exactly like a launch that inherited nothing.
    pub fn describe(&self) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        if let InventoryCompleteness::NotEnumerable { reason } = &self.completeness {
            lines.push(format!(
                "the open descriptors could not be enumerated on this host ({reason}); everything not \
                 listed below is unmeasured, not absent"
            ));
        }
        lines.extend(self.descriptors.iter().map(ToString::to_string));
        if lines.is_empty() {
            lines.push(
                "no descriptor was found open beyond the ones this launch closed; the enumeration was \
                 complete"
                    .to_string(),
            );
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standard() -> Vec<InheritedDescriptor> {
        STANDARD_DESCRIPTORS
            .iter()
            .map(|(number, description)| InheritedDescriptor {
                number: *number,
                description: (*description).to_string(),
                disposition: DescriptorDisposition::Delegated {
                    reason: "inherited by design".to_string(),
                },
            })
            .collect()
    }

    #[test]
    fn a_complete_inventory_of_delegated_descriptors_is_a_clean_boundary() {
        let inventory = DescriptorInventory::enumerated(standard());
        assert!(inventory.asserts_clean_boundary());
        assert_eq!(inventory.residual().count(), 0);
    }

    /// **The property this module exists for.** An inventory that could not be
    /// taken must never read as a clean boundary — including when its list is
    /// identical to one that does.
    ///
    /// The two inventories below differ by exactly one thing: whether the
    /// enumeration succeeded. Without that pair, the assertion could pass
    /// because the descriptor list happened to be empty.
    #[test]
    fn an_inventory_that_could_not_be_taken_never_asserts_a_clean_boundary() {
        let unmeasurable = DescriptorInventory::not_enumerable("this host exposes no descriptor list", standard());
        assert!(
            !unmeasurable.asserts_clean_boundary(),
            "an unmeasured inventory claimed a clean boundary"
        );
        assert!(unmeasurable.describe()[0].contains("unmeasured, not absent"));

        let measured = DescriptorInventory::enumerated(standard());
        assert!(measured.asserts_clean_boundary());
        assert_eq!(measured.descriptors(), unmeasurable.descriptors());
    }

    /// A descriptor the launch could not close must break the clean-boundary
    /// claim on its own, without help from the completeness flag.
    #[test]
    fn one_unclosable_descriptor_breaks_a_complete_inventorys_claim() {
        let mut descriptors = standard();
        descriptors.push(InheritedDescriptor {
            number: 7,
            description: "socket".to_string(),
            disposition: DescriptorDisposition::ResidualUnclosable {
                reason: "another thread holds it".to_string(),
            },
        });
        let inventory = DescriptorInventory::enumerated(descriptors);
        assert!(!inventory.asserts_clean_boundary());
        assert_eq!(inventory.residual().count(), 1);
        assert!(inventory.describe().iter().any(|l| l.contains("could not be closed")));
    }

    /// A closed descriptor is not residual — the control for the test above.
    #[test]
    fn a_closed_descriptor_is_not_residual() {
        let mut descriptors = standard();
        descriptors.push(InheritedDescriptor {
            number: 7,
            description: "socket".to_string(),
            disposition: DescriptorDisposition::ClosedBeforeExec,
        });
        let inventory = DescriptorInventory::enumerated(descriptors);
        assert!(inventory.asserts_clean_boundary());
        assert!(inventory.describe().iter().any(|l| l.contains("closed before exec")));
    }

    #[test]
    fn an_unmeasured_descriptor_is_residual() {
        let inventory = DescriptorInventory::enumerated(vec![InheritedDescriptor {
            number: 9,
            description: "unresolved".to_string(),
            disposition: DescriptorDisposition::Unmeasured {
                reason: "the target could not be read".to_string(),
            },
        }]);
        assert!(!inventory.asserts_clean_boundary());
    }

    /// Silence about descriptors reads as an absence of them, so the rendering
    /// must never be empty.
    #[test]
    fn an_empty_inventory_still_says_something() {
        let inventory = DescriptorInventory::enumerated(Vec::new());
        assert_eq!(inventory.describe().len(), 1);
        assert!(inventory.describe()[0].contains("complete"));
    }
}
