//! `Serialize` for the canonical model, written by hand rather than derived.
//!
//! Every vocabulary type in this module documents an `as_str()` as "the stable
//! spelling used in events and metric labels", and [`CanonicalCategory`]
//! documents its rendered `BASE[qualifier]` form as a contract. A derived
//! `Serialize` emits neither: it emits the Rust identifier (`"Critical"`,
//! `"PolicyDefined"`) and, for the category, a nested object
//! (`{"base":"AccessToken","qualifier":{"Scheme":{…}}}`). Shipping that would
//! have handed B-9's event layer a wire format contradicting the documented one,
//! which is the sort of shape mistake that propagates rather than gets caught.
//!
//! `#[serde(rename_all = …)]` would fix the enums but not the category, and it
//! would leave two places to keep in step. These impls delegate to the same
//! `as_str()` and `Display` the documentation names, so the JSON cannot drift
//! from the contract without the contract itself changing.
//!
//! There is deliberately **no `Deserialize`**. See the module documentation for
//! why nothing here reconstructs a finding from bytes.

use serde::{Serialize, Serializer};

use super::{
    CanonicalCategory, CategoryBase, CategoryQualifier, ConfidenceBand, DetectionMethod, FindingStatus, Recognizer,
    Severity,
};

/// Serialize a type as whatever its `as_str()` returns.
macro_rules! serialize_as_str {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Serialize for $ty {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serializer.serialize_str(self.as_str())
                }
            }
        )*
    };
}

serialize_as_str!(
    CategoryBase,
    Severity,
    ConfidenceBand,
    DetectionMethod,
    FindingStatus,
    Recognizer,
);

/// Serialize a type as its `Display` rendering.
macro_rules! serialize_as_display {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Serialize for $ty {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serializer.collect_str(self)
                }
            }
        )*
    };
}

serialize_as_display!(CanonicalCategory, CategoryQualifier);
