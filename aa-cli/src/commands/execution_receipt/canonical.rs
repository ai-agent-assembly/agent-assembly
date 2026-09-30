//! Canonical serialization and content-digest primitives for execution receipts.
//!
//! AAASM-6166 / ADR 0035 amendment. This module answers one question only —
//! "what exact bytes does a digest cover" — and answers it once, so
//! [`schema::ReceiptEnvelope::seal`](super::schema::ReceiptEnvelope::seal) and
//! every fixture/test in this crate agree on the same rendering.
//!
//! # Why `serde_json::to_value` first, not `to_string` directly
//!
//! `aa_core::integration::store::integrity_of` comments that a struct's
//! `Serialize` output is "already key-ordered", which is true only for
//! `serde_json::Value::Object` (its internal `Map` is a `BTreeMap` because this
//! workspace does not enable `preserve_order` — verified: `grep -rn
//! preserve_order --include=Cargo.toml .` finds nothing). A struct serialized
//! directly with `to_string` instead follows serde's field-declaration order,
//! which is exactly what a struct's own field reordering would then change.
//! Going through [`serde_json::Value`] first is what makes struct field order
//! a no-op on the digest — see `the_canonical_form_is_pinned` and
//! `struct_field_order_does_not_change_the_digest` for the tests that pin this
//! down rather than merely assert it once.
use aa_core::integration::fingerprint::{fingerprint_raw, FINGERPRINT_PREFIX};

/// Names the canonical form a digest is taken over.
///
/// Bumped only when the bytes for an unchanged body would change — which
/// invalidates every stored digest. Recorded on [`super::schema::ReceiptSeal`]
/// so a receipt written under a later form is detectably different from one
/// written under this one, rather than silently mismatching.
pub const CANONICAL_FORM: &str = "json/sorted-keys/compact/integers-only";

/// A `sha256:`-prefixed content digest, in the same encoding
/// `aa_core::integration::fingerprint` and `IntegrationReceipt`'s own
/// fingerprints already use.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Digest(String);

impl Digest {
    /// The digest of `canonical`'s exact bytes.
    pub fn of_canonical(canonical: &str) -> Self {
        Self(fingerprint_raw(canonical))
    }

    /// Wrap an already-computed lowercase SHA-256 hex digest, in the same
    /// `sha256:<hex>` encoding [`fingerprint_raw`] produces.
    ///
    /// For a mechanism (e.g. `aa-workspace-tx`) that already hashes its own
    /// content and hands back bare hex — hashing that hex string again
    /// through [`Self::of_canonical`] would digest the digest, not the
    /// content it names. This constructor does not re-hash; it trusts `hex`
    /// is already the digest a caller wants stored.
    pub fn from_sha256_hex(hex: &str) -> Self {
        Self(format!("{FINGERPRINT_PREFIX}{hex}"))
    }

    /// The `sha256:<hex>` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a value could not be turned into the canonical form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CanonicalError {
    /// `serde_json` itself refused the value.
    #[error("the value could not be canonicalized: {detail}")]
    NotSerializable {
        /// The underlying serde error, stringified.
        detail: String,
    },
    /// A floating-point number reached the canonical form.
    ///
    /// The receipt's own types carry `u64`/`u32`/`i32`/`usize` only, so this
    /// should be unreachable through the public constructors — it exists as a
    /// checked invariant, not a documented input constraint, precisely so a
    /// future field addition that slips in an `f64` fails loudly here rather
    /// than producing a digest whose bytes vary by platform float rendering.
    #[error("a floating-point number reached a receipt at {pointer}; the canonical form admits integers only")]
    FloatingPoint {
        /// A JSON-Pointer-like path to the offending number.
        pointer: String,
    },
}

/// The canonical JSON bytes for `value`: parsed through [`serde_json::Value`]
/// (so key order is `BTreeMap`-sorted regardless of field declaration order),
/// re-serialized compactly, with every floating-point number rejected.
pub fn canonical_json<T: serde::Serialize>(value: &T) -> Result<String, CanonicalError> {
    let as_value =
        serde_json::to_value(value).map_err(|e| CanonicalError::NotSerializable { detail: e.to_string() })?;
    let mut pointer = String::new();
    reject_floats(&as_value, &mut pointer)?;
    serde_json::to_string(&as_value).map_err(|e| CanonicalError::NotSerializable { detail: e.to_string() })
}

/// Walk `value`, failing on the first `f64` found anywhere in the tree.
fn reject_floats(value: &serde_json::Value, pointer: &mut String) -> Result<(), CanonicalError> {
    match value {
        serde_json::Value::Number(n) => {
            if n.is_f64() {
                return Err(CanonicalError::FloatingPoint {
                    pointer: if pointer.is_empty() {
                        "/".to_string()
                    } else {
                        pointer.clone()
                    },
                });
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            let base_len = pointer.len();
            for (i, item) in items.iter().enumerate() {
                pointer.push('/');
                pointer.push_str(&i.to_string());
                reject_floats(item, pointer)?;
                pointer.truncate(base_len);
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            let base_len = pointer.len();
            for (k, v) in map {
                pointer.push('/');
                pointer.push_str(k);
                reject_floats(v, pointer)?;
                pointer.truncate(base_len);
            }
            Ok(())
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => Ok(()),
    }
}

/// The digest of `value`'s canonical form.
pub fn digest_of<T: serde::Serialize>(value: &T) -> Result<Digest, CanonicalError> {
    Ok(Digest::of_canonical(&canonical_json(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately declared out of alphabetical order — `b` before `a` — so
    /// this test can only pass if canonicalization actually sorts keys rather
    /// than happening to match declaration order.
    #[derive(serde::Serialize)]
    struct OutOfOrder {
        b: u32,
        a: u32,
    }

    #[derive(serde::Serialize)]
    struct Floaty {
        x: f64,
    }

    #[test]
    fn the_canonical_form_is_pinned() {
        let value = OutOfOrder { b: 2, a: 1 };
        assert_eq!(canonical_json(&value).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn struct_field_order_does_not_change_the_digest() {
        #[derive(serde::Serialize)]
        struct Declared1 {
            a: u32,
            b: u32,
        }
        #[derive(serde::Serialize)]
        struct Declared2 {
            b: u32,
            a: u32,
        }
        let d1 = digest_of(&Declared1 { a: 1, b: 2 }).unwrap();
        let d2 = digest_of(&Declared2 { b: 2, a: 1 }).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn two_independently_built_equal_values_are_byte_identical() {
        let a = canonical_json(&OutOfOrder { b: 2, a: 1 }).unwrap();
        let b = canonical_json(&OutOfOrder { a: 1, b: 2 }).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_float_anywhere_in_the_tree_is_rejected_with_its_pointer() {
        let err = canonical_json(&Floaty { x: 1.5 }).unwrap_err();
        match err {
            CanonicalError::FloatingPoint { pointer } => assert_eq!(pointer, "/x"),
            other => panic!("expected FloatingPoint, got {other:?}"),
        }
    }

    #[test]
    fn from_sha256_hex_agrees_with_of_canonical_for_the_same_bytes() {
        let canonical = r#"{"a":1}"#;
        let via_canonical = Digest::of_canonical(canonical);
        let hex = via_canonical
            .as_str()
            .strip_prefix(FINGERPRINT_PREFIX)
            .expect("of_canonical output carries the sha256: prefix");
        let via_hex = Digest::from_sha256_hex(hex);
        assert_eq!(via_canonical, via_hex);
    }

    #[test]
    fn vec_insertion_order_is_significant_when_not_sorted_by_the_caller() {
        // Arrays are NOT reordered by canonicalization — only object keys are.
        // A caller that needs order-independence must sort before serializing;
        // this proves the canonicalizer itself does not do it for them.
        let a = canonical_json(&vec![1, 2, 3]).unwrap();
        let b = canonical_json(&vec![3, 2, 1]).unwrap();
        assert_ne!(a, b);
    }
}
