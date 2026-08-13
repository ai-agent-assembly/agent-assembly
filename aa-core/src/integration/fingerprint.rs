//! Canonical fingerprints, managed-key projections, and the screen that keeps a
//! receipt from becoming somewhere secrets live.
//!
//! # Semantics-exact, not byte-exact — the AAASM-5276 C3 constraint
//!
//! The Spike measured that `aa-devtool-claude-code/src/apply.rs:85` reserialises
//! the whole settings document on every write, so a user file in non-canonical
//! formatting (tabs, comments-adjacent whitespace, a hand-chosen key order)
//! cannot survive an install→remove cycle byte-for-byte *no matter how good the
//! receipt is*. AAASM-5278 accepts that as a stated constraint rather than
//! pretending otherwise, and this module is where the acceptance is made
//! operational:
//!
//! * every fingerprint is taken over the **canonical JSON** of a document, never
//!   over its bytes, so a reserialisation that changed only formatting is
//!   correctly reported as *no drift* rather than as a change the user did not
//!   make;
//! * restoration is therefore verified against *semantics*, and
//!   the removal report says so instead of implying a guarantee the write path
//!   cannot keep.
//!
//! The reconsideration trigger is narrow and concrete: **if the adapter's write
//! path stops reserialising** — a format-preserving JSON editor, or a managed
//! block written into a region of the file the rest of which is copied verbatim
//! — then byte-exact restore becomes achievable and this decision should be
//! revisited, because at that point the weaker guarantee would be a choice
//! rather than a constraint.
//!
//! # Why a projection, and not just "hash the file"
//!
//! Drift has to distinguish *a user edited something of their own* from *an
//! AASM-owned value changed* (ADR 0030 matrix row 10; repair is only safe
//! because of it). One hash over the whole file cannot tell those apart. So each
//! settings step is fingerprinted twice: once over the projection of just the
//! keys the step claims, and once over the whole document. Two hashes, two
//! questions, and the answer to the second never authorises a write.
//!
//! # Why the secret screen lives here
//!
//! Removal restores the values that were in the file before AASM touched it,
//! which means those values are written into a receipt. A settings file is a
//! place users do put credentials. Screening the material *before* it reaches
//! the receipt — rather than redacting on the way out to a log — is the only
//! placement where "the receipt does not contain the secret" is a property of
//! the file on disk rather than of every reader of it.

use std::fmt::Write as _;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

/// Prefix every fingerprint in this module carries, matching the digest format
/// already used for policy documents in [`AuditEntry`](crate::AuditEntry).
pub const FINGERPRINT_PREFIX: &str = "sha256:";

/// Why a document could not be fingerprinted or projected.
///
/// Both variants are resolution failures in ADR 0015's sense: the caller must
/// fail closed on them, never treat them as "no drift".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FingerprintError {
    /// The document is not parseable JSON.
    #[error("the document is not valid JSON: {detail}")]
    NotJson {
        /// The parser's complaint, without the document's contents.
        detail: String,
    },
    /// The document parsed but is not a JSON object, so it has no keys to own.
    #[error("the document is a JSON {found}, not an object")]
    NotAnObject {
        /// What it turned out to be.
        found: &'static str,
    },
}

/// Hex-encode `bytes` into a lowercase string.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bare hex SHA-256 of `text`, without the [`FINGERPRINT_PREFIX`].
///
/// Used where an existing type already fixes the encoding — notably
/// [`StepAction::WriteManagedSettings::content_sha256`](super::StepAction),
/// which the lifecycle contract documents as "hex-encoded".
pub fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex(&hasher.finalize())
}

/// A prefixed fingerprint of `text` exactly as given, with no canonicalisation.
pub fn fingerprint_raw(text: &str) -> String {
    format!("{FINGERPRINT_PREFIX}{}", sha256_hex(text))
}

fn parse_object(raw: &str) -> Result<serde_json::Map<String, serde_json::Value>, FingerprintError> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|e| FingerprintError::NotJson {
        // `to_string()` on a serde_json error carries a line/column, never the
        // document's contents — safe to surface in a diagnostic.
        detail: e.to_string(),
    })?;
    match value {
        serde_json::Value::Object(map) => Ok(map),
        serde_json::Value::Null => Err(FingerprintError::NotAnObject { found: "null" }),
        serde_json::Value::Bool(_) => Err(FingerprintError::NotAnObject { found: "boolean" }),
        serde_json::Value::Number(_) => Err(FingerprintError::NotAnObject { found: "number" }),
        serde_json::Value::String(_) => Err(FingerprintError::NotAnObject { found: "string" }),
        serde_json::Value::Array(_) => Err(FingerprintError::NotAnObject { found: "array" }),
    }
}

/// The canonical rendering of `raw`: parsed, key-ordered, whitespace-free.
///
/// `serde_json`'s `Map` is a `BTreeMap` in this workspace (the `preserve_order`
/// feature is deliberately not enabled), so serialization is already sorted and
/// this is a stable function of the document's *meaning*.
pub fn canonicalize(raw: &str) -> Result<String, FingerprintError> {
    let map = parse_object(raw)?;
    Ok(serde_json::Value::Object(map).to_string())
}

/// Fingerprint of the whole document's semantics.
///
/// Two files that differ only in formatting or key order produce the same value
/// — see the module docs on why that is the accepted constraint and not a bug.
pub fn document_fingerprint(raw: &str) -> Result<String, FingerprintError> {
    Ok(fingerprint_raw(&canonicalize(raw)?))
}

/// The canonical JSON object containing only those `managed_keys` that are
/// present in `raw`.
///
/// Absent keys are omitted rather than rendered as `null`, so "the key is not
/// there" and "the key is there and holds null" stay distinguishable.
pub fn managed_projection(raw: &str, managed_keys: &[String]) -> Result<String, FingerprintError> {
    let map = parse_object(raw)?;
    let mut projection = serde_json::Map::new();
    for key in managed_keys {
        if let Some(value) = map.get(key) {
            projection.insert(key.clone(), value.clone());
        }
    }
    Ok(serde_json::Value::Object(projection).to_string())
}

/// Fingerprint of the AASM-owned projection of `raw`.
///
/// This is the value a receipt stores per step and the only one a drift check
/// may act on: a mismatch here means an AASM-managed value changed, and nothing
/// else does.
pub fn managed_fingerprint(raw: &str, managed_keys: &[String]) -> Result<String, FingerprintError> {
    Ok(fingerprint_raw(&managed_projection(raw, managed_keys)?))
}

/// Which of `managed_keys` are **not** present in `raw`.
///
/// Recorded before an apply so removal can delete exactly the keys AASM added,
/// rather than deleting every key it manages and taking a user's pre-existing
/// value with it.
pub fn absent_managed_keys(raw: &str, managed_keys: &[String]) -> Result<Vec<String>, FingerprintError> {
    let map = parse_object(raw)?;
    Ok(managed_keys.iter().filter(|k| !map.contains_key(*k)).cloned().collect())
}

/// Merge `incoming`'s values for `managed_keys` into `current`, leaving every
/// other key of `current` exactly as it was.
///
/// This is the write shape [`SettingsMerge::MergeManagedKeys`](super::SettingsMerge)
/// names, and the reason repair can be safe: a key the plan does not claim is
/// never read, never written and never deleted.
pub fn merge_managed_keys(current: &str, incoming: &str, managed_keys: &[String]) -> Result<String, FingerprintError> {
    let mut base = parse_object(current)?;
    let incoming = parse_object(incoming)?;
    for key in managed_keys {
        if let Some(value) = incoming.get(key) {
            base.insert(key.clone(), value.clone());
        }
    }
    Ok(serde_json::Value::Object(base).to_string())
}

/// Put `prior_values` back into `current` and delete `absent_keys`.
///
/// The inverse of [`merge_managed_keys`] against the state a receipt's prior-state
/// record captured. Keys of `current` that neither collection names — including
/// everything the user changed after installation — are carried through untouched.
pub fn restore_managed_keys(
    current: &str,
    prior_values: &str,
    absent_keys: &[String],
) -> Result<String, FingerprintError> {
    let mut base = parse_object(current)?;
    let prior = parse_object(prior_values)?;
    for (key, value) in prior {
        base.insert(key, value);
    }
    for key in absent_keys {
        base.remove(key);
    }
    Ok(serde_json::Value::Object(base).to_string())
}

fn scanner() -> &'static aa_security::CredentialScanner {
    static SCANNER: OnceLock<aa_security::CredentialScanner> = OnceLock::new();
    SCANNER.get_or_init(aa_security::CredentialScanner::new)
}

/// Whether `text` contains anything the deterministic credential scanner
/// recognises as secret material.
///
/// The scanner's pattern set is finite, so a `false` is "nothing matched", not
/// "there is no secret here". Callers use it to *withhold* material from a
/// receipt, never to certify that storing it is safe — which is why a receipt's
/// prior-state record additionally caps what it stores to the keys the plan
/// claims.
pub fn contains_credential_material(text: &str) -> bool {
    !scanner().scan(text).is_clean()
}

/// The per-key secret screen: the subset of `values` (a canonical JSON object)
/// whose keys are safe to persist, and the names of the keys that were withheld.
///
/// Screening per key rather than per document means one credential-bearing key
/// does not cost the restorability of its neighbours.
pub fn screen_managed_values(values: &str) -> Result<(String, Vec<String>), FingerprintError> {
    let map = parse_object(values)?;
    let mut safe = serde_json::Map::new();
    let mut withheld = Vec::new();
    for (key, value) in map {
        // Scan the rendered value, not just string leaves: a secret can sit
        // inside a nested object or an array element just as easily.
        if contains_credential_material(&value.to_string()) {
            withheld.push(key);
        } else {
            safe.insert(key, value);
        }
    }
    Ok((serde_json::Value::Object(safe).to_string(), withheld))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANAGED: &str = "permissions";

    fn managed_keys() -> Vec<String> {
        vec![MANAGED.to_string(), "permissionMode".to_string()]
    }

    #[test]
    fn formatting_and_key_order_do_not_change_a_fingerprint() {
        // The C3 constraint made concrete: these two documents mean the same
        // thing and must not read as drift.
        let pretty = "{\n  \"permissions\": {\"allow\": [\"Bash\"]},\n  \"theme\": \"dark\"\n}";
        let terse = r#"{"theme":"dark","permissions":{"allow":["Bash"]}}"#;
        assert_eq!(
            document_fingerprint(pretty).unwrap(),
            document_fingerprint(terse).unwrap()
        );
    }

    #[test]
    fn the_projection_sees_only_the_keys_the_step_claims() {
        let doc = r#"{"permissions":{"allow":["Bash"]},"theme":"dark"}"#;
        let projection = managed_projection(doc, &managed_keys()).unwrap();
        assert_eq!(projection, r#"{"permissions":{"allow":["Bash"]}}"#);

        // Changing an unmanaged key moves the document fingerprint and leaves
        // the managed one alone — the whole basis of the drift distinction.
        let edited = r#"{"permissions":{"allow":["Bash"]},"theme":"light"}"#;
        assert_eq!(
            managed_fingerprint(doc, &managed_keys()).unwrap(),
            managed_fingerprint(edited, &managed_keys()).unwrap()
        );
        assert_ne!(
            document_fingerprint(doc).unwrap(),
            document_fingerprint(edited).unwrap()
        );
    }

    #[test]
    fn an_absent_key_is_not_a_null_key() {
        let doc = r#"{"permissionMode":null}"#;
        assert_eq!(
            absent_managed_keys(doc, &managed_keys()).unwrap(),
            vec![MANAGED.to_string()]
        );
        assert_eq!(
            managed_projection(doc, &managed_keys()).unwrap(),
            r#"{"permissionMode":null}"#
        );
    }

    #[test]
    fn merge_and_restore_leave_unrelated_keys_alone() {
        let original = r#"{"theme":"dark"}"#;
        let absent = absent_managed_keys(original, &managed_keys()).unwrap();
        let prior = managed_projection(original, &managed_keys()).unwrap();

        let installed = merge_managed_keys(
            original,
            r#"{"permissions":{"allow":[]},"permissionMode":"default"}"#,
            &managed_keys(),
        )
        .unwrap();
        assert!(installed.contains("\"theme\":\"dark\""));

        // The user changes something of their own after installation.
        let user_edited = merge_managed_keys(&installed, r#"{}"#, &[]).unwrap();
        let user_edited = user_edited.replace("\"dark\"", "\"light\"");

        let restored = restore_managed_keys(&user_edited, &prior, &absent).unwrap();
        assert_eq!(
            restored, r#"{"theme":"light"}"#,
            "the post-install user change must survive removal"
        );
    }

    #[test]
    fn a_non_object_document_fails_closed() {
        assert!(matches!(
            document_fingerprint("[1,2,3]"),
            Err(FingerprintError::NotAnObject { found: "array" })
        ));
        assert!(matches!(
            document_fingerprint("not json"),
            Err(FingerprintError::NotJson { .. })
        ));
    }

    #[test]
    fn credential_shaped_values_are_withheld_per_key() {
        // Synthetic, fabricated to match the scanner's `sk-ant-` literal
        // pattern. Never a credential.
        let secret = "sk-ant-api03-AAASM5278SYNTHETICDONOTUSEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let values = format!(r#"{{"apiKey":"{secret}","permissionMode":"default"}}"#);
        let (safe, withheld) = screen_managed_values(&values).unwrap();
        assert_eq!(withheld, vec!["apiKey".to_string()]);
        assert!(!safe.contains("AAASM5278SYNTHETIC"), "{safe}");
        assert!(safe.contains("permissionMode"));
    }

    #[test]
    fn content_sha256_is_hex_without_the_prefix() {
        let hex = sha256_hex("{}");
        assert_eq!(hex.len(), 64);
        assert_eq!(fingerprint_raw("{}"), format!("{FINGERPRINT_PREFIX}{hex}"));
    }
}
