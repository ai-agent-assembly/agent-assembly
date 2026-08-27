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
//! * every fingerprint is taken over the **canonical form of the step's
//!   declared format** (`aa_core::integration::step::DocumentFormat`), never
//!   over its bytes, so a reserialisation that changed only formatting is
//!   correctly reported as *no drift* rather than as a change the user did not
//!   make. For JSON, canonical means parse → sorted, whitespace-free
//!   `serde_json`. For TOML, canonical means parse → sorted, plain
//!   `toml::to_string` (never `toml::to_string_pretty` — see `canonicalize`'s
//!   doc comment for why the choice between the two must never move once
//!   fingerprints exist);
//! * restoration is therefore verified against *semantics*, and
//!   the removal report says so instead of implying a guarantee the write path
//!   cannot keep. The same C3 reserialisation-not-byte-exact constraint applies
//!   identically to both formats.
//!
//! The reconsideration trigger is narrow and concrete: **if the adapter's write
//! path stops reserialising** — a format-preserving editor, or a managed
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
//!
//! # One document type, two backends
//!
//! The private `Doc` enum is deliberately the *only* place JSON and TOML
//! diverge. Every public function (`project`, `merge_from`, `absent`,
//! `restore`, `screen`) is written once against `Doc` and branches on the
//! variant only in `parse`/`render` — duplicating the credential screen or the
//! merge/restore logic per format is exactly the security regression this
//! module exists to avoid (a fix applied to one format's copy and not the
//! other's). No `serde_json::Value` or `toml::Value` appears in any public
//! signature here.
//!
//! `toml::Table` (aka `toml::value::Table`) is a `BTreeMap`-backed sorted map,
//! matching `serde_json::Map`'s ordering behaviour in this workspace (the
//! `preserve_order` feature is not enabled for `serde_json` here) — so both
//! backends serialize their keys in the same stable, sorted order.

use std::fmt::Write as _;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::step::DocumentFormat;

/// Prefix every fingerprint in this module carries, matching the digest format
/// already used for policy documents in [`AuditEntry`](crate::AuditEntry).
pub const FINGERPRINT_PREFIX: &str = "sha256:";

/// Why a document could not be fingerprinted or projected.
///
/// Every variant is a resolution failure in ADR 0015's sense: the caller must
/// fail closed on it, never treat it as "no drift".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FingerprintError {
    /// The document is not parseable JSON.
    #[error("the document is not valid JSON: {detail}")]
    NotJson {
        /// The parser's complaint, without the document's contents.
        detail: String,
    },
    /// The document is not parseable TOML.
    ///
    /// A TOML document is a table by construction, so a TOML parse failure is
    /// always this variant, never [`NotAnObject`](Self::NotAnObject) — that
    /// variant is unreachable for the TOML backend.
    #[error("the document is not valid TOML: {detail}")]
    NotToml {
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

/// The document a [`DocumentFormat`]-aware operation works over.
///
/// The one place JSON and TOML diverge; see the module docs for why every
/// other function in this module is written once against this type.
enum Doc {
    Json(serde_json::Map<String, serde_json::Value>),
    Toml(toml::Table),
}

impl Doc {
    fn parse(format: DocumentFormat, raw: &str) -> Result<Self, FingerprintError> {
        match format {
            DocumentFormat::Json => Ok(Doc::Json(parse_json_object(raw)?)),
            DocumentFormat::Toml => {
                let table: toml::Table = raw.parse().map_err(|e: toml::de::Error| FingerprintError::NotToml {
                    // `to_string()` on a toml error carries a line/column, never
                    // the document's contents — safe to surface in a diagnostic.
                    detail: e.to_string(),
                })?;
                Ok(Doc::Toml(table))
            }
        }
    }

    /// The canonical rendering: parsed, key-ordered, whitespace-minimal.
    ///
    /// TOML's canonical form is plain [`toml::to_string`], never
    /// `toml::to_string_pretty`. Both are idempotent and both round-trip, so a
    /// later swap to the pretty renderer would compile and every self-
    /// consistency test would still pass — while silently invalidating every
    /// fingerprint stored before the swap, because the canonical bytes a
    /// fingerprint is taken over would have changed shape. Do not change this.
    fn render(&self) -> String {
        match self {
            Doc::Json(map) => serde_json::Value::Object(map.clone()).to_string(),
            Doc::Toml(table) => toml::to_string(table).expect("a parsed toml::Table always re-serializes"),
        }
    }

    fn get(&self, key: &str) -> Option<DocValue<'_>> {
        match self {
            Doc::Json(map) => map.get(key).map(DocValue::Json),
            Doc::Toml(table) => table.get(key).map(DocValue::Toml),
        }
    }

    fn contains_key(&self, key: &str) -> bool {
        match self {
            Doc::Json(map) => map.contains_key(key),
            Doc::Toml(table) => table.contains_key(key),
        }
    }

    fn insert(&mut self, key: String, value: DocValue<'_>) {
        match (self, value) {
            (Doc::Json(map), DocValue::Json(v)) => {
                map.insert(key, v.clone());
            }
            (Doc::Toml(table), DocValue::Toml(v)) => {
                table.insert(key, v.clone());
            }
            _ => unreachable!("DocValue's variant always matches the Doc it was read from"),
        }
    }

    fn remove(&mut self, key: &str) {
        match self {
            Doc::Json(map) => {
                map.remove(key);
            }
            Doc::Toml(table) => {
                table.remove(key);
            }
        }
    }

    fn empty(format: DocumentFormat) -> Self {
        match format {
            DocumentFormat::Json => Doc::Json(serde_json::Map::new()),
            DocumentFormat::Toml => Doc::Toml(toml::Table::new()),
        }
    }

    /// This document's keys, cloned into a value the credential scanner can
    /// scan and the screen can carry across into a new `Doc` of the same kind.
    fn into_owned_pairs(self) -> Vec<(String, OwnedDocValue)> {
        match self {
            Doc::Json(map) => map.into_iter().map(|(k, v)| (k, OwnedDocValue::Json(v))).collect(),
            Doc::Toml(table) => table.into_iter().map(|(k, v)| (k, OwnedDocValue::Toml(v))).collect(),
        }
    }
}

/// A borrowed value read out of a [`Doc`], format-tagged so [`Doc::insert`]
/// can refuse to cross formats.
enum DocValue<'a> {
    Json(&'a serde_json::Value),
    Toml(&'a toml::Value),
}

/// An owned value taken out of a [`Doc`], for building a new document of the
/// same kind (the projection, the screened-safe subset, …).
enum OwnedDocValue {
    Json(serde_json::Value),
    Toml(toml::Value),
}

impl OwnedDocValue {
    fn as_doc_value(&self) -> DocValue<'_> {
        match self {
            OwnedDocValue::Json(v) => DocValue::Json(v),
            OwnedDocValue::Toml(v) => DocValue::Toml(v),
        }
    }

    /// Rendered form of just this value, for the credential scanner — a secret
    /// can sit inside a nested table/object or an array just as easily as in a
    /// string leaf.
    fn render(&self) -> String {
        match self {
            OwnedDocValue::Json(v) => v.to_string(),
            OwnedDocValue::Toml(v) => v.to_string(),
        }
    }

    fn format(&self) -> DocumentFormat {
        match self {
            OwnedDocValue::Json(_) => DocumentFormat::Json,
            OwnedDocValue::Toml(_) => DocumentFormat::Toml,
        }
    }
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

fn parse_json_object(raw: &str) -> Result<serde_json::Map<String, serde_json::Value>, FingerprintError> {
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

/// The document that means "nothing is here": `{}` for JSON, `""` for TOML.
///
/// TOML has no empty-object literal — an empty table is simply the absence of
/// any key, i.e. the empty string. Callers that need to compare "the file was
/// absent or blank" against a fingerprint use this rather than a
/// format-specific literal.
pub fn empty_document(format: DocumentFormat) -> &'static str {
    match format {
        DocumentFormat::Json => "{}",
        DocumentFormat::Toml => "",
    }
}

/// The canonical rendering of `raw`: parsed, key-ordered, whitespace-minimal,
/// in `format`.
///
/// `serde_json`'s `Map` and `toml::Table` are both `BTreeMap`-backed in this
/// workspace (the `preserve_order` feature is deliberately not enabled for
/// `serde_json`), so serialization is already sorted and this is a stable
/// function of the document's *meaning*.
///
/// TOML is always rendered with plain [`toml::to_string`], never
/// `toml::to_string_pretty` — see `Doc::render`'s doc comment for why that
/// choice must never move once fingerprints exist.
pub fn canonicalize(format: DocumentFormat, raw: &str) -> Result<String, FingerprintError> {
    Ok(Doc::parse(format, raw)?.render())
}

/// Fingerprint of the whole document's semantics.
///
/// Two files that differ only in formatting or key order produce the same value
/// — see the module docs on why that is the accepted constraint and not a bug.
pub fn document_fingerprint(format: DocumentFormat, raw: &str) -> Result<String, FingerprintError> {
    Ok(fingerprint_raw(&canonicalize(format, raw)?))
}

/// The canonical document containing only those `managed_keys` that are
/// present in `raw`, rendered in `format`.
///
/// Absent keys are omitted rather than rendered as null, so "the key is not
/// there" and "the key is there and holds null" stay distinguishable.
pub fn managed_projection(
    format: DocumentFormat,
    raw: &str,
    managed_keys: &[String],
) -> Result<String, FingerprintError> {
    let doc = Doc::parse(format, raw)?;
    let mut projection = Doc::empty(format);
    for key in managed_keys {
        if let Some(value) = doc.get(key) {
            projection.insert(key.clone(), value);
        }
    }
    Ok(projection.render())
}

/// Fingerprint of the AASM-owned projection of `raw`.
///
/// This is the value a receipt stores per step and the only one a drift check
/// may act on: a mismatch here means an AASM-managed value changed, and nothing
/// else does.
pub fn managed_fingerprint(
    format: DocumentFormat,
    raw: &str,
    managed_keys: &[String],
) -> Result<String, FingerprintError> {
    Ok(fingerprint_raw(&managed_projection(format, raw, managed_keys)?))
}

/// Which of `managed_keys` are **not** present in `raw`.
///
/// Recorded before an apply so removal can delete exactly the keys AASM added,
/// rather than deleting every key it manages and taking a user's pre-existing
/// value with it.
pub fn absent_managed_keys(
    format: DocumentFormat,
    raw: &str,
    managed_keys: &[String],
) -> Result<Vec<String>, FingerprintError> {
    let doc = Doc::parse(format, raw)?;
    Ok(managed_keys.iter().filter(|k| !doc.contains_key(k)).cloned().collect())
}

/// Merge `incoming`'s values for `managed_keys` into `current`, leaving every
/// other key of `current` exactly as it was.
///
/// This is the write shape [`SettingsMerge::MergeManagedKeys`](super::SettingsMerge)
/// names, and the reason repair can be safe: a key the plan does not claim is
/// never read, never written and never deleted.
pub fn merge_managed_keys(
    format: DocumentFormat,
    current: &str,
    incoming: &str,
    managed_keys: &[String],
) -> Result<String, FingerprintError> {
    let mut base = Doc::parse(format, current)?;
    let incoming = Doc::parse(format, incoming)?;
    for key in managed_keys {
        if let Some(value) = incoming.get(key) {
            base.insert(key.clone(), value);
        }
    }
    Ok(base.render())
}

/// Put `prior_values` back into `current` and delete `absent_keys`.
///
/// The inverse of [`merge_managed_keys`] against the state a receipt's prior-state
/// record captured. Keys of `current` that neither collection names — including
/// everything the user changed after installation — are carried through untouched.
pub fn restore_managed_keys(
    format: DocumentFormat,
    current: &str,
    prior_values: &str,
    absent_keys: &[String],
) -> Result<String, FingerprintError> {
    let mut base = Doc::parse(format, current)?;
    let prior = Doc::parse(format, prior_values)?;
    for (key, value) in prior.into_owned_pairs() {
        base.insert(key, value.as_doc_value());
    }
    for key in absent_keys {
        base.remove(key);
    }
    Ok(base.render())
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

/// The per-key secret screen: the subset of `values` (a canonical document in
/// `format`) whose keys are safe to persist, and the names of the keys that
/// were withheld.
///
/// Screening per key rather than per document means one credential-bearing key
/// does not cost the restorability of its neighbours.
pub fn screen_managed_values(format: DocumentFormat, values: &str) -> Result<(String, Vec<String>), FingerprintError> {
    let doc = Doc::parse(format, values)?;
    let mut safe = Doc::empty(format);
    let mut withheld = Vec::new();
    for (key, value) in doc.into_owned_pairs() {
        // Scan the rendered value, not just string leaves: a secret can sit
        // inside a nested table/object or an array element just as easily.
        if contains_credential_material(&value.render()) {
            withheld.push(key);
        } else {
            debug_assert_eq!(value.format(), format);
            safe.insert(key, value.as_doc_value());
        }
    }
    Ok((safe.render(), withheld))
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
            document_fingerprint(DocumentFormat::Json, pretty).unwrap(),
            document_fingerprint(DocumentFormat::Json, terse).unwrap()
        );
    }

    #[test]
    fn the_json_canonical_form_is_pinned() {
        // Existing JSON tests above are all self-consistency comparisons and
        // wouldn't catch a canonicalization regression on their own — this
        // pins the exact rendered bytes.
        assert_eq!(
            canonicalize(DocumentFormat::Json, "{\n \"b\":2,\n \"a\":1}").unwrap(),
            r#"{"a":1,"b":2}"#
        );
    }

    #[test]
    fn the_projection_sees_only_the_keys_the_step_claims() {
        let doc = r#"{"permissions":{"allow":["Bash"]},"theme":"dark"}"#;
        let projection = managed_projection(DocumentFormat::Json, doc, &managed_keys()).unwrap();
        assert_eq!(projection, r#"{"permissions":{"allow":["Bash"]}}"#);

        // Changing an unmanaged key moves the document fingerprint and leaves
        // the managed one alone — the whole basis of the drift distinction.
        let edited = r#"{"permissions":{"allow":["Bash"]},"theme":"light"}"#;
        assert_eq!(
            managed_fingerprint(DocumentFormat::Json, doc, &managed_keys()).unwrap(),
            managed_fingerprint(DocumentFormat::Json, edited, &managed_keys()).unwrap()
        );
        assert_ne!(
            document_fingerprint(DocumentFormat::Json, doc).unwrap(),
            document_fingerprint(DocumentFormat::Json, edited).unwrap()
        );
    }

    #[test]
    fn an_absent_key_is_not_a_null_key() {
        let doc = r#"{"permissionMode":null}"#;
        assert_eq!(
            absent_managed_keys(DocumentFormat::Json, doc, &managed_keys()).unwrap(),
            vec![MANAGED.to_string()]
        );
        assert_eq!(
            managed_projection(DocumentFormat::Json, doc, &managed_keys()).unwrap(),
            r#"{"permissionMode":null}"#
        );
    }

    #[test]
    fn merge_and_restore_leave_unrelated_keys_alone() {
        let original = r#"{"theme":"dark"}"#;
        let absent = absent_managed_keys(DocumentFormat::Json, original, &managed_keys()).unwrap();
        let prior = managed_projection(DocumentFormat::Json, original, &managed_keys()).unwrap();

        let installed = merge_managed_keys(
            DocumentFormat::Json,
            original,
            r#"{"permissions":{"allow":[]},"permissionMode":"default"}"#,
            &managed_keys(),
        )
        .unwrap();
        assert!(installed.contains("\"theme\":\"dark\""));

        // The user changes something of their own after installation.
        let user_edited = merge_managed_keys(DocumentFormat::Json, &installed, r#"{}"#, &[]).unwrap();
        let user_edited = user_edited.replace("\"dark\"", "\"light\"");

        let restored = restore_managed_keys(DocumentFormat::Json, &user_edited, &prior, &absent).unwrap();
        assert_eq!(
            restored, r#"{"theme":"light"}"#,
            "the post-install user change must survive removal"
        );
    }

    #[test]
    fn a_non_object_document_fails_closed() {
        assert!(matches!(
            document_fingerprint(DocumentFormat::Json, "[1,2,3]"),
            Err(FingerprintError::NotAnObject { found: "array" })
        ));
        assert!(matches!(
            document_fingerprint(DocumentFormat::Json, "not json"),
            Err(FingerprintError::NotJson { .. })
        ));
    }

    #[test]
    fn credential_shaped_values_are_withheld_per_key() {
        // Synthetic, fabricated to match the scanner's `sk-ant-` literal
        // pattern. Never a credential.
        let secret = "sk-ant-api03-AAASM5278SYNTHETICDONOTUSEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let values = format!(r#"{{"apiKey":"{secret}","permissionMode":"default"}}"#);
        let (safe, withheld) = screen_managed_values(DocumentFormat::Json, &values).unwrap();
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

    // --- TOML backend ---

    #[test]
    fn toml_document_fingerprint_treats_blank_as_empty_and_json_empty_as_invalid() {
        // The literal CI regression this fix exists for: `aa-devtool-codex`
        // writes real TOML now, and the fingerprint module was hardcoded to
        // JSON, so a blank/absent TOML file failed to fingerprint at all.
        assert!(document_fingerprint(DocumentFormat::Toml, "").is_ok());
        assert!(document_fingerprint(DocumentFormat::Toml, "{}").is_err());
    }

    #[test]
    fn a_format_mismatch_is_a_negative_control() {
        let toml_doc = "sandbox_mode = \"read-only\"\n";
        let json_doc = r#"{"sandbox_mode":"read-only"}"#;
        assert!(document_fingerprint(DocumentFormat::Json, toml_doc).is_err());
        assert!(document_fingerprint(DocumentFormat::Toml, json_doc).is_err());
    }

    #[test]
    fn toml_canonicalization_is_equivalent_across_syntaxes() {
        let table_header = "[mcp_servers.foo]\ncommand = \"bar\"\n";
        let inline = "mcp_servers = { foo = { command = \"bar\" } }\n";
        let dotted = "mcp_servers.foo.command = \"bar\"\n";
        let commented = "# a comment\nmcp_servers.foo.command = \"bar\"   # trailing\n\n";

        let canonical = canonicalize(DocumentFormat::Toml, table_header).unwrap();
        assert_eq!(canonical, canonicalize(DocumentFormat::Toml, inline).unwrap());
        assert_eq!(canonical, canonicalize(DocumentFormat::Toml, dotted).unwrap());
        assert_eq!(canonical, canonicalize(DocumentFormat::Toml, commented).unwrap());
    }

    #[test]
    fn toml_projection_sees_only_the_keys_the_step_claims() {
        let keys = vec!["sandbox_mode".to_string(), "approval_policy".to_string()];
        let doc = "sandbox_mode = \"read-only\"\napproval_policy = \"untrusted\"\nmodel = \"o3\"\n";
        let edited = "sandbox_mode = \"read-only\"\napproval_policy = \"untrusted\"\nmodel = \"o4\"\n";

        assert_eq!(
            managed_fingerprint(DocumentFormat::Toml, doc, &keys).unwrap(),
            managed_fingerprint(DocumentFormat::Toml, edited, &keys).unwrap()
        );
        assert_ne!(
            document_fingerprint(DocumentFormat::Toml, doc).unwrap(),
            document_fingerprint(DocumentFormat::Toml, edited).unwrap()
        );
    }

    #[test]
    fn toml_credential_shaped_values_are_withheld_per_key() {
        let secret = "sk-ant-api03-AAASM5278SYNTHETICDONOTUSEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let values = format!("api_key = \"{secret}\"\nsandbox_mode = \"read-only\"\n");
        let (safe, withheld) = screen_managed_values(DocumentFormat::Toml, &values).unwrap();
        assert_eq!(withheld, vec!["api_key".to_string()]);
        assert!(!safe.contains("AAASM5278SYNTHETIC"), "{safe}");
        assert!(safe.contains("sandbox_mode"));
    }

    #[test]
    fn toml_merge_preserves_a_user_written_subtable() {
        let keys = vec!["sandbox_mode".to_string()];
        let original = "[mcp_servers.foo]\ncommand = \"bar\"\n";

        let installed =
            merge_managed_keys(DocumentFormat::Toml, original, "sandbox_mode = \"read-only\"\n", &keys).unwrap();

        assert!(installed.contains("[mcp_servers.foo]"), "{installed}");
        assert!(installed.contains("command = \"bar\""), "{installed}");
        assert!(installed.contains("sandbox_mode = \"read-only\""), "{installed}");
    }
}
