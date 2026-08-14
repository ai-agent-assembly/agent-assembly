//! Stable content identity for a validated [`PolicyDocument`] (AAASM-5107).
//!
//! A runtime `PolicyDocument` carries no id column or digest, so nothing on the
//! audit-write path could name *which* document produced a decision. The Policy
//! list, the capability matrix and the team view all fall back to the
//! `(scope, metadata.name)` pair as the only nameable handle — but that pair is
//! explicitly **not** an identity: it omits `policy_version`, so two revisions of
//! the same `(scope, name)` collapse onto one key, and in the flat/non-envelope
//! format (`name = None`) every unnamed document at a scope shares one key.
//!
//! [`PolicyDocument::content_digest`] closes that gap with a **content digest**:
//! the SHA-256 of a canonical, order-independent encoding of *every* validated
//! field of the document. Two documents produce the same digest iff they are
//! equal under `PolicyDocument`'s own `PartialEq` (whole-content equality), so
//! the digest is exactly as discriminating as the strongest identity the type
//! already exposes — and it distinguishes two versions of the same
//! `(scope, name)` because any content difference (including `policy_version`)
//! changes the hash.
//!
//! ## Why a content hash, not `(scope, name, version)`
//!
//! A version-qualified key would name the *declared* revision, but two documents
//! can declare the same `metadata.version` while differing in body (an operator
//! edits rules without bumping the version), and the flat format declares no
//! version at all. A content digest is unambiguous in both cases and needs no
//! trusted version field. SHA-256 collision resistance makes it
//! unforgeable-enough for audit attribution: an attacker cannot craft a second,
//! semantically different document that hashes to a victim document's id.
//!
//! ## Relationship to the audit hash chain
//!
//! This digest is computed **independently** of [`aa_core::audit::AuditEntry`]'s
//! tamper-evident chain hash. It is carried as an additive, optional field and
//! never alters how the chain hash is computed for entries that do not set it —
//! the existing audit-integrity guarantees are untouched (AAASM-5107 §6).

use sha2::{Digest, Sha256};

use crate::document::{
    ActionOnExceed, ApprovalPolicy, BudgetPolicy, CredentialAction, DataPolicy, NetworkPolicy, PolicyDocument,
    SchedulePolicy, ToolPolicy,
};

/// Length-prefix an optional string into `hasher`: a `0` tag byte for `None`,
/// or a `1` tag byte followed by the big-endian byte length and the UTF-8 bytes
/// for `Some`. The tag distinguishes `None` from `Some("")` and the length
/// prefix makes adjacent fields unambiguous (no delimiter injection).
fn hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        None => hasher.update([0u8]),
        Some(s) => {
            hasher.update([1u8]);
            hasher.update((s.len() as u64).to_be_bytes());
            hasher.update(s.as_bytes());
        }
    }
}

/// Length-prefix a required string into `hasher`.
fn hash_str(hasher: &mut Sha256, s: &str) {
    hasher.update((s.len() as u64).to_be_bytes());
    hasher.update(s.as_bytes());
}

/// Hash an optional `f64` as its canonical IEEE-754 big-endian bits, tagged for
/// presence. `to_bits` is used (not `to_be_bytes` on the value) so the encoding
/// is exact and reproducible.
fn hash_opt_f64(hasher: &mut Sha256, value: Option<f64>) {
    match value {
        None => hasher.update([0u8]),
        Some(v) => {
            hasher.update([1u8]);
            hasher.update(v.to_bits().to_be_bytes());
        }
    }
}

fn hash_opt_u32(hasher: &mut Sha256, value: Option<u32>) {
    match value {
        None => hasher.update([0u8]),
        Some(v) => {
            hasher.update([1u8]);
            hasher.update(v.to_be_bytes());
        }
    }
}

fn hash_network(hasher: &mut Sha256, network: Option<&NetworkPolicy>) {
    match network {
        None => hasher.update([0u8]),
        Some(np) => {
            hasher.update([1u8]);
            // allowlist order is operator-authored and semantically meaningful
            // (first match wins is not used, but the list is a set the operator
            // wrote); hash it in declared order so an equal document — which
            // compares the Vec element-wise — hashes equal.
            hasher.update((np.allowlist.len() as u64).to_be_bytes());
            for host in &np.allowlist {
                hash_str(hasher, host);
            }
        }
    }
}

fn hash_schedule(hasher: &mut Sha256, schedule: Option<&SchedulePolicy>) {
    match schedule.and_then(|s| s.active_hours.as_ref()) {
        None => hasher.update([0u8]),
        Some(ah) => {
            hasher.update([1u8]);
            hash_str(hasher, &ah.start);
            hash_str(hasher, &ah.end);
            hash_str(hasher, &ah.timezone);
        }
    }
}

fn hash_budget(hasher: &mut Sha256, budget: Option<&BudgetPolicy>) {
    match budget {
        None => hasher.update([0u8]),
        Some(bp) => {
            hasher.update([1u8]);
            hash_opt_f64(hasher, bp.daily_limit_usd);
            hash_opt_f64(hasher, bp.monthly_limit_usd);
            hash_opt_f64(hasher, bp.org_daily_limit_usd);
            hash_opt_f64(hasher, bp.org_monthly_limit_usd);
            hash_opt_str(hasher, bp.timezone.as_deref());
            hasher.update([match bp.action_on_exceed {
                ActionOnExceed::Deny => 0u8,
                ActionOnExceed::Suspend => 1u8,
            }]);
            match bp.window {
                None => hasher.update([0u8]),
                Some(d) => {
                    hasher.update([1u8]);
                    hasher.update(d.as_nanos().to_be_bytes());
                }
            }
        }
    }
}

fn hash_data(hasher: &mut Sha256, data: Option<&DataPolicy>) {
    match data {
        None => hasher.update([0u8]),
        Some(dp) => {
            hasher.update([1u8]);
            hasher.update((dp.sensitive_patterns.len() as u64).to_be_bytes());
            for pat in &dp.sensitive_patterns {
                hash_str(hasher, pat);
            }
            hasher.update([match dp.credential_action {
                CredentialAction::Block => 0u8,
                CredentialAction::RedactOnly => 1u8,
                CredentialAction::AlertOnly => 2u8,
                CredentialAction::AlertAndRedact => 3u8,
            }]);
            // AAASM-5354: which detectors ran is part of what a policy decides,
            // so two documents differing only in `locale_packs` must not share
            // a digest — the audit trail attributes a decision by it, and
            // `policy_hits` is keyed by it.
            //
            // Emitted **only when non-empty**, which is what keeps this from
            // silently re-keying the world. `content_digest` is the
            // `policy_doc_id` on every audit entry and the key `hits_24h` counts
            // by; hashing an unconditional length prefix would change the digest
            // of every document that has ever existed, resetting every policy's
            // hit count and shifting audit attribution across the upgrade
            // boundary. A document with no `locale_packs` therefore hashes to
            // exactly the bytes it hashed to before this field existed —
            // `legacy_documents_keep_their_pre_locale_packs_digest` pins that
            // against a digest captured from the parent commit.
            //
            // The `0xFF` marker keeps the encoding unambiguous despite the
            // omission. Without it, the 8-byte length prefix of a non-empty list
            // would sit where a legacy document's `approval_timeout_secs` starts.
            // That field is a big-endian `u32`, so its leading byte is `0xFF`
            // only for a timeout above 4.28e9 seconds (136 years); no reachable
            // configuration collides.
            if !dp.locale_packs.is_empty() {
                hasher.update([0xFFu8]);
                hasher.update((dp.locale_packs.len() as u64).to_be_bytes());
                for tag in &dp.locale_packs {
                    hash_str(hasher, tag);
                }
            }
        }
    }
}

fn hash_approval(hasher: &mut Sha256, approval: Option<&ApprovalPolicy>) {
    match approval {
        None => hasher.update([0u8]),
        Some(ap) => {
            hasher.update([1u8]);
            hash_opt_u32(hasher, ap.timeout_seconds);
            hash_opt_str(hasher, ap.escalation_role.as_deref());
        }
    }
}

fn hash_tools(hasher: &mut Sha256, tools: &std::collections::HashMap<String, ToolPolicy>) {
    // HashMap iteration order is nondeterministic — sort by tool name so an
    // equal tool map (which `PolicyDocument: PartialEq` compares order-free)
    // always hashes identically.
    let mut names: Vec<&String> = tools.keys().collect();
    names.sort();
    hasher.update((names.len() as u64).to_be_bytes());
    for name in names {
        let tp = &tools[name];
        hash_str(hasher, name);
        hasher.update([u8::from(tp.allow)]);
        hash_opt_u32(hasher, tp.limit_per_hour);
        hash_opt_str(hasher, tp.requires_approval_if.as_deref());
    }
}

fn hash_capabilities(hasher: &mut Sha256, caps: Option<&aa_core::CapabilitySet>) {
    match caps {
        None => hasher.update([0u8]),
        Some(cs) => {
            hasher.update([1u8]);
            // allow / deny are BTreeSet<Capability>, already in a total,
            // deterministic order. Capability's Display is its stable wire form.
            hasher.update((cs.allow.len() as u64).to_be_bytes());
            for c in &cs.allow {
                hash_str(hasher, &c.to_string());
            }
            hasher.update((cs.deny.len() as u64).to_be_bytes());
            for c in &cs.deny {
                hash_str(hasher, &c.to_string());
            }
            hasher.update([u8::from(cs.allow_restricted)]);
        }
    }
}

impl PolicyDocument {
    /// A stable, content-derived identity for this document: `"sha256:<hex>"`
    /// where the hex is the SHA-256 of a canonical encoding of every validated
    /// field.
    ///
    /// Two documents share a digest iff they are equal under `PolicyDocument`'s
    /// `PartialEq`; in particular the digest distinguishes two versions of the
    /// same `(scope, metadata.name)` pair whenever their content differs. See
    /// the module docs for the full rationale and the audit-chain relationship.
    pub fn content_digest(&self) -> String {
        let mut hasher = Sha256::new();
        // Domain-separation tag + version byte so this digest can never be
        // confused with any other SHA-256 in the system and so the encoding can
        // be revved without silently colliding with v1 ids.
        hasher.update(b"aa-policy-doc-id\x01");
        // scope — the canonical `global` / `org:x` / `team:x` / `agent:<uuid>` /
        // `tool:x` wire string.
        hash_str(&mut hasher, &self.scope.to_string());
        hash_opt_str(&mut hasher, self.name.as_deref());
        hash_opt_str(&mut hasher, self.policy_version.as_deref());
        hash_opt_str(&mut hasher, self.version.as_deref());
        hash_network(&mut hasher, self.network.as_ref());
        hash_schedule(&mut hasher, self.schedule.as_ref());
        hash_budget(&mut hasher, self.budget.as_ref());
        hash_data(&mut hasher, self.data.as_ref());
        hasher.update(self.approval_timeout_secs.to_be_bytes());
        hash_approval(&mut hasher, self.approval_policy.as_ref());
        hash_tools(&mut hasher, &self.tools);
        hash_capabilities(&mut hasher, self.capabilities.as_ref());
        let digest: [u8; 32] = hasher.finalize().into();
        format!("sha256:{}", hex::encode(digest))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aa_core::CapabilitySet;

    use super::*;
    use crate::document::ToolPolicy;
    use crate::scope::PolicyScope;

    /// AAASM-5354 — adding `data.locale_packs` must not re-key documents that
    /// do not use it.
    ///
    /// `content_digest` is the `policy_doc_id` stamped on every audit entry and
    /// the key `policy_hits` counts by, so a digest change is not cosmetic: it
    /// resets every policy's `hits_24h` and shifts audit attribution across the
    /// upgrade boundary. The expected value below was **captured by running
    /// `content_digest` on this fixture at commit `b7e853b09`**, the parent
    /// `main` that has no `locale_packs` field at all — so this pins the real
    /// legacy encoding, not this build's idea of it.
    ///
    /// If this fails, `hash_data` started emitting bytes for an empty
    /// `locale_packs`. That is a migration event, not a refactor.
    #[test]
    fn legacy_documents_keep_their_pre_locale_packs_digest() {
        let mut doc = base_doc();
        doc.data = Some(crate::document::DataPolicy {
            sensitive_patterns: vec!["sk-[a-z]+".to_string()],
            credential_action: crate::document::CredentialAction::RedactOnly,
            locale_packs: vec![],
        });
        assert_eq!(
            doc.content_digest(),
            "sha256:c4664a0acb0bd210dc52b02942ec99c70b23919c57ff04edd47d07556e0582da",
            "adding locale_packs re-keyed a document that does not use it"
        );
    }

    /// The other half: a document that *does* name a pack must not share a
    /// digest with one that does not, or the audit trail could not tell which
    /// detectors ran.
    #[test]
    fn naming_a_locale_pack_changes_the_digest() {
        let mut without = base_doc();
        without.data = Some(crate::document::DataPolicy {
            sensitive_patterns: vec!["sk-[a-z]+".to_string()],
            credential_action: crate::document::CredentialAction::RedactOnly,
            locale_packs: vec![],
        });
        let mut with = without.clone();
        with.data.as_mut().unwrap().locale_packs = vec!["zh-TW".to_string()];
        assert_ne!(without.content_digest(), with.content_digest());

        // And two different packs are two different documents.
        let mut other = with.clone();
        other.data.as_mut().unwrap().locale_packs = vec!["ja-JP".to_string()];
        assert_ne!(with.content_digest(), other.content_digest());
    }

    fn base_doc() -> PolicyDocument {
        PolicyDocument {
            name: Some("baseline".to_string()),
            policy_version: Some("1".to_string()),
            version: None,
            scope: PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: HashMap::new(),
            capabilities: None,
            filesystem: None,
        }
    }

    #[test]
    fn digest_is_prefixed_and_stable_across_calls() {
        let doc = base_doc();
        let a = doc.content_digest();
        let b = doc.content_digest();
        assert_eq!(a, b, "digest must be deterministic for one document");
        assert!(a.starts_with("sha256:"), "digest must carry the scheme prefix: {a}");
        // "sha256:" (7) + 64 hex chars.
        assert_eq!(a.len(), 7 + 64);
    }

    #[test]
    fn equal_documents_have_equal_digests() {
        assert_eq!(base_doc(), base_doc());
        assert_eq!(base_doc().content_digest(), base_doc().content_digest());
    }

    #[test]
    fn digest_distinguishes_two_versions_of_same_scope_and_name() {
        // Same (scope, name), different content — the exact case the (scope,
        // name) PolicyKey collapses and this digest must separate.
        let mut v1 = base_doc();
        v1.policy_version = Some("1".to_string());
        let mut v2 = base_doc();
        v2.policy_version = Some("2".to_string());
        assert_ne!(v1.content_digest(), v2.content_digest());

        // Even when the declared version is identical, a body edit changes the id.
        let mut edited = base_doc();
        edited.tools.insert(
            "bash".to_string(),
            ToolPolicy {
                allow: false,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        assert_ne!(base_doc().content_digest(), edited.content_digest());
    }

    #[test]
    fn tool_map_insertion_order_does_not_change_digest() {
        let tp = |allow: bool| ToolPolicy {
            allow,
            limit_per_hour: None,
            requires_approval_if: None,
        };
        let mut a = base_doc();
        a.tools.insert("alpha".into(), tp(true));
        a.tools.insert("beta".into(), tp(false));
        let mut b = base_doc();
        b.tools.insert("beta".into(), tp(false));
        b.tools.insert("alpha".into(), tp(true));
        assert_eq!(a.content_digest(), b.content_digest());
    }

    #[test]
    fn scope_change_changes_digest() {
        let mut team = base_doc();
        team.scope = PolicyScope::Team("platform".into());
        assert_ne!(base_doc().content_digest(), team.content_digest());
    }

    #[test]
    fn capability_set_contributes_to_digest() {
        let mut caps = CapabilitySet::default();
        caps.deny.insert(aa_core::Capability::FileWrite);
        let mut doc = base_doc();
        doc.capabilities = Some(caps);
        assert_ne!(base_doc().content_digest(), doc.content_digest());
    }
}
