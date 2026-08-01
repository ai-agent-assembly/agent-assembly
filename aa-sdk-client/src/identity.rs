//! Agent identity helpers for gateway registration.
//!
//! The gateway's `AgentLifecycleService.Register` RPC requires the registering
//! `agent_id` to be a syntactically-valid `did:key` DID — a plain string is
//! rejected with `InvalidArgument: agent_id is not a did:key DID (missing
//! "did:key:" prefix)`. SDKs configure agents with human-readable identifiers
//! (used for socket naming and event tagging), so this module resolves such an
//! identifier to a conformant `did:key`.
//!
//! # The DID names a key, so it comes from the key (AAASM-5332)
//!
//! An Ed25519 `did:key` *is* an encoding of a public key, and the gateway
//! enforces that (`enforce_did_key_binding` refuses a registration whose DID
//! embeds a different key than the presented `public_key`). The DID therefore
//! cannot be chosen independently of the keypair — it is a rendering of it.
//!
//! Until AAASM-5332 that keypair was derived from the identifier, which made the
//! DID a pure function of a public string and the private key computable by
//! anyone who could read an agent id. Now the keypair is randomly generated and
//! persisted by [`crate::identity_store`], so resolving an identifier to its DID
//! means *loading that agent's durable key* — a fallible, filesystem-touching
//! operation rather than a hash. That is the cost of the DID meaning something.
//!
//! The identifier→DID mapping stays stable for the life of the key, so the
//! identity that registered, the identity a launch runs under, and the identity
//! the gateway attributes audit records to remain one principal across restarts.

use crate::identity_store::{IdentityStore, IdentityStoreError};
use crate::keypair::AgentKeypair;

/// Length, in bytes, of an Ed25519 public key.
#[cfg(test)]
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Multicodec prefix for an Ed25519 public key, used by the tests below.
#[cfg(test)]
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// Resolve a plain agent identifier to the `did:key` DID it registers under,
/// enrolling a durable identity key on first use.
///
/// The returned string has the shape `did:key:z<base58btc>` where the decoded
/// multibase value is `[0xed, 0x01]` followed by the 32-byte Ed25519 verifying
/// key of the agent's durable identity keypair — the same key
/// [`AgentKeypair::public_key_hex`] supplies as the registration `public_key`,
/// which is what `enforce_did_key_binding` requires.
///
/// An `identity` that is *already* a `did:key` is refused with
/// [`IdentityStoreError::ProvisionedDidUnsupported`] rather than passed through.
/// This looks like a removed feature and is not: the pass-through could never
/// have produced a successful registration. `build_register_request` sends a
/// `public_key` belonging to a key this crate holds, and the gateway's
/// `enforce_did_key_binding` requires the DID to embed *that* key — so a
/// caller-supplied DID was guaranteed to mismatch and be rejected as
/// `Unauthenticated`. Refusing here turns a confusing gateway-side rejection
/// into a local error that says what is actually wrong, and it forecloses the
/// worse alternative of silently registering the agent under a DID other than
/// the one the operator named.
pub fn agent_id_to_did_key(identity: &str) -> Result<String, IdentityStoreError> {
    if identity.starts_with("did:key:") {
        return Err(IdentityStoreError::ProvisionedDidUnsupported {
            did: identity.to_string(),
        });
    }

    Ok(IdentityStore::default_location()?.load_or_enroll(identity)?.did_key())
}

/// The `did:key` an identifier mapped to under the pre-AAASM-5332 derived
/// scheme.
///
/// Exists for **migration and revocation only**. Every DID this function returns
/// is compromised by construction: its private key is `SHA-256(identity)`, so
/// anyone who has ever seen the identifier — in an audit record, a topology
/// view, or the dashboard — can sign for it. An operator upgrading an existing
/// deployment needs to be able to *name* those identities in order to deregister
/// them, which is what this is for.
///
/// It must never be used to build a registration. Nothing in the crate calls it
/// outside migration reporting and tests.
pub fn legacy_derived_did(identity: &str) -> String {
    if identity.starts_with("did:key:") {
        return identity.to_string();
    }
    AgentKeypair::derive_transport_key(identity).did_key()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_store::IdentityStore;

    /// A store rooted in a fresh temporary directory, so each test's enrolments
    /// are its own and no test can pass by reading a key another test wrote.
    fn temp_store(label: &str) -> (IdentityStore, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "aa-identity-test-{}-{}-{:?}",
            label,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        (IdentityStore::at(root.join("identity")), root)
    }

    /// Replicate the gateway's `did:key` validation so the test proves the
    /// resolved DID would be accepted by `AgentLifecycleService.Register`
    /// without depending on the `aa-gateway` crate.
    fn validate_did_key(value: &str) -> Result<(), &'static str> {
        let multibase = value.strip_prefix("did:key:").ok_or("missing did:key: prefix")?;
        let encoded = multibase.strip_prefix('z').ok_or("missing z multibase prefix")?;
        if encoded.is_empty() {
            return Err("empty multibase value");
        }
        let decoded = bs58::decode(encoded).into_vec().map_err(|_| "not valid base58btc")?;
        if decoded.is_empty() {
            return Err("decodes to empty bytes");
        }
        Ok(())
    }

    #[test]
    fn resolves_a_conformant_did_key() {
        let (store, _root) = temp_store("conformant");
        let did = store.load_or_enroll("my-agent-001").expect("enrolment").did_key();
        assert!(did.starts_with("did:key:z"), "got {did}");
        validate_did_key(&did).expect("resolved DID must pass gateway validation");
    }

    /// Stability is what keeps registration, launch and audit attribution on one
    /// principal — but it must come from *reading the same stored key*, not from
    /// recomputing a hash.
    #[test]
    fn resolution_is_stable_across_calls_for_one_stored_key() {
        let (store, _root) = temp_store("stable");
        let first = store.load_or_enroll("agent-a").expect("enrolment").did_key();
        let second = store.load_or_enroll("agent-a").expect("load").did_key();
        assert_eq!(first, second);
    }

    #[test]
    fn distinct_identities_yield_distinct_dids() {
        let (store, _root) = temp_store("distinct");
        assert_ne!(
            store.load_or_enroll("agent-a").expect("enrolment").did_key(),
            store.load_or_enroll("agent-b").expect("enrolment").did_key()
        );
    }

    /// The core AAASM-5332 property expressed at the DID level: the identifier
    /// no longer determines the DID, so two installations that agree on the name
    /// still hold different keys.
    #[test]
    fn the_same_identifier_in_two_stores_yields_two_different_dids() {
        let (first_store, _a) = temp_store("two-stores-a");
        let (second_store, _b) = temp_store("two-stores-b");

        assert_ne!(
            first_store.load_or_enroll("ops-laptop").expect("enrolment").did_key(),
            second_store.load_or_enroll("ops-laptop").expect("enrolment").did_key(),
            "if one identifier still determines one DID, the private key is still a function of \
             public data and the possession proof still proves nothing"
        );
    }

    #[test]
    fn ed25519_did_keys_use_the_canonical_prefix() {
        let (store, _root) = temp_store("prefix");
        // The multicodec 0xed01 prefix renders as the well-known "z6Mk" head.
        let did = store.load_or_enroll("anything").expect("enrolment").did_key();
        assert!(did.starts_with("did:key:z6Mk"), "got {did}");
    }

    /// A caller-supplied DID is refused locally, because this crate cannot hold
    /// its private key and so could never prove possession of it.
    #[test]
    fn a_provisioned_did_is_refused_rather_than_registered_under_a_substitute() {
        let existing = "did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T";
        let err = agent_id_to_did_key(existing).expect_err("a DID we hold no key for must be refused");
        assert!(
            matches!(err, IdentityStoreError::ProvisionedDidUnsupported { .. }),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains(existing),
            "the refusal must name the DID the operator supplied; got {err}"
        );
    }

    #[test]
    fn resolved_did_decodes_to_ed25519_multicodec_payload() {
        let (store, _root) = temp_store("payload");
        let did = store.load_or_enroll("payload-check").expect("enrolment").did_key();
        let encoded = did.strip_prefix("did:key:z").unwrap();
        let decoded = bs58::decode(encoded).into_vec().unwrap();
        assert_eq!(&decoded[..2], &ED25519_MULTICODEC_PREFIX);
        assert_eq!(decoded.len(), 2 + ED25519_PUBLIC_KEY_LEN);
    }

    /// Migration: the legacy DID must still be nameable (an operator has to
    /// deregister it) and must be *different* from the durable one, or the
    /// upgrade did nothing.
    #[test]
    fn the_legacy_derived_did_is_reproducible_and_is_not_the_durable_did() {
        let (store, _root) = temp_store("legacy");
        let legacy = legacy_derived_did("ops-laptop");

        assert_eq!(
            legacy,
            legacy_derived_did("ops-laptop"),
            "operators must be able to name it"
        );
        assert!(legacy.starts_with("did:key:z6Mk"), "got {legacy}");
        assert_ne!(
            legacy,
            store.load_or_enroll("ops-laptop").expect("enrolment").did_key(),
            "the durable identity must not land back on the compromised legacy DID"
        );
    }
}
