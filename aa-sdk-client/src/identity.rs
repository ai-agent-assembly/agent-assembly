//! Agent identity helpers for gateway registration.
//!
//! The gateway's `AgentLifecycleService.Register` RPC requires the registering
//! `agent_id` to be a syntactically-valid `did:key` DID — a plain string is
//! rejected with `InvalidArgument: agent_id is not a did:key DID (missing
//! "did:key:" prefix)`. SDKs configure agents with human-readable identifiers
//! (used for socket naming and event tagging), so this module derives a
//! conformant `did:key` from such an identifier.
//!
//! The derivation is **deterministic**: the same input always yields the same
//! DID, so an agent keeps a stable identity across process restarts without
//! having to persist a keypair. Bytes are produced by hashing the input with
//! SHA-256, then wrapped as an Ed25519 `did:key` (multicodec `0xed 0x01`,
//! base58btc multibase). The resulting DID has the canonical `did:key:z6Mk…`
//! shape and passes the gateway's syntactic `did:key` validation.

use sha2::{Digest, Sha256};

/// Multicodec prefix for an Ed25519 public key (`0xed`), varint-encoded as
/// the two bytes `0xed 0x01`. A `did:key` for Ed25519 is the base58btc
/// multibase encoding of these two bytes followed by the 32-byte key.
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// Length, in bytes, of an Ed25519 public key.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Derive a deterministic, conformant Ed25519 `did:key` DID from a plain agent
/// identifier.
///
/// The returned string has the shape `did:key:z<base58btc>` where the decoded
/// multibase value is `[0xed, 0x01]` followed by 32 deterministic bytes derived
/// from `identity`. This is accepted by the gateway's `did:key` validation,
/// which checks the `did:key:` prefix, the `z` base58btc multibase marker, and
/// that the value decodes to non-empty bytes.
///
/// If `identity` is already a `did:key` DID (it starts with `did:key:`), it is
/// returned unchanged so callers can pass through an explicitly-provisioned DID.
pub fn agent_id_to_did_key(identity: &str) -> String {
    if identity.starts_with("did:key:") {
        return identity.to_string();
    }

    // Derive a stable 32-byte value to stand in for an Ed25519 public key. No
    // keypair is provisioned at this layer, so the DID identifies the agent by
    // its configured identifier rather than by a verifiable signing key.
    let digest = Sha256::digest(identity.as_bytes());
    let mut key_bytes = [0u8; ED25519_PUBLIC_KEY_LEN];
    key_bytes.copy_from_slice(&digest[..ED25519_PUBLIC_KEY_LEN]);

    let mut multicodec = Vec::with_capacity(ED25519_MULTICODEC_PREFIX.len() + ED25519_PUBLIC_KEY_LEN);
    multicodec.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    multicodec.extend_from_slice(&key_bytes);

    let multibase = bs58::encode(&multicodec).into_string();
    format!("did:key:z{multibase}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replicate the gateway's `did:key` validation so the test proves the
    /// derived DID would be accepted by `AgentLifecycleService.Register`
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
    fn derives_conformant_did_key() {
        let did = agent_id_to_did_key("my-agent-001");
        assert!(did.starts_with("did:key:z"), "got {did}");
        validate_did_key(&did).expect("derived DID must pass gateway validation");
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(agent_id_to_did_key("agent-a"), agent_id_to_did_key("agent-a"));
    }

    #[test]
    fn distinct_identities_yield_distinct_dids() {
        assert_ne!(agent_id_to_did_key("agent-a"), agent_id_to_did_key("agent-b"));
    }

    #[test]
    fn ed25519_did_keys_use_the_canonical_prefix() {
        // The multicodec 0xed01 prefix renders as the well-known "z6Mk" head.
        let did = agent_id_to_did_key("anything");
        assert!(did.starts_with("did:key:z6Mk"), "got {did}");
    }

    #[test]
    fn passes_through_existing_did_key() {
        let existing = "did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T";
        assert_eq!(agent_id_to_did_key(existing), existing);
    }

    #[test]
    fn derived_did_decodes_to_ed25519_multicodec_payload() {
        let did = agent_id_to_did_key("payload-check");
        let encoded = did.strip_prefix("did:key:z").unwrap();
        let decoded = bs58::decode(encoded).into_vec().unwrap();
        assert_eq!(&decoded[..2], &ED25519_MULTICODEC_PREFIX);
        assert_eq!(decoded.len(), 2 + ED25519_PUBLIC_KEY_LEN);
    }
}
