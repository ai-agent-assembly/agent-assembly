//! Proto ↔ registry type conversions for the AgentLifecycleService.

use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use sha2::{Digest, Sha256};

/// Derive a deterministic 16-byte registry key from a composite proto [`AgentId`](ProtoAgentId).
///
/// Hashes `"{org_id}/{team_id}/{agent_id}"` with SHA-256, then truncates to 16 bytes.
pub fn proto_agent_id_to_key(id: &ProtoAgentId) -> [u8; 16] {
    let composite = format!("{}/{}/{}", id.org_id, id.team_id, id.agent_id);
    let digest = Sha256::digest(composite.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Validate that a proto [`AgentId`](ProtoAgentId) is populated and that its
/// `agent_id` is a syntactically-valid `did:key` DID.
///
/// A `did:key` identifier has the shape `did:key:<multibase>` where the
/// multibase value is `base58btc` (multibase prefix `z`). This check verifies:
///
/// 1. `agent_id` is non-empty.
/// 2. It begins with the `did:key:` prefix.
/// 3. The method-specific identifier starts with the `z` (base58btc)
///    multibase prefix and the remainder decodes to a non-empty byte string.
///
/// It deliberately does not assert the multicodec key type or key length, so
/// any well-formed base58btc `did:key` is accepted.
pub fn validate_proto_agent_id(id: &ProtoAgentId) -> Result<(), &'static str> {
    if id.agent_id.is_empty() {
        return Err("agent_id is empty");
    }
    validate_did_key(&id.agent_id)
}

/// Verify that `value` is a syntactically-valid `base58btc` `did:key` DID.
fn validate_did_key(value: &str) -> Result<(), &'static str> {
    let multibase = value
        .strip_prefix("did:key:")
        .ok_or("agent_id is not a did:key DID (missing \"did:key:\" prefix)")?;

    let encoded = multibase
        .strip_prefix('z')
        .ok_or("agent_id is not a valid did:key DID (expected base58btc \"z\" multibase prefix)")?;

    if encoded.is_empty() {
        return Err("agent_id is not a valid did:key DID (empty multibase value)");
    }

    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| "agent_id is not a valid did:key DID (multibase value is not valid base58btc)")?;

    if decoded.is_empty() {
        return Err("agent_id is not a valid did:key DID (multibase value decodes to empty bytes)");
    }

    Ok(())
}

/// Multicodec varint prefix identifying an `ed25519-pub` key inside a `did:key`.
///
/// `did:key` encodes the key type as an unsigned-varint multicodec code ahead of
/// the raw key bytes; `ed25519-pub` is code `0xed`, whose varint encoding is the
/// two bytes `[0xed, 0x01]`.
const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Why a `did:key` `agent_id` failed to bind to a separately-supplied
/// `public_key` (AAASM-4787).
///
/// The variant drives the gRPC status the caller returns: a malformed or
/// non-Ed25519 `did:key` (or a malformed `public_key`) is the caller's own input
/// error (`InvalidArgument`), whereas a well-formed Ed25519 `did:key` whose
/// embedded key simply differs from the supplied `public_key` is an
/// identity-squatting attempt (`Unauthenticated`).
#[derive(Debug, PartialEq, Eq)]
pub enum DidKeyBindingError {
    /// The `did:key` is not a base58btc Ed25519 `did:key`, or the supplied
    /// `public_key` is not 32 bytes of hex.
    Malformed(&'static str),
    /// The `did:key`'s embedded Ed25519 key does not equal the supplied
    /// `public_key` — the caller is presenting a DID whose key it does not hold.
    Mismatch,
}

impl std::fmt::Display for DidKeyBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "{msg}"),
            Self::Mismatch => write!(
                f,
                "agent_id did:key embedded public key does not match the supplied public_key"
            ),
        }
    }
}

/// Extract the raw 32-byte Ed25519 public key that a `did:key` `agent_id`
/// cryptographically encodes.
///
/// A `did:key` is `did:key:z<base58btc(<multicodec-varint><key-bytes>)>`; for
/// Ed25519 the multicodec is `ed25519-pub` (`[0xed, 0x01]`) followed by the 32
/// raw public-key bytes. Returns the embedded key so `Register` /
/// `RequestChallenge` can bind it to the separately-supplied `public_key`
/// (AAASM-4787) — without that binding an attacker can present a victim's
/// `did:key` alongside their own `public_key` plus a proof under their own key
/// and squat the victim's identity.
///
/// Unlike [`validate_did_key`], this asserts the multicodec key type: it errors
/// when the value is not a base58btc `did:key`, carries a non-Ed25519
/// multicodec, or does not decode to exactly the 2-byte prefix plus 32 key bytes.
pub fn did_key_ed25519_public_key(value: &str) -> Result<[u8; 32], &'static str> {
    let multibase = value
        .strip_prefix("did:key:")
        .ok_or("agent_id is not a did:key DID (missing \"did:key:\" prefix)")?;

    let encoded = multibase
        .strip_prefix('z')
        .ok_or("agent_id is not a valid did:key DID (expected base58btc \"z\" multibase prefix)")?;

    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| "agent_id is not a valid did:key DID (multibase value is not valid base58btc)")?;

    let key_bytes = decoded
        .strip_prefix(&ED25519_PUB_MULTICODEC)
        .ok_or("agent_id did:key is not an ed25519-pub multicodec key")?;

    key_bytes
        .try_into()
        .map_err(|_| "agent_id did:key does not encode a 32-byte Ed25519 public key")
}

/// Assert that the Ed25519 key embedded in the `did:key` `agent_id` equals the
/// separately-supplied `public_key_hex` (AAASM-4787).
///
/// This is the cryptographic binding that stops did:key identity squatting: the
/// registration possession proof only proves the caller holds the private key
/// for `public_key`, *not* that `public_key` is the key the `did:key` actually
/// names. Both are supplied by the caller, so without this check an attacker can
/// pair a victim's `did:key` with their own key pair. Callers map
/// [`DidKeyBindingError::Malformed`] to `InvalidArgument` and
/// [`DidKeyBindingError::Mismatch`] to `Unauthenticated`.
pub fn assert_did_key_binds_public_key(agent_id: &str, public_key_hex: &str) -> Result<(), DidKeyBindingError> {
    let embedded = did_key_ed25519_public_key(agent_id).map_err(DidKeyBindingError::Malformed)?;

    let supplied =
        hex::decode(public_key_hex).map_err(|_| DidKeyBindingError::Malformed("public_key is not valid hex"))?;
    if supplied.len() != 32 {
        return Err(DidKeyBindingError::Malformed(
            "public_key must be 32 bytes (64 hex chars)",
        ));
    }

    if embedded[..] != supplied[..] {
        return Err(DidKeyBindingError::Mismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto_id(agent_id: &str) -> ProtoAgentId {
        ProtoAgentId {
            org_id: "acme-corp".into(),
            team_id: "platform".into(),
            agent_id: agent_id.into(),
        }
    }

    #[test]
    fn accepts_valid_did_key() {
        // The DID used across the conformance vectors.
        let id = proto_id("did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T");
        assert!(validate_proto_agent_id(&id).is_ok());
    }

    #[test]
    fn rejects_empty_agent_id() {
        let id = proto_id("");
        assert_eq!(validate_proto_agent_id(&id), Err("agent_id is empty"));
    }

    #[test]
    fn rejects_non_did_string() {
        let id = proto_id("agent-lifecycle-1");
        assert!(validate_proto_agent_id(&id).is_err());
    }

    #[test]
    fn rejects_wrong_did_method() {
        // A real DID, but not the did:key method.
        let id = proto_id("did:web:example.com");
        assert!(validate_proto_agent_id(&id).is_err());
    }

    #[test]
    fn rejects_did_key_without_multibase_prefix() {
        // Missing the leading 'z' base58btc multibase marker.
        let id = proto_id("did:key:6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T");
        assert!(validate_proto_agent_id(&id).is_err());
    }

    #[test]
    fn rejects_did_key_with_empty_multibase() {
        let id = proto_id("did:key:z");
        assert!(validate_proto_agent_id(&id).is_err());
    }

    #[test]
    fn rejects_did_key_with_invalid_base58() {
        // '0', 'O', 'I', 'l' are not in the base58btc alphabet.
        let id = proto_id("did:key:z0OIl");
        assert!(validate_proto_agent_id(&id).is_err());
    }
}
