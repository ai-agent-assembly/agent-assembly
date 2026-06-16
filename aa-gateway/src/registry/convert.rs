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
