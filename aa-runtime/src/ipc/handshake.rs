//! IPC session handshake verification (AAASM-3585).
//!
//! On every accepted UDS connection the runtime issues a fresh random nonce and
//! requires the SDK to reply with an Ed25519 signature over `nonce ||
//! sdk_version`. This binds the session to a consistent, replay-resistant SDK
//! identity and authenticates the *claimed SDK version* (AAASM-3666) so a
//! downgraded build cannot silently present a current version string.
//!
//! ## Trust boundary (AAASM-3922)
//!
//! This handshake is **not** an authentication secret and must not be relied on
//! as one. The expected verifying key is derived deterministically from the
//! configured **agent id** (seed = `SHA-256(agent_id)` → `SigningKey` →
//! `VerifyingKey`), and the agent id is the UDS socket filename — a public,
//! non-secret identifier. Any local process that can reach the socket can
//! recompute the same keypair and produce a valid signature, so the signature
//! proves *integrity and version-binding*, not possession of a secret.
//!
//! The real trust boundary for the IPC channel is enforced elsewhere:
//!   * the socket is created with `0600` permissions, and
//!   * the runtime checks the connecting peer's credentials (peercred UID)
//!     against the expected owner.
//!
//! Those two controls — not this signature — are what stop an unrelated local
//! user from connecting and answering "allow" for everything or flooding forged
//! audit events. The handshake adds defence-in-depth (a consistent identity and
//! an authenticated version) *within* that boundary.
//!
//! The SDK (`aa-sdk-client`'s `AgentKeypair::derive`) and the runtime are both
//! configured with the same `AA_AGENT_ID`, so both sides arrive at the same
//! keypair without exchanging key material.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use aa_proto::assembly::ipc::v1::HandshakeProof;
use aa_security::sdk_identity::VerifiedSdkIdentity;

/// Number of random bytes in a per-session challenge nonce.
pub const NONCE_LEN: usize = 32;

/// Derive the Ed25519 verifying key the runtime expects an SDK handshake to be
/// signed with, from the configured agent id.
///
/// Mirrors `aa-sdk-client::keypair::AgentKeypair::derive`: the seed is
/// `SHA-256(agent_id)`, which is always a valid 32-byte Ed25519 secret scalar
/// seed, so derivation never fails.
///
/// Note (AAASM-3922): the agent id is the public UDS socket filename, so this
/// "key" is not a secret — any local peer that can reach the socket can derive
/// it too. The signature it verifies provides integrity + version-binding, not
/// authentication; the socket's `0600` perms + peercred UID check are the true
/// trust boundary (see the module docs).
pub fn expected_verifying_key(agent_id: &str) -> VerifyingKey {
    let seed: [u8; 32] = Sha256::digest(agent_id.as_bytes()).into();
    SigningKey::from_bytes(&seed).verifying_key()
}

/// Generate a fresh random 32-byte challenge nonce.
///
/// The bytes are produced directly by `rand::random`, which draws from a
/// ChaCha-based, OS-seeded thread CSPRNG and *returns* the value. Producing the
/// array from the RNG (rather than zero-initializing a buffer and filling it in
/// place) keeps any constant literal out of the nonce data-flow.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    rand::random::<[u8; NONCE_LEN]>()
}

/// The exact bytes the handshake signature must cover: the raw `nonce` followed
/// by the UTF-8 `sdk_version` bytes (AAASM-3666).
///
/// Both sides MUST construct this identically — the SDK signs it
/// (`aa-sdk-client::ipc::handshake_signed_payload`) and the runtime
/// reconstructs it from the received nonce + the proof's claimed version before
/// verifying. Binding the version into the signed payload is what makes the
/// version *authenticated*: a local tamperer cannot swap a downgraded build's
/// version for a current one without invalidating the signature. An empty
/// `sdk_version` reduces the payload to the bare nonce (pre-AAASM-3666
/// behaviour).
fn signed_payload(nonce: &[u8], sdk_version: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(nonce.len() + sdk_version.len());
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(sdk_version.as_bytes());
    payload
}

/// Verify a `HandshakeProof` against the challenge `nonce` and the expected
/// verifying key for this agent, returning the verified SDK identity.
///
/// Returns `Some(VerifiedSdkIdentity)` only when the signature is a valid
/// Ed25519 signature over `nonce || proof.sdk_version` AND the proof's
/// `public_key` matches the expected key (so a peer cannot present a different,
/// self-controlled key it does hold). Any malformed field (wrong-length
/// signature, non-hex / mismatched public key, bad signature) returns `None`
/// (fail closed).
///
/// Note (AAASM-3922): because the expected key is derived from the non-secret
/// agent id, a local peer that already passes the socket's `0600` perms +
/// peercred UID check could itself produce a valid proof. This verification
/// therefore provides integrity and version-binding *within* that trust
/// boundary — it is not, on its own, proof that the peer holds a secret.
///
/// Because the version is part of the verified payload, the returned identity's
/// version is trustworthy: an empty version yields
/// [`VerifiedSdkIdentity::none`] (present-without-version — the verdict stays
/// `Unverifiable`, no regression for pre-AAASM-3666 SDKs), and a non-empty
/// version yields [`VerifiedSdkIdentity::with_version`] which the classifier can
/// flag as downgraded/forged (AAASM-3666 / AAASM-3571).
pub fn verify_proof(nonce: &[u8], proof: &HandshakeProof, expected: &VerifyingKey) -> Option<VerifiedSdkIdentity> {
    // The presented public key must be the expected one — binds the channel to
    // the agent's registered identity, not just to "some key the peer holds".
    let expected_hex = hex::encode(expected.to_bytes());
    if proof.public_key != expected_hex {
        return None;
    }

    // Signature must be exactly 64 bytes.
    let sig_bytes: [u8; 64] = match proof.signature.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return None,
    };
    let signature = Signature::from_bytes(&sig_bytes);

    // Verify over `nonce || sdk_version` — the version is authenticated, not
    // merely carried alongside the proof.
    let payload = signed_payload(nonce, &proof.sdk_version);
    if expected.verify_strict(&payload, &signature).is_err() {
        return None;
    }

    // Authenticated. Carry the verified version through only when one was signed;
    // an empty version stays present-without-version (Unverifiable).
    Some(if proof.sdk_version.is_empty() {
        VerifiedSdkIdentity::none()
    } else {
        VerifiedSdkIdentity::with_version(proof.sdk_version.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// Reconstruct the SDK-side signing key for an agent id the same way the
    /// SDK does, so the test can produce a genuine proof.
    fn signing_key(agent_id: &str) -> SigningKey {
        let seed: [u8; 32] = Sha256::digest(agent_id.as_bytes()).into();
        SigningKey::from_bytes(&seed)
    }

    fn valid_proof(agent_id: &str, nonce: &[u8]) -> HandshakeProof {
        valid_proof_with_version(agent_id, nonce, "")
    }

    fn valid_proof_with_version(agent_id: &str, nonce: &[u8], sdk_version: &str) -> HandshakeProof {
        let sk = signing_key(agent_id);
        let sig = sk.sign(&signed_payload(nonce, sdk_version));
        HandshakeProof {
            agent_did: format!("did:key:{agent_id}"),
            public_key: hex::encode(sk.verifying_key().to_bytes()),
            signature: sig.to_bytes().to_vec(),
            sdk_version: sdk_version.to_string(),
        }
    }

    #[test]
    fn derivation_matches_sdk_keypair_for_same_agent_id() {
        // Same agent id → same verifying key on both sides.
        let vk = expected_verifying_key("agent-x");
        let sk = signing_key("agent-x");
        assert_eq!(vk.to_bytes(), sk.verifying_key().to_bytes());
    }

    #[test]
    fn nonce_is_32_bytes_and_varies() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_eq!(a.len(), NONCE_LEN);
        assert_ne!(a, b, "two nonces must differ (random)");
    }

    #[test]
    fn valid_proof_verifies() {
        let nonce = generate_nonce();
        let proof = valid_proof("agent-x", &nonce);
        // No version signed → authenticated but present-without-version.
        let verified = verify_proof(&nonce, &proof, &expected_verifying_key("agent-x"));
        assert_eq!(verified, Some(VerifiedSdkIdentity::none()));
    }

    #[test]
    fn valid_proof_with_version_carries_the_verified_version() {
        // AAASM-3666: a proof signing `nonce || version` verifies and the
        // returned identity carries that authenticated version.
        let nonce = generate_nonce();
        let proof = valid_proof_with_version("agent-x", &nonce, "1.4.0");
        let verified = verify_proof(&nonce, &proof, &expected_verifying_key("agent-x"));
        assert_eq!(verified, Some(VerifiedSdkIdentity::with_version("1.4.0")));
    }

    #[test]
    fn tampered_version_is_rejected() {
        // AAASM-3666: the version is authenticated. A local tamperer who swaps
        // the claimed version (e.g. a downgraded build presenting a current
        // version string) without re-signing must fail — the signature no longer
        // matches `nonce || version`.
        let nonce = generate_nonce();
        let mut proof = valid_proof_with_version("agent-x", &nonce, "0.1.0");
        proof.sdk_version = "9.9.9".to_string(); // claim a newer version, same sig
        assert!(verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")).is_none());
    }

    #[test]
    fn forged_signature_is_rejected() {
        let nonce = generate_nonce();
        let mut proof = valid_proof("agent-x", &nonce);
        // Flip a byte in the signature.
        proof.signature[0] ^= 0xFF;
        assert!(verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")).is_none());
    }

    #[test]
    fn signature_over_a_different_nonce_is_rejected() {
        let nonce = generate_nonce();
        let other = generate_nonce();
        let proof = valid_proof("agent-x", &other);
        assert!(verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")).is_none());
    }

    #[test]
    fn proof_from_a_different_agent_key_is_rejected() {
        // A peer holds a real key, but not the expected agent's key.
        let nonce = generate_nonce();
        let proof = valid_proof("attacker-agent", &nonce);
        assert!(verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")).is_none());
    }

    #[test]
    fn wrong_length_signature_is_rejected() {
        let nonce = generate_nonce();
        let mut proof = valid_proof("agent-x", &nonce);
        proof.signature.truncate(10);
        assert!(verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")).is_none());
    }
}
