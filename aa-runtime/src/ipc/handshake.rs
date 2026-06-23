//! IPC session handshake verification (AAASM-3585).
//!
//! On every accepted UDS connection the runtime issues a fresh random nonce and
//! requires the SDK to reply with an Ed25519 signature over it, proving the peer
//! holds the agent's private key. Reaching the socket is not enough — a local
//! attacker who connects still cannot answer "allow" for everything or flood
//! forged audit events, because it cannot produce a valid signature.
//!
//! The expected verifying key is derived **deterministically from the runtime's
//! configured agent id**, mirroring `aa-sdk-client`'s `AgentKeypair::derive`
//! (seed = `SHA-256(agent_id)` → `SigningKey` → `VerifyingKey`). The SDK and the
//! runtime are configured with the same `AA_AGENT_ID`, so both sides arrive at
//! the same keypair without sharing key material.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use aa_proto::assembly::ipc::v1::HandshakeProof;

/// Number of random bytes in a per-session challenge nonce.
pub const NONCE_LEN: usize = 32;

/// Derive the Ed25519 verifying key the runtime expects an SDK to prove
/// possession of, from the configured agent id.
///
/// Mirrors `aa-sdk-client::keypair::AgentKeypair::derive`: the seed is
/// `SHA-256(agent_id)`, which is always a valid 32-byte Ed25519 secret scalar
/// seed, so derivation never fails.
pub fn expected_verifying_key(agent_id: &str) -> VerifyingKey {
    let seed: [u8; 32] = Sha256::digest(agent_id.as_bytes()).into();
    SigningKey::from_bytes(&seed).verifying_key()
}

/// Generate a fresh random 32-byte challenge nonce.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    // `getrandom` reads from the OS CSPRNG; a failure here means the platform
    // has no entropy source, which is unrecoverable for a security handshake.
    getrandom::getrandom(&mut nonce).expect("OS RNG must be available for the IPC handshake nonce");
    nonce
}

/// Verify a `HandshakeProof` against the challenge `nonce` and the expected
/// verifying key for this agent.
///
/// Returns `true` only when the signature is a valid Ed25519 signature over the
/// exact nonce bytes AND the proof's `public_key` matches the expected key (so a
/// peer cannot present a different, self-controlled key it does hold). Any
/// malformed field (wrong-length signature, non-hex / mismatched public key)
/// fails closed.
pub fn verify_proof(nonce: &[u8], proof: &HandshakeProof, expected: &VerifyingKey) -> bool {
    // The presented public key must be the expected one — binds the channel to
    // the agent's registered identity, not just to "some key the peer holds".
    let expected_hex = hex::encode(expected.to_bytes());
    if proof.public_key != expected_hex {
        return false;
    }

    // Signature must be exactly 64 bytes.
    let sig_bytes: [u8; 64] = match proof.signature.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_bytes);

    expected.verify_strict(nonce, &signature).is_ok()
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
        let sk = signing_key(agent_id);
        let sig = sk.sign(nonce);
        HandshakeProof {
            agent_did: format!("did:key:{agent_id}"),
            public_key: hex::encode(sk.verifying_key().to_bytes()),
            signature: sig.to_bytes().to_vec(),
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
        assert!(verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")));
    }

    #[test]
    fn forged_signature_is_rejected() {
        let nonce = generate_nonce();
        let mut proof = valid_proof("agent-x", &nonce);
        // Flip a byte in the signature.
        proof.signature[0] ^= 0xFF;
        assert!(!verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")));
    }

    #[test]
    fn signature_over_a_different_nonce_is_rejected() {
        let nonce = generate_nonce();
        let other = generate_nonce();
        let proof = valid_proof("agent-x", &other);
        assert!(!verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")));
    }

    #[test]
    fn proof_from_a_different_agent_key_is_rejected() {
        // A peer holds a real key, but not the expected agent's key.
        let nonce = generate_nonce();
        let proof = valid_proof("attacker-agent", &nonce);
        assert!(!verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")));
    }

    #[test]
    fn wrong_length_signature_is_rejected() {
        let nonce = generate_nonce();
        let mut proof = valid_proof("agent-x", &nonce);
        proof.signature.truncate(10);
        assert!(!verify_proof(&nonce, &proof, &expected_verifying_key("agent-x")));
    }
}
