//! Deterministic Ed25519 keypair derivation for gateway registration.
//!
//! The gateway's `AgentLifecycleService.Register` requires *both* a
//! syntactically-valid `did:key` agent identity *and* a real Ed25519
//! `public_key` (32 bytes, hex-encoded — see
//! `aa-gateway/src/service/lifecycle_service.rs`, which calls
//! `VerifyingKey::from_bytes` on the decoded hex). A bare SHA-256 hash is not a
//! valid Ed25519 verifying key, so the registration identity and the
//! `public_key` field must both come from one real keypair to stay consistent.
//!
//! SDKs configure agents with a human-readable identifier rather than a
//! provisioned keypair, so this module derives a **deterministic** keypair from
//! that identifier: the same agent id always yields the same keypair, giving a
//! stable identity across process restarts without persisting key material. The
//! seed is `SHA-256(identifier)`, fed to [`SigningKey::from_bytes`]; the
//! resulting [`VerifyingKey`] backs both the `did:key` and the `public_key`.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Multicodec prefix for an Ed25519 public key (`0xed`), varint-encoded as the
/// two bytes `0xed 0x01`. An Ed25519 `did:key` is the base58btc multibase
/// encoding of these two bytes followed by the 32-byte verifying key.
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// A deterministic Ed25519 keypair derived from an agent identifier.
///
/// Holds the signing key so it can both expose the verifying key (and the
/// identity values derived from it) and **sign** challenges — the latter proves
/// key possession in the local IPC session handshake (AAASM-3587) and could
/// back per-RPC request signing. The verifying key is guaranteed to come from a
/// genuine, valid Ed25519 keypair that the gateway will accept.
pub struct AgentKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl AgentKeypair {
    /// Derive the deterministic keypair for `identifier`.
    ///
    /// The seed is `SHA-256(identifier)` (always 32 bytes), which is a valid
    /// Ed25519 secret scalar seed, so derivation never fails.
    pub fn derive(identifier: &str) -> Self {
        let seed: [u8; 32] = Sha256::digest(identifier.as_bytes()).into();
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// The 32-byte Ed25519 verifying (public) key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Sign `message` with the agent's Ed25519 signing key, returning the raw
    /// 64-byte signature. Used to prove key possession over a runtime-issued
    /// handshake nonce (AAASM-3587).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// The verifying key hex-encoded, as the gateway's `public_key` field
    /// expects (64 lowercase hex chars).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// The canonical Ed25519 `did:key` for this keypair: the base58btc
    /// multibase (`z` prefix) of `0xed 0x01` followed by the 32-byte verifying
    /// key. Passes the gateway's `did:key` validation and binds the DID to the
    /// same key as [`public_key_hex`](Self::public_key_hex).
    pub fn did_key(&self) -> String {
        let mut multicodec = Vec::with_capacity(ED25519_MULTICODEC_PREFIX.len() + 32);
        multicodec.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
        multicodec.extend_from_slice(&self.public_key_bytes());
        let multibase = bs58::encode(&multicodec).into_string();
        format!("did:key:z{multibase}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            AgentKeypair::derive("agent-a").public_key_hex(),
            AgentKeypair::derive("agent-a").public_key_hex()
        );
    }

    #[test]
    fn distinct_identifiers_yield_distinct_keys() {
        assert_ne!(
            AgentKeypair::derive("agent-a").public_key_hex(),
            AgentKeypair::derive("agent-b").public_key_hex()
        );
    }

    #[test]
    fn public_key_hex_is_64_chars() {
        let hex = AgentKeypair::derive("any").public_key_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn public_key_is_a_valid_ed25519_verifying_key() {
        // Mirror the gateway's acceptance check: decode hex and parse as a key.
        let kp = AgentKeypair::derive("gateway-accepts-me");
        let bytes = hex::decode(kp.public_key_hex()).unwrap();
        let arr: [u8; 32] = bytes.try_into().unwrap();
        VerifyingKey::from_bytes(&arr).expect("public_key must be a valid Ed25519 key");
    }

    #[test]
    fn sign_produces_a_signature_that_verifies_under_the_public_key() {
        use ed25519_dalek::{Signature, Verifier};
        let kp = AgentKeypair::derive("signer");
        let msg = b"challenge-nonce";
        let sig_bytes = kp.sign(msg);
        let vk = VerifyingKey::from_bytes(&kp.public_key_bytes()).unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn sign_is_deterministic_for_same_input() {
        let kp = AgentKeypair::derive("signer");
        assert_eq!(kp.sign(b"abc"), kp.sign(b"abc"));
    }

    #[test]
    fn did_key_uses_canonical_ed25519_prefix() {
        let did = AgentKeypair::derive("anything").did_key();
        assert!(did.starts_with("did:key:z6Mk"), "got {did}");
    }

    #[test]
    fn did_key_and_public_key_encode_the_same_key() {
        let kp = AgentKeypair::derive("consistency");
        let encoded = kp.did_key().strip_prefix("did:key:z").unwrap().to_string();
        let decoded = bs58::decode(encoded).into_vec().unwrap();
        // Strip the 0xed 0x01 multicodec prefix; the rest must equal the pubkey.
        assert_eq!(&decoded[2..], &kp.public_key_bytes());
    }
}
