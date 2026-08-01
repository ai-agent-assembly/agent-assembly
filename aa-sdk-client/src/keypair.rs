//! Ed25519 keypairs for agent identity and for the local IPC transport.
//!
//! The gateway's `AgentLifecycleService.Register` requires *both* a
//! syntactically-valid `did:key` agent identity *and* a real Ed25519
//! `public_key` (32 bytes, hex-encoded — see
//! `aa-gateway/src/service/lifecycle_service.rs`, which calls
//! `VerifyingKey::from_bytes` on the decoded hex). A bare SHA-256 hash is not a
//! valid Ed25519 verifying key, so the registration identity and the
//! `public_key` field must both come from one real keypair to stay consistent.
//!
//! # Two keys, one of which is a secret (AAASM-5332)
//!
//! This module deliberately exposes two *different* kinds of keypair, because
//! the crate needs two things that look alike and are not:
//!
//! * [`AgentKeypair::generate`] / [`AgentKeypair::from_seed`] — the **durable
//!   agent identity key**. Its private half is real key material: randomly
//!   generated from the OS CSPRNG, persisted once by
//!   [`crate::identity_store`], and never reconstructible from anything public.
//!   This is the key the registration possession proof is made with.
//! * [`AgentKeypair::derive_transport_key`] — the **local IPC transport key**,
//!   deterministically derived from the agent id. It is *not* a secret and is
//!   documented as such at both ends (see `aa-runtime::ipc::handshake`, whose
//!   `expected_verifying_key` recomputes the identical value, and AAASM-3922).
//!
//! # Why the identity key is generated, not derived
//!
//! Until AAASM-5332 the identity key was *also* derived, seeded with
//! `SHA-256(agent_id)`. That looked deliberate — it bought a stable identity
//! across restarts with nothing to persist — but the seed is a hash of a public
//! value. The agent id appears in audit records, topology views and the
//! dashboard, and `Register` is reachable unauthenticated by design (it is a
//! bootstrap endpoint mounted behind `enrich_interceptor`, which authenticates
//! nothing). So the possession proof, the single control deciding *who may
//! register as a given agent*, proved only that the caller could compute
//! SHA-256 of a value everyone can read.
//!
//! Every surrounding control was correctly built and none of them helped,
//! because each rests on that same non-secret: `enforce_did_key_binding` binds
//! the DID to the presented public key, but an attacker who derives the keypair
//! derives a self-consistent pair; `verify_possession_proof` checks a real
//! signature, made with a key the attacker holds just as legitimately; the nonce
//! is genuinely single-use, which stops replay and not impersonation.
//!
//! A derived key cannot be repaired by strengthening what surrounds it. The
//! private half has to be something the attacker cannot compute, which means it
//! has to be random and it has to be stored.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Multicodec prefix for an Ed25519 public key (`0xed`), varint-encoded as the
/// two bytes `0xed 0x01`. An Ed25519 `did:key` is the base58btc multibase
/// encoding of these two bytes followed by the 32-byte verifying key.
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// An Ed25519 keypair backing an agent's `did:key`, `public_key` and
/// signatures.
///
/// Holds the signing key so it can both expose the verifying key (and the
/// identity values derived from it) and **sign** challenges — the latter proves
/// key possession to the gateway at registration and in the local IPC session
/// handshake (AAASM-3587). The verifying key is guaranteed to come from a
/// genuine, valid Ed25519 keypair that the gateway will accept.
///
/// How the instance was built decides whether its private half is a secret at
/// all — see the module docs. [`generate`](Self::generate) and
/// [`from_seed`](Self::from_seed) produce identity keys;
/// [`derive_transport_key`](Self::derive_transport_key) produces the
/// deliberately non-secret IPC transport key.
pub struct AgentKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl AgentKeypair {
    /// Build an identity keypair from a 32-byte secret seed (AAASM-5332).
    ///
    /// Every 32-byte value is a valid Ed25519 secret scalar seed, so this cannot
    /// fail. `seed` is the private half of the agent's identity and must have
    /// come from [`crate::identity_store`] — either freshly generated from the
    /// OS CSPRNG or read back from the owner-only key file. Seeding this from
    /// anything an attacker could compute reintroduces the AAASM-5332 defect
    /// wholesale, which is why the only in-crate caller is the identity store.
    pub(crate) fn from_seed(seed: &Zeroizing<[u8; 32]>) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Generate a fresh identity keypair from the operating system's CSPRNG.
    ///
    /// Delegates the seed to [`crate::identity_store::random_seed`], so there is
    /// exactly one randomness source in the crate to audit. Returns the seed
    /// alongside the keypair because the caller — the identity store — must
    /// persist it: a generated key that is not written down is a new identity on
    /// every process start, which is the opposite of what registration needs.
    pub(crate) fn generate() -> std::io::Result<(Self, Zeroizing<[u8; 32]>)> {
        let seed = crate::identity_store::random_seed()?;
        let keypair = Self::from_seed(&seed);
        Ok((keypair, seed))
    }

    /// Derive the **non-secret** local IPC transport keypair for `identifier`.
    ///
    /// The seed is `SHA-256(identifier)` (always 32 bytes), so derivation never
    /// fails — and so any local process that knows the agent id can recompute
    /// this keypair. That is understood and accepted at both ends: the runtime's
    /// `aa-runtime::ipc::handshake::expected_verifying_key` computes the very
    /// same value in order to check the handshake, and the trust boundary for
    /// that channel is the socket's `0600` mode plus the peercred UID check, not
    /// this signature (AAASM-3922). What the signature buys there is integrity
    /// and SDK-version binding (AAASM-3666) *within* that boundary.
    ///
    /// It follows that this key must never be used where a secret is required.
    /// It is not the agent's identity and it must not sign a registration
    /// possession proof — for that, and for the `did:key` the gateway registers,
    /// use the durable key from [`crate::identity_store`]. The name says
    /// "transport" so that a future caller reaching for a keypair cannot pick
    /// this one up believing it authenticates anybody.
    pub fn derive_transport_key(identifier: &str) -> Self {
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

    /// The transport key must stay reproducible from the agent id alone: the
    /// runtime recomputes it independently to check the IPC handshake, so a
    /// change here silently breaks every SDK connection.
    #[test]
    fn transport_key_derivation_is_deterministic() {
        assert_eq!(
            AgentKeypair::derive_transport_key("agent-a").public_key_hex(),
            AgentKeypair::derive_transport_key("agent-a").public_key_hex()
        );
    }

    /// The exact value the runtime expects. `aa-runtime`'s `expected_verifying_key`
    /// computes `SHA-256(agent_id)` → `SigningKey` → `VerifyingKey`; pinning it
    /// here means a well-meaning change to the transport key fails in this crate
    /// rather than as a mysterious handshake rejection at run time.
    #[test]
    fn transport_key_is_the_value_the_runtime_recomputes() {
        let seed: [u8; 32] = Sha256::digest(b"agent-a").into();
        let expected = SigningKey::from_bytes(&seed).verifying_key();
        assert_eq!(
            AgentKeypair::derive_transport_key("agent-a").public_key_bytes(),
            expected.to_bytes()
        );
    }

    #[test]
    fn distinct_identifiers_yield_distinct_transport_keys() {
        assert_ne!(
            AgentKeypair::derive_transport_key("agent-a").public_key_hex(),
            AgentKeypair::derive_transport_key("agent-b").public_key_hex()
        );
    }

    /// The heart of AAASM-5332: an identity key is *random*, so asking for one
    /// twice for the same agent must not produce the same key. If this ever
    /// passes trivially the generator has gone back to deriving from something.
    #[test]
    fn generated_identity_keys_are_random_not_derived() {
        let (first, first_seed) = AgentKeypair::generate().expect("the OS CSPRNG must be readable");
        let (second, second_seed) = AgentKeypair::generate().expect("the OS CSPRNG must be readable");

        assert_ne!(
            first.public_key_hex(),
            second.public_key_hex(),
            "two generated identity keys must differ; identical keys mean the private half is a \
             function of something predictable, which is the defect this ticket exists to remove"
        );
        assert_ne!(*first_seed, *second_seed, "the seeds themselves must differ");
    }

    /// A generated identity key must never coincide with the transport key for
    /// any identifier — that is what makes knowing the agent id insufficient.
    #[test]
    fn a_generated_identity_key_is_not_the_transport_key_for_any_identifier() {
        let (identity, _) = AgentKeypair::generate().expect("the OS CSPRNG must be readable");
        for id in ["agent-a", "ops-laptop", "", "did:key:z6Mkwhatever"] {
            assert_ne!(
                identity.public_key_hex(),
                AgentKeypair::derive_transport_key(id).public_key_hex(),
                "a generated identity key must not be recomputable from `{id}`"
            );
        }
    }

    /// Round-trip: the seed the store persists must rebuild the same key, or a
    /// restart silently becomes a different agent.
    #[test]
    fn from_seed_reproduces_the_generated_key() {
        let (generated, seed) = AgentKeypair::generate().expect("the OS CSPRNG must be readable");
        assert_eq!(
            AgentKeypair::from_seed(&seed).public_key_hex(),
            generated.public_key_hex()
        );
    }

    #[test]
    fn public_key_hex_is_64_chars() {
        let hex = AgentKeypair::derive_transport_key("any").public_key_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn public_key_is_a_valid_ed25519_verifying_key() {
        // Mirror the gateway's acceptance check: decode hex and parse as a key.
        let (kp, _) = AgentKeypair::generate().expect("the OS CSPRNG must be readable");
        let bytes = hex::decode(kp.public_key_hex()).unwrap();
        let arr: [u8; 32] = bytes.try_into().unwrap();
        VerifyingKey::from_bytes(&arr).expect("public_key must be a valid Ed25519 key");
    }

    #[test]
    fn sign_produces_a_signature_that_verifies_under_the_public_key() {
        use ed25519_dalek::{Signature, Verifier};
        let (kp, _) = AgentKeypair::generate().expect("the OS CSPRNG must be readable");
        let msg = b"challenge-nonce";
        let sig_bytes = kp.sign(msg);
        let vk = VerifyingKey::from_bytes(&kp.public_key_bytes()).unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn sign_is_deterministic_for_same_input() {
        let kp = AgentKeypair::derive_transport_key("signer");
        assert_eq!(kp.sign(b"abc"), kp.sign(b"abc"));
    }

    #[test]
    fn did_key_uses_canonical_ed25519_prefix() {
        let did = AgentKeypair::derive_transport_key("anything").did_key();
        assert!(did.starts_with("did:key:z6Mk"), "got {did}");
    }

    #[test]
    fn did_key_and_public_key_encode_the_same_key() {
        let (kp, _) = AgentKeypair::generate().expect("the OS CSPRNG must be readable");
        let encoded = kp.did_key().strip_prefix("did:key:z").unwrap().to_string();
        let decoded = bs58::decode(encoded).into_vec().unwrap();
        // Strip the 0xed 0x01 multicodec prefix; the rest must equal the pubkey.
        assert_eq!(&decoded[2..], &kp.public_key_bytes());
    }
}
