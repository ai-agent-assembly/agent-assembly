//! Argon2id password hashing for native email/password accounts (AAASM-5304).
//!
//! Native accounts (ADR 0031, Postgres-gated) store a user's password as an
//! argon2id PHC-encoded hash — never plaintext. This module is the single place
//! that hash is minted and checked; the encoded string carries the algorithm,
//! version, parameters, and per-hash salt, so parameters can be raised later
//! without a schema change.
//!
//! Parameters are fixed at the OWASP argon2id floor ratified in ADR 0031 §Q2:
//! `m = 19456 (19 MiB)`, `t = 2`, `p = 1`. The implementation may raise (never
//! lower) these later; because the params live in the stored hash, an old hash
//! still verifies after a raise.
//!
//! Distinct from [`crate::api_key`], which argon2-hashes machine API keys with
//! the library default cost. Human passwords are lower-entropy than a 128-bit
//! random API key, so they are hashed at the deliberately higher OWASP floor.

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

/// OWASP-recommended argon2id memory cost, in KiB: 19456 KiB = 19 MiB
/// (ADR 0031 §Q2). This is a floor; it may be raised, never lowered.
const ARGON2_M_COST_KIB: u32 = 19456;

/// OWASP-recommended argon2id time cost (iterations) — ADR 0031 §Q2.
const ARGON2_T_COST: u32 = 2;

/// OWASP-recommended argon2id parallelism (lanes) — ADR 0031 §Q2.
const ARGON2_P_COST: u32 = 1;

/// Build the argon2id hasher pinned to the ADR 0031 §Q2 OWASP-floor parameters.
///
/// `Params::new` only rejects out-of-range values; the three constants above are
/// well within argon2's valid ranges, so this never fails in practice — the
/// `expect` documents that invariant rather than guarding a reachable error.
fn hasher() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("ADR 0031 argon2id params are within valid ranges");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a plaintext password into a PHC-encoded argon2id string for storage.
///
/// The returned string embeds the algorithm, version, `m`/`t`/`p` parameters,
/// and a fresh random salt, so it is self-describing and verifiable by
/// [`verify_password`] without any external parameter record.
///
/// The plaintext is never logged and never leaves this call; only the encoded
/// hash is returned. Returns `Err` only if the underlying hasher fails, which
/// for valid parameters does not happen for well-formed input.
pub fn hash_password(password: &str) -> Result<String, PasswordHashError> {
    // `hash_password` mints the fresh random salt itself (argon2 0.6 /
    // password-hash 0.6). It draws `RECOMMENDED_SALT_LEN` bytes from the OS CSPRNG
    // via getrandom — the same entropy source the explicit `SaltString::generate(&mut OsRng)`
    // used before, so the salt is no less random for being generated inside the call.
    let hash = hasher()
        .hash_password(password.as_bytes())
        .map_err(|_| PasswordHashError::Hash)?;
    Ok(hash.to_string())
}

/// Verify a plaintext candidate against a stored PHC-encoded argon2id hash.
///
/// Returns `true` only if the candidate matches. A malformed or unparseable
/// stored hash yields `false` (never a panic). Verification uses the parameters
/// encoded in the stored hash and argon2's constant-time comparison, so it does
/// not leak a match/no-match timing signal from the final compare. The candidate
/// password is never logged.
pub fn verify_password(hash: &str, candidate: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    // A default `Argon2` is sufficient to *verify*: the cost parameters are read
    // from the encoded hash, not from this instance.
    Argon2::default().verify_password(candidate.as_bytes(), &parsed).is_ok()
}

/// Failure minting an argon2id password hash.
///
/// Carries no detail by design: the error must never surface the password or the
/// partial hash. The single variant is enough for the caller to map to a 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordHashError {
    /// The argon2id hasher failed to produce a hash.
    Hash,
}

impl std::fmt::Display for PasswordHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately generic — no password/hash material in the message.
        write!(f, "failed to hash password")
    }
}

impl std::error::Error for PasswordHashError {}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::{OsRng, RngCore as _};

    /// Build a throwaway random password string at runtime for the tests.
    ///
    /// Generated (not a literal) on purpose: these are disposable test inputs,
    /// and sourcing them from `OsRng` means no constant string ever flows into a
    /// password argument — which is both the honest description of what they are
    /// and what keeps the credential-scanning lint from reading a fixture as a
    /// real hard-coded secret.
    ///
    /// `OsRng` now comes from `rand_core` directly: argon2 0.6 no longer re-exports
    /// it, because `password_hash::rand_core` sits behind a non-default feature.
    /// This crate already declares `rand_core` (with `getrandom`) as a direct
    /// dependency, so nothing new is pulled in.
    fn throwaway_password() -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hash_is_phc_encoded_argon2id() {
        let hash = hash_password(&throwaway_password()).expect("hash");
        // PHC identifier for argon2id.
        assert!(hash.starts_with("$argon2id$"), "must be an argon2id PHC string: {hash}");
    }

    #[test]
    fn hash_encodes_the_owasp_floor_params() {
        let hash = hash_password(&throwaway_password()).expect("hash");
        // The encoded string carries the params so they can be raised without a
        // schema change; assert the ADR 0031 §Q2 floor is what we mint.
        assert!(hash.contains("m=19456"), "memory cost must be the OWASP floor: {hash}");
        assert!(hash.contains("t=2"), "time cost must be the OWASP floor: {hash}");
        assert!(hash.contains("p=1"), "parallelism must be the OWASP floor: {hash}");
    }

    #[test]
    fn verify_accepts_the_correct_password() {
        let pw = throwaway_password();
        let hash = hash_password(&pw).expect("hash");
        assert!(verify_password(&hash, &pw), "the right password must verify");
    }

    #[test]
    fn verify_rejects_a_wrong_password() {
        let pw = throwaway_password();
        let wrong = throwaway_password();
        let hash = hash_password(&pw).expect("hash");
        assert!(!verify_password(&hash, &wrong), "a wrong password must not verify");
    }

    #[test]
    fn verify_rejects_an_unparseable_hash() {
        assert!(
            !verify_password("not-a-phc-hash", &throwaway_password()),
            "a garbage hash must not verify"
        );
    }

    #[test]
    fn distinct_hashes_for_the_same_password() {
        // A fresh random salt per hash means the same password hashes differently
        // each time, yet each still verifies.
        let pw = throwaway_password();
        let a = hash_password(&pw).expect("hash a");
        let b = hash_password(&pw).expect("hash b");
        assert_ne!(a, b, "per-hash salt must make two hashes of one password differ");
        assert!(verify_password(&a, &pw));
        assert!(verify_password(&b, &pw));
    }
}
