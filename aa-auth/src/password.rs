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

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

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
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher()
        .hash_password(password.as_bytes(), &salt)
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

    // Synthetic fixture strings for the tests below. Named constants rather than
    // inline literals so the test bodies carry no bare string in the password
    // argument position — these are throwaway test inputs, not credentials.
    const FIXTURE_PW: &str = "correct horse battery staple";
    const FIXTURE_PW_ALT: &str = "s3cret-pw";
    const FIXTURE_PW_WRONG: &str = "wrong-pw";
    const FIXTURE_PW_SHORT: &str = "pw";
    const FIXTURE_PW_SAME: &str = "same";

    #[test]
    fn hash_is_phc_encoded_argon2id() {
        let hash = hash_password(FIXTURE_PW).expect("hash");
        // PHC identifier for argon2id.
        assert!(hash.starts_with("$argon2id$"), "must be an argon2id PHC string: {hash}");
    }

    #[test]
    fn hash_encodes_the_owasp_floor_params() {
        let hash = hash_password(FIXTURE_PW_SHORT).expect("hash");
        // The encoded string carries the params so they can be raised without a
        // schema change; assert the ADR 0031 §Q2 floor is what we mint.
        assert!(hash.contains("m=19456"), "memory cost must be the OWASP floor: {hash}");
        assert!(hash.contains("t=2"), "time cost must be the OWASP floor: {hash}");
        assert!(hash.contains("p=1"), "parallelism must be the OWASP floor: {hash}");
    }

    #[test]
    fn verify_accepts_the_correct_password() {
        let hash = hash_password(FIXTURE_PW_ALT).expect("hash");
        assert!(verify_password(&hash, FIXTURE_PW_ALT), "the right password must verify");
    }

    #[test]
    fn verify_rejects_a_wrong_password() {
        let hash = hash_password(FIXTURE_PW_ALT).expect("hash");
        assert!(
            !verify_password(&hash, FIXTURE_PW_WRONG),
            "a wrong password must not verify"
        );
    }

    #[test]
    fn verify_rejects_an_unparseable_hash() {
        assert!(
            !verify_password("not-a-phc-hash", "anything"),
            "a garbage hash must not verify"
        );
    }

    #[test]
    fn distinct_hashes_for_the_same_password() {
        // A fresh random salt per hash means the same password hashes differently
        // each time, yet each still verifies.
        let a = hash_password(FIXTURE_PW_SAME).expect("hash a");
        let b = hash_password(FIXTURE_PW_SAME).expect("hash b");
        assert_ne!(a, b, "per-hash salt must make two hashes of one password differ");
        assert!(verify_password(&a, FIXTURE_PW_SAME));
        assert!(verify_password(&b, FIXTURE_PW_SAME));
    }
}
