//! Load-time eBPF bytecode integrity verification (AAASM-3602).
//!
//! Each embedded probe object carries a sha256 digest baked in at build time:
//! `build.rs` recomputes the digest over the compiled probe object it is about
//! to embed and emits it as `cargo:rustc-env=AA_*_BPF_SHA256=…`. Before any
//! bytes are handed to `aya::Ebpf::load`, [`verify_bytecode`] recomputes the
//! digest over the embedded bytes and refuses to proceed on a mismatch.
//!
//! ## What this check does — and does NOT — guarantee
//!
//! The baked-in expected digest is derived from the **same** object that is
//! embedded, so the comparison is self-referential. It is therefore **not** a
//! supply-chain guarantee and **not** "the last line of defense against the
//! swapped-`.o` attack": an attacker who tampers with the probe source or the
//! compiled `.o` before the build moves both the embedded bytes and the baked
//! digest together, and the check still passes.
//!
//! What it *does* catch is post-build, in-binary corruption of the embedded
//! bytecode region that leaves the baked digest string intact — e.g. bit-rot or
//! a partial in-place patch of the bytecode that does not also rewrite the
//! constant. It also rejects the empty / unverifiable stub emitted when the BPF
//! toolchain is absent. The check is **fail-closed**: a mismatch (or an empty
//! stub) returns [`EbpfError::IntegrityMismatch`], never a silent
//! degrade-to-allow.
//!
//! The cosign-signed `EBPF_SHA256SUMS` manifest produced at release time
//! (AAASM-3601) is an independent *download-time* verification artifact; it is
//! generated from these same objects and is not consumed by this build, so it
//! does not anchor the digest baked here.
//
// TODO(AAASM-3601): source the expected digest from an independently-signed
// SHA256SUMS (verified separately from the embedded artifact) so this becomes a
// real supply-chain guarantee rather than in-binary corruption detection.

use sha2::{Digest, Sha256};

use crate::error::EbpfError;

/// Expected sha256 (hex) of the file-I/O probe object, baked in by `build.rs`.
pub const AA_FILE_IO_BPF_SHA256: &str = env!("AA_FILE_IO_BPF_SHA256");
/// Expected sha256 (hex) of the exec-tracepoint probe object.
pub const AA_EXEC_BPF_SHA256: &str = env!("AA_EXEC_BPF_SHA256");
/// Expected sha256 (hex) of the TLS uprobe probe object.
pub const AA_TLS_BPF_SHA256: &str = env!("AA_TLS_BPF_SHA256");
/// Expected sha256 (hex) of the syscall-guard enforcement probe object.
pub const AA_SYSCALL_GUARD_BPF_SHA256: &str = env!("AA_SYSCALL_GUARD_BPF_SHA256");

/// Verify `bytes` hashes to `expected_hex`, returning
/// [`EbpfError::IntegrityMismatch`] on any divergence.
///
/// This detects post-build, in-binary corruption of the embedded bytecode (and
/// the empty / unverifiable stub); it is **not** a supply-chain guarantee — see
/// the module-level docs. `object` names the probe for diagnostics. An empty
/// `expected_hex` (the placeholder emitted on non-Linux or when no digest was
/// produced) is treated as **unverifiable** and rejected — we never load
/// bytecode we cannot pin.
pub fn verify_bytecode(object: &str, bytes: &[u8], expected_hex: &str) -> Result<(), EbpfError> {
    let actual = hex::encode(Sha256::digest(bytes));

    if expected_hex.is_empty() {
        return Err(EbpfError::IntegrityMismatch {
            object: object.to_string(),
            expected: "<unset: no signed digest baked in>".to_string(),
            actual,
        });
    }

    if !actual.eq_ignore_ascii_case(expected_hex) {
        return Err(EbpfError::IntegrityMismatch {
            object: object.to_string(),
            expected: expected_hex.to_string(),
            actual,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // These tests cover what `verify_bytecode` actually provides: detecting a
    // digest mismatch (post-build in-binary corruption) and rejecting the empty
    // / unverifiable stub. They do NOT — and cannot — assert a supply-chain
    // guarantee, since the baked digest is derived from the embedded object
    // itself (see module docs / TODO(AAASM-3601)).
    use super::*;

    #[test]
    fn matching_digest_passes() {
        let bytes = b"hello bpf";
        let expected = hex::encode(Sha256::digest(bytes));
        assert!(verify_bytecode("aa-test", bytes, &expected).is_ok());
    }

    #[test]
    fn corrupted_bytecode_is_rejected() {
        // Embedded bytes differ from what the baked digest was computed over
        // (the in-binary-corruption case this check guards against).
        let bytes = b"corrupted bytecode";
        // digest of the *original*, uncorrupted bytes
        let wrong = hex::encode(Sha256::digest(b"original bytecode"));
        let err = verify_bytecode("aa-test", bytes, &wrong).unwrap_err();
        match err {
            EbpfError::IntegrityMismatch {
                object,
                expected,
                actual,
            } => {
                assert_eq!(object, "aa-test");
                assert_eq!(expected, wrong);
                assert_ne!(actual, wrong);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn empty_expected_is_unverifiable_and_rejected() {
        let err = verify_bytecode("aa-test", b"anything", "").unwrap_err();
        assert!(matches!(err, EbpfError::IntegrityMismatch { .. }));
    }

    #[test]
    fn digest_comparison_is_case_insensitive() {
        let bytes = b"case test";
        let expected = hex::encode(Sha256::digest(bytes)).to_uppercase();
        assert!(verify_bytecode("aa-test", bytes, &expected).is_ok());
    }
}
