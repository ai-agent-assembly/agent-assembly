//! Load-time eBPF bytecode integrity verification (AAASM-3602).
//!
//! Each embedded probe object carries a sha256 digest baked in at build time
//! (`build.rs` emits `cargo:rustc-env=AA_*_BPF_SHA256=…`, sourced from the
//! signed `EBPF_SHA256SUMS` produced by CI in AAASM-3601). Before any bytes are
//! handed to `aya::Ebpf::load`, [`verify_bytecode`] recomputes the digest over
//! the embedded bytes and refuses to proceed on a mismatch.
//!
//! This is the last line of defense against the swapped-`.o` supply-chain
//! attack: even if a tampered object is somehow embedded, the binary will not
//! load a probe whose digest does not match what CI signed. The check is
//! **fail-closed** — a mismatch (or an empty / unverifiable stub) returns
//! [`EbpfError::IntegrityMismatch`], never a silent degrade-to-allow.

use sha2::{Digest, Sha256};

use crate::error::EbpfError;

/// Expected sha256 (hex) of the file-I/O probe object, baked in by `build.rs`.
pub const AA_FILE_IO_BPF_SHA256: &str = env!("AA_FILE_IO_BPF_SHA256");
/// Expected sha256 (hex) of the exec-tracepoint probe object.
pub const AA_EXEC_BPF_SHA256: &str = env!("AA_EXEC_BPF_SHA256");
/// Expected sha256 (hex) of the TLS uprobe probe object.
pub const AA_TLS_BPF_SHA256: &str = env!("AA_TLS_BPF_SHA256");

/// Verify `bytes` hashes to `expected_hex`, returning
/// [`EbpfError::IntegrityMismatch`] on any divergence.
///
/// `object` names the probe for diagnostics. An empty `expected_hex` (the
/// placeholder emitted on non-Linux or when no digest was produced) is treated
/// as **unverifiable** and rejected — we never load bytecode we cannot pin.
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
    use super::*;
    #[test]
    fn matching_digest_passes() {
        let bytes = b"hello bpf";
        let expected = hex::encode(Sha256::digest(bytes));
        assert!(verify_bytecode("aa-test", bytes, &expected).is_ok());
    }

}
