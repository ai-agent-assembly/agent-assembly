//! Error types for the aa-ebpf userspace loader.

use thiserror::Error;

/// Errors that can occur while loading, attaching, or reading eBPF programs.
#[derive(Debug, Error)]
pub enum EbpfError {
    // ── aya-native variants (Linux only, used by uprobe/ringbuf) ────────
    /// Failed to load the eBPF program ELF object.
    #[cfg(target_os = "linux")]
    #[error("failed to load eBPF object: {0}")]
    Load(#[from] aya::EbpfError),
    /// An eBPF map operation failed (e.g. writing to a PID filter map).
    #[cfg(target_os = "linux")]
    #[error("eBPF map operation failed: {0}")]
    Map(#[from] aya::maps::MapError),
    /// An eBPF program operation failed (e.g. load or attach).
    #[cfg(target_os = "linux")]
    #[error("eBPF program operation failed: {0}")]
    Program(#[from] aya::programs::ProgramError),

    /// Failed to attach an uprobe or kprobe to a target symbol.
    #[error("failed to attach probe to `{symbol}`: {source}")]
    Attach {
        /// Name of the target symbol (e.g. `SSL_write`).
        symbol: String,
        /// Underlying error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// The ring buffer returned an unexpected event size.
    #[error("ring buffer event size mismatch: expected {expected}, got {got}")]
    EventSize {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length received.
        got: usize,
    },

    /// A required eBPF map was not found in the loaded object.
    #[error("eBPF map `{name}` not found in object")]
    MapNotFound {
        /// Name of the missing map.
        name: String,
    },

    /// A required eBPF program was not found in the loaded object.
    #[error("eBPF program `{name}` not found in object")]
    ProgramNotFound {
        /// Name of the missing program.
        name: String,
    },

    /// Insufficient permissions to load or attach eBPF programs.
    #[error("permission denied: {detail}")]
    PermissionDenied {
        /// Human-readable description of the required capability.
        detail: String,
    },

    /// The embedded BPF bytecode did not match the digest baked in at build
    /// time (AAASM-3602). This is a hard, fail-closed error: a probe whose
    /// embedded bytecode has been corrupted in-binary — or is an empty stub —
    /// is refused, never loaded blindly. Note this detects post-build
    /// corruption only; the baked digest is derived from the same embedded
    /// object, so it is not a supply-chain guarantee against a tampered build
    /// (see the `integrity` module docs / TODO(AAASM-3601)).
    #[error("eBPF bytecode integrity check failed for `{object}`: expected sha256 {expected}, got {actual}")]
    IntegrityMismatch {
        /// The probe object whose digest mismatched.
        object: String,
        /// The pinned digest baked in at build time.
        expected: String,
        /// The digest actually computed over the embedded bytes.
        actual: String,
    },

    /// OpenSSL shared library could not be located for the target process.
    #[error("could not find OpenSSL library for pid {pid:?}")]
    OpenSslNotFound {
        /// Target PID, or `None` for system-wide search.
        pid: Option<i32>,
    },

    /// An I/O error occurred during async ring-buffer polling or /proc parsing.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // ── string-based variants (used by file I/O loader, cross-platform) ─
    /// Failed to load the compiled eBPF bytecode into the kernel.
    #[error("eBPF program load failed: {0}")]
    ProgramLoad(String),

    /// Failed to attach a kprobe to the target syscall.
    #[error("kprobe attach failed: {0}")]
    ProbeAttach(String),

    /// Failed to update a BPF map from userspace.
    #[error("BPF map update failed: {0}")]
    MapUpdate(String),

    /// Failed to parse an event received from the BPF perf event array.
    #[error("event parse failed: {0}")]
    EventParse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_program_load() {
        let err = EbpfError::ProgramLoad("missing privileges".into());
        assert_eq!(err.to_string(), "eBPF program load failed: missing privileges");
    }

    #[test]
    fn display_probe_attach() {
        let err = EbpfError::ProbeAttach("sys_openat not found".into());
        assert_eq!(err.to_string(), "kprobe attach failed: sys_openat not found");
    }

    #[test]
    fn display_map_update() {
        let err = EbpfError::MapUpdate("map full".into());
        assert_eq!(err.to_string(), "BPF map update failed: map full");
    }

    #[test]
    fn display_event_parse() {
        let err = EbpfError::EventParse("truncated buffer".into());
        assert_eq!(err.to_string(), "event parse failed: truncated buffer");
    }

    #[test]
    fn display_map_not_found() {
        let err = EbpfError::MapNotFound {
            name: "PID_FILTER".into(),
        };
        assert_eq!(err.to_string(), "eBPF map `PID_FILTER` not found in object");
    }

    #[test]
    fn display_program_not_found() {
        let err = EbpfError::ProgramNotFound {
            name: "ssl_write".into(),
        };
        assert_eq!(err.to_string(), "eBPF program `ssl_write` not found in object");
    }

    #[test]
    fn display_permission_denied() {
        let err = EbpfError::PermissionDenied {
            detail: "requires CAP_BPF".into(),
        };
        assert_eq!(err.to_string(), "permission denied: requires CAP_BPF");
    }

    #[test]
    fn display_openssl_not_found() {
        let err = EbpfError::OpenSslNotFound { pid: Some(1234) };
        assert_eq!(err.to_string(), "could not find OpenSSL library for pid Some(1234)");
    }

    #[test]
    fn implements_std_error() {
        let err = EbpfError::ProgramLoad("test".into());
        let _: &dyn std::error::Error = &err;
    }
}
