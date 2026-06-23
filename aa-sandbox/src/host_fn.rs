//! Host-function input sanitization — the single sanctioned path for a
//! host-function import to read guest linear memory.
//!
//! Host functions are the classic sandbox-escape conduit: a weakly-validated
//! `(ptr, len)` pair handed to a custom import is the path-traversal /
//! memory-safety primitive an attacker fuzzes until it touches host memory.
//! Today [`crate::runtime::SandboxRuntime::new`] only wires WASI (no custom
//! `Linker::func_wrap` imports), but the moment one is added — or WASI args
//! are surfaced — every guest-memory read MUST route through
//! [`validate_guest_ptr_len`] / [`read_guest_bytes`] so the bounds check is
//! centralized and cannot drift per import.
//!
//! The helpers operate on a raw guest-memory byte slice (`&[u8]`, the
//! `wasmtime::Memory` data view) plus the guest-supplied `(ptr, len)` and
//! never panic, never index out of bounds, and never read host memory: an
//! out-of-range pointer, an oversized length, or a `ptr + len` wraparound all
//! return a typed [`HostFnError`] mapped to a deterministic guest-visible
//! errno. This is the property the AAASM-3622 fuzz target exercises.

/// Failure modes a validated host-function import surfaces instead of trapping
/// or reading host memory.
///
/// Each variant maps to a deterministic guest-visible errno via
/// [`HostFnError::errno`] so a guest sees a stable error rather than
/// undefined behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFnError {
    /// `ptr` (or `ptr + len`) lies outside the guest's linear memory. The
    /// classic out-of-bounds read an attacker fuzzes for. Maps to `EFAULT`.
    OutOfBounds,
    /// `ptr + len` overflowed `u64` (a wraparound that would otherwise alias
    /// low memory). Maps to `EFAULT`.
    LengthOverflow,
    /// `len` exceeds the per-call maximum read length derived from the sandbox
    /// limits. Maps to `EINVAL`. Caps how much a single host-fn read can move
    /// so a fuzzed import cannot request an enormous copy.
    LengthTooLarge,
}

impl HostFnError {
    /// The deterministic guest-visible errno for this failure.
    ///
    /// Uses WASI preview-1 errno numbering so the value is meaningful to a
    /// WASI guest: `EFAULT` (21) for bad-address failures, `EINVAL` (28) for
    /// the oversized-length failure.
    pub fn errno(self) -> u32 {
        match self {
            HostFnError::OutOfBounds | HostFnError::LengthOverflow => 21, // WASI EFAULT
            HostFnError::LengthTooLarge => 28,                            // WASI EINVAL
        }
    }
}

impl std::fmt::Display for HostFnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostFnError::OutOfBounds => f.write_str("host-fn guest pointer out of bounds"),
            HostFnError::LengthOverflow => f.write_str("host-fn guest (ptr + len) overflowed"),
            HostFnError::LengthTooLarge => f.write_str("host-fn guest read length exceeds maximum"),
        }
    }
}

impl std::error::Error for HostFnError {}
