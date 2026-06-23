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

/// Validate that the guest-supplied `(ptr, len)` names a region fully inside a
/// guest linear memory of `mem_len` bytes and within the per-call `max_len`
/// cap, returning the validated `[start, end)` byte range on success.
///
/// This is the single bounds-check every host-function import must run before
/// touching guest memory. It is total and panic-free for *all* inputs:
///
/// 1. `len > max_len` → [`HostFnError::LengthTooLarge`] (caps a single read).
/// 2. `ptr + len` overflowing `u64` → [`HostFnError::LengthOverflow`] (a
///    wraparound that would otherwise alias low memory).
/// 3. `ptr + len > mem_len` → [`HostFnError::OutOfBounds`] (the region runs
///    past the end of guest memory).
///
/// On success the returned `(start, end)` satisfies `start <= end <= mem_len`,
/// so slicing `&memory[start..end]` can never panic or read host memory. A
/// zero-length read at any in-range (or at the one-past-the-end) `ptr` is
/// permitted and yields an empty range.
pub fn validate_guest_ptr_len(mem_len: usize, ptr: u64, len: u64, max_len: u64) -> Result<(usize, usize), HostFnError> {
    if len > max_len {
        return Err(HostFnError::LengthTooLarge);
    }
    // Checked add on u64 catches the ptr + len wraparound primitive.
    let end = ptr.checked_add(len).ok_or(HostFnError::LengthOverflow)?;
    // Compare in u64 space before narrowing to usize so a 64-bit ptr/len on a
    // 32-bit usize host can never silently truncate into range.
    if end > mem_len as u64 {
        return Err(HostFnError::OutOfBounds);
    }
    // Both fit: end <= mem_len <= usize::MAX, and ptr <= end.
    Ok((ptr as usize, end as usize))
}

/// Read `len` guest bytes at `ptr` from a guest linear-memory byte slice,
/// validating the region first via [`validate_guest_ptr_len`].
///
/// `memory` is the raw `wasmtime::Memory` data view. On success the returned
/// slice borrows strictly within `memory` and is exactly `len` bytes; on any
/// validation failure a typed [`HostFnError`] is returned and `memory` is
/// never indexed out of range. This is the single sanctioned guest-memory read
/// path for host-function imports.
pub fn read_guest_bytes(memory: &[u8], ptr: u64, len: u64, max_len: u64) -> Result<&[u8], HostFnError> {
    let (start, end) = validate_guest_ptr_len(memory.len(), ptr, len, max_len)?;
    // start <= end <= memory.len() guaranteed by the validator, so this slice
    // is always in bounds.
    Ok(&memory[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: u64 = 4096;

    #[test]
    fn in_range_read_succeeds() {
        let mem = b"hello, sandbox";
        let got = read_guest_bytes(mem, 7, 7, MAX).expect("in-range read must succeed");
        assert_eq!(got, b"sandbox");
    }

    #[test]
    fn out_of_range_ptr_is_rejected() {
        let mem = [0u8; 16];
        // ptr past the end of memory.
        assert_eq!(read_guest_bytes(&mem, 17, 1, MAX), Err(HostFnError::OutOfBounds));
        // ptr in range but ptr + len runs past the end.
        assert_eq!(read_guest_bytes(&mem, 10, 10, MAX), Err(HostFnError::OutOfBounds));
    }

    #[test]
    fn ptr_plus_len_overflow_is_rejected() {
        let mem = [0u8; 16];
        // ptr + len wraps u64; must be caught as overflow, never aliased low.
        let res = validate_guest_ptr_len(mem.len(), u64::MAX, 5, u64::MAX);
        assert_eq!(res, Err(HostFnError::LengthOverflow));
    }

    #[test]
    fn oversized_len_is_rejected_before_bounds() {
        let mem = [0u8; 16];
        // len exceeds the per-call cap — rejected as too-large even though it
        // would also be out of bounds.
        assert_eq!(read_guest_bytes(&mem, 0, MAX + 1, MAX), Err(HostFnError::LengthTooLarge));
    }

    #[test]
    fn zero_length_read_is_allowed_in_range() {
        let mem = [1u8; 8];
        assert_eq!(read_guest_bytes(&mem, 4, 0, MAX), Ok(&[][..]));
        // Zero-length read at exactly one-past-the-end is also valid.
        assert_eq!(read_guest_bytes(&mem, 8, 0, MAX), Ok(&[][..]));
    }

    #[test]
    fn full_memory_read_succeeds() {
        let mem = [9u8; 32];
        let got = read_guest_bytes(&mem, 0, 32, MAX).expect("full read must succeed");
        assert_eq!(got.len(), 32);
    }

    #[test]
    fn validated_range_never_exceeds_memory() {
        // Property-style spot check: any accepted range stays within memory.
        let mem_len = 64usize;
        for ptr in 0..70u64 {
            for len in 0..70u64 {
                if let Ok((start, end)) = validate_guest_ptr_len(mem_len, ptr, len, MAX) {
                    assert!(start <= end);
                    assert!(end <= mem_len);
                }
            }
        }
    }

    #[test]
    fn errno_mapping_is_deterministic() {
        assert_eq!(HostFnError::OutOfBounds.errno(), 21);
        assert_eq!(HostFnError::LengthOverflow.errno(), 21);
        assert_eq!(HostFnError::LengthTooLarge.errno(), 28);
    }
}
