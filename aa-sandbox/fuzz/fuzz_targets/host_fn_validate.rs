//! Fuzz the host-function input-sanitization helpers (AAASM-3622).
//!
//! Drives [`aa_sandbox::host_fn::validate_guest_ptr_len`] and
//! [`aa_sandbox::host_fn::read_guest_bytes`] with adversarial
//! `(ptr, len, max_len)` triples against an arbitrary guest-memory buffer and
//! asserts the security invariant the AC depends on: validation NEVER panics
//! and NEVER yields a slice outside the guest memory bounds. A crash here is a
//! sandbox-escape / memory-safety finding.
//!
//! Run (nightly): `cargo +nightly fuzz run host_fn_validate -- -runs=100000`.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use aa_sandbox::host_fn::{read_guest_bytes, validate_guest_ptr_len};

#[derive(Debug, Arbitrary)]
struct Input {
    /// Arbitrary guest linear-memory contents.
    memory: Vec<u8>,
    /// Guest-supplied pointer.
    ptr: u64,
    /// Guest-supplied length.
    len: u64,
    /// Per-call maximum read length cap.
    max_len: u64,
}

fuzz_target!(|input: Input| {
    let mem_len = input.memory.len();

    // The validator must be total: it returns a result for every input and
    // never panics, overflows, or indexes out of range.
    if let Ok((start, end)) = validate_guest_ptr_len(mem_len, input.ptr, input.len, input.max_len) {
        // Any accepted range must stay strictly within guest memory.
        assert!(start <= end, "validated range inverted: {start} > {end}");
        assert!(end <= mem_len, "validated end {end} exceeds memory len {mem_len}");
    }

    // read_guest_bytes routes through the validator; on success the returned
    // slice must borrow strictly within `memory` and match the requested len.
    if let Ok(bytes) = read_guest_bytes(&input.memory, input.ptr, input.len, input.max_len) {
        assert_eq!(bytes.len() as u64, input.len, "read slice length mismatch");
        // The slice must equal the corresponding guest-memory window — proving
        // it never aliased host memory.
        let start = input.ptr as usize;
        assert_eq!(bytes, &input.memory[start..start + bytes.len()]);
    }
});
