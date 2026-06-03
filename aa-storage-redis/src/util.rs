//! Internal helpers shared across the Redis store implementations.

use core::fmt::Write as _;

/// Lower-case hex-encode a 16-byte id for use as part of a Redis key.
pub(crate) fn hex16(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in bytes {
        // Writing to a `String` is infallible.
        let _ = write!(out, "{byte:02x}");
    }
    out
}
