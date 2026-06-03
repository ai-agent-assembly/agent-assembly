//! Timestamp abstraction compatible with `no_std` environments.
//!
//! In `no_std` mode the caller is responsible for supplying the nanosecond
//! value. In `std` mode a [`From<SystemTime>`] convenience impl is available.

/// Nanoseconds since the Unix epoch.
///
/// In `no_std` environments use [`Timestamp::from_nanos`] to construct a value
/// directly. In `std` environments the [`From<std::time::SystemTime>`] impl
/// can be used as a convenience.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schemars", schemars(transparent))]
pub struct Timestamp(u64);

impl Timestamp {
    /// Construct a [`Timestamp`] from raw nanoseconds since the Unix epoch.
    #[inline]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Return the raw nanosecond value.
    #[inline]
    pub const fn as_nanos(&self) -> u64 {
        self.0
    }
}

#[cfg(feature = "std")]
impl From<std::time::SystemTime> for Timestamp {
    fn from(t: std::time::SystemTime) -> Self {
        let nanos = t
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_nanos() as u64;
        Self(nanos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_nanos() {
        let ts = Timestamp::from_nanos(1_000_000_000);
        assert_eq!(ts.as_nanos(), 1_000_000_000);
    }

    #[cfg(feature = "std")]
    #[test]
    fn from_system_time_at_epoch_is_zero() {
        let ts = Timestamp::from(std::time::SystemTime::UNIX_EPOCH);
        assert_eq!(ts.as_nanos(), 0);
    }
}
