//! [`ConfigError`] — failures raised while resolving storage drivers from config.

/// Error returned when a `[storage]` configuration cannot be resolved against
/// the driver [`Registry`](crate::Registry).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A driver name in `[storage]` is not registered for its kind.
    ///
    /// `available` lists every driver name registered for `kind`, so the
    /// operator can see the valid choices in the error message.
    #[error("unknown {kind} driver {name:?}; available drivers: [{}]", available.join(", "))]
    UnknownDriver {
        /// The storage-kind key that named the driver (e.g. `"policy_store"`).
        kind: &'static str,
        /// The unrecognized driver name from the config.
        name: String,
        /// Driver names registered for this kind, in sorted order.
        available: Vec<String>,
    },

    /// A driver was named but its `[storage.<name>]` subsection is missing.
    #[error("driver {name:?} (selected for {kind}) has no [storage.{name}] subsection")]
    MissingDriverSection {
        /// The storage-kind key that named the driver.
        kind: &'static str,
        /// The driver name whose subsection is absent.
        name: String,
    },

    /// The driver's factory failed to build the backend from its subsection.
    #[error("failed to build {kind} driver {name:?}: {source}")]
    Build {
        /// The storage-kind key that named the driver.
        kind: &'static str,
        /// The driver name being built.
        name: String,
        /// The underlying backend error.
        #[source]
        source: crate::StorageError,
    },
}
