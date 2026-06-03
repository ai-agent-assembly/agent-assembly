//! Mapping from Redis / connection-pool failures to [`aa_storage::StorageError`].

use aa_storage::StorageError;

/// Map any backend transport, pool, or protocol failure to
/// [`StorageError::Backend`].
pub(crate) fn backend<E: core::fmt::Display>(err: E) -> StorageError {
    StorageError::Backend(err.to_string())
}
