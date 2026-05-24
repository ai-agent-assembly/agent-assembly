//! Gateway-side **Secret Injection** capability — placeholder registry that
//! substitutes `${NAME}` tokens with real credential values at tool-dispatch
//! time so the resolved value is never present in any LLM-bound request body
//! or audit-log entry.
//!
//! See `aa-gateway/src/secrets/README.md` (AAASM-1929) for the threat model
//! and the placeholder-vs-resolved audit contract.
//!
//! ## Distinction from Secret Detection
//!
//! Secret *Detection* (AAASM-1521 / 1549, already shipped) is a reactive
//! guard against agents *accidentally* leaking real credentials. Secret
//! *Injection* (this module, AAASM-1920) is a proactive feature: agents
//! reference credentials *by name* and the gateway substitutes the real
//! value at dispatch time. The two capabilities are complementary, not
//! alternatives.

pub mod error;
pub mod resolver;
pub mod store;
pub mod types;

pub use error::SecretsError;
pub use store::{InMemorySecretsStore, SecretsStore};
pub use types::Secret;
