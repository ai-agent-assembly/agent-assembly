//! Placeholder resolver — walks a JSON value and substitutes `${NAME}`
//! tokens with their registered credential values from a [`SecretsStore`].
//!
//! The resolver is the only consumer of [`SecretsStore::lookup`] in the
//! request path. It returns a [`SubstitutionResult`] that records which
//! placeholder *names* were resolved so the caller can emit an audit
//! entry with the placeholder-form args while forwarding the resolved
//! form to the tool sink (AAASM-1920 audit-shape contract).
//!
//! Unregistered placeholders surface as
//! [`SecretInjectionError::UnknownPlaceholder`]. The resolver **never**
//! silently passes a literal `${UNKNOWN}` token through to the tool sink
//! — that would mask a typo into an arbitrary-string injection at
//! downstream parser layer.
