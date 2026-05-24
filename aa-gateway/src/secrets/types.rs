//! Data types backing the Secret Injection module.

/// A registered secret mapping: the public **placeholder name** an agent
/// references (e.g. `DB_PASSWORD`) → the **real credential value** the
/// gateway substitutes in at tool-dispatch time.
///
/// The placeholder name is stored *without* the `${...}` syntactic wrapping
/// (i.e. `DB_PASSWORD`, not `${DB_PASSWORD}`); the resolver wraps and
/// unwraps it as needed when walking JSON.
///
/// Cloning a `Secret` clones the real value — callers that hold a `Secret`
/// outside the `SecretsStore` are responsible for keeping it out of any
/// LLM-bound request body or audit-log entry. See `aa-gateway/src/secrets/
/// README.md` (AAASM-1929) for the threat-model contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// The placeholder name, without `${...}` wrapping. Conventionally
    /// `SCREAMING_SNAKE_CASE`; validation is the resolver's responsibility,
    /// not the store's.
    pub name: String,
    /// The real credential value that will replace `${name}` tokens at
    /// dispatch time. Never logged, never serialised into audit entries.
    pub value: String,
}
