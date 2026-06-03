//! Encrypted credential reference — never plaintext on the wire.

use alloc::string::String;
use alloc::vec::Vec;

/// An encrypted credential reference.
///
/// The plaintext secret is **never** present: a `Credential` carries only the
/// resolver `placeholder` an agent uses in tool arguments, the opaque
/// `ciphertext`, and the `kek_ref` identifying the key-encryption-key needed to
/// decrypt it out-of-band. Encryption-at-rest itself is a separate workstream.
///
/// # Wire format
///
/// `ciphertext` serializes as a JSON array of byte values:
///
/// ```json
/// {
///   "placeholder": "${OPENAI_API_KEY}",
///   "ciphertext": [186, 220, 17, 42],
///   "kek_ref": "kms://prod/keys/api-secrets"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct Credential {
    /// Placeholder token the agent uses in tool args, e.g. `"${OPENAI_API_KEY}"`.
    pub placeholder: String,
    /// Opaque ciphertext of the secret. Never plaintext.
    pub ciphertext: Vec<u8>,
    /// Reference to the key-encryption-key used to seal `ciphertext`.
    pub kek_ref: String,
}
