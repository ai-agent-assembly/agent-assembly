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

/// Outcome of a successful [`resolve_placeholders`] call.
///
/// `resolved` is the post-substitution JSON value the caller should forward
/// to the tool sink. `names_substituted` is the list of placeholder *names*
/// that were replaced — names only, never the resolved credential values.
///
/// Callers emit an audit entry from the *pre*-resolution args and forward
/// the *post*-resolution args downstream; this struct keeps the two views
/// disambiguated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstitutionResult {
    /// The resolved JSON value, with every matched `${NAME}` token replaced
    /// by its registered credential value.
    pub resolved: serde_json::Value,
    /// The placeholder names that were resolved, in encounter order.
    /// Names appear once per occurrence — a string with two references to
    /// `${DB_PASSWORD}` produces two entries.
    pub names_substituted: Vec<String>,
}

use std::sync::OnceLock;

use regex::Regex;

/// Lazy-compiled regex for the `${NAME}` token. `NAME` is uppercase +
/// digits + underscore and starts with a letter — matches the convention
/// pinned in the `e2e_secret_injection.rs` scaffold (`${DB_PASSWORD}`,
/// `${UNKNOWN_SECRET}`).
///
/// `OnceLock` (rather than `LazyLock`) keeps the workspace MSRV at 1.75.
fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$\{([A-Z][A-Z0-9_]*)\}").expect("placeholder regex is valid"))
}

use crate::secrets::{SecretInjectionError, SecretsStore};

/// Substitute every `${NAME}` token in a single string, appending each
/// resolved placeholder *name* to `names` so the caller can audit the
/// placeholder-form. Returns the substituted string, or
/// [`SecretInjectionError::UnknownPlaceholder`] if any token references an
/// unregistered name.
fn resolve_string(
    input: &str,
    store: &dyn SecretsStore,
    names: &mut Vec<String>,
) -> Result<String, SecretInjectionError> {
    let re = placeholder_re();
    let mut output = String::with_capacity(input.len());
    let mut last_end = 0;
    for cap in re.captures_iter(input) {
        let m = cap.get(0).expect("regex match");
        let name = cap.get(1).expect("regex captures name").as_str();
        let value = store
            .lookup(name)
            .ok_or_else(|| SecretInjectionError::UnknownPlaceholder { name: name.to_owned() })?;
        output.push_str(&input[last_end..m.start()]);
        output.push_str(&value);
        names.push(name.to_owned());
        last_end = m.end();
    }
    output.push_str(&input[last_end..]);
    Ok(output)
}

/// Walks `value`, substituting every `${NAME}` token in any string leaf
/// with its registered credential value from `store`.
///
/// Returns a [`SubstitutionResult`] carrying:
///
/// * `resolved` — the post-substitution JSON, ready to forward to the tool
///   sink.
/// * `names_substituted` — the placeholder *names* that were resolved (in
///   walk order). The caller emits an audit entry from the *pre*-resolution
///   args so the placeholder-form is what hits disk.
///
/// Returns [`SecretInjectionError::UnknownPlaceholder`] on the first
/// unregistered token encountered; the resolver never silently passes a
/// literal `${UNKNOWN}` through to the tool sink.
pub fn resolve_placeholders(
    value: &serde_json::Value,
    store: &dyn SecretsStore,
) -> Result<SubstitutionResult, SecretInjectionError> {
    let mut names = Vec::new();
    let resolved = walk(value, store, &mut names)?;
    Ok(SubstitutionResult {
        resolved,
        names_substituted: names,
    })
}

fn walk(
    value: &serde_json::Value,
    store: &dyn SecretsStore,
    names: &mut Vec<String>,
) -> Result<serde_json::Value, SecretInjectionError> {
    match value {
        serde_json::Value::String(s) => Ok(serde_json::Value::String(resolve_string(s, store, names)?)),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(walk(item, store, names)?);
            }
            Ok(serde_json::Value::Array(out))
        }
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), walk(v, store, names)?);
            }
            Ok(serde_json::Value::Object(out))
        }
        // Numbers, booleans, null: passed through unchanged.
        other => Ok(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{InMemorySecretsStore, Secret};
    use serde_json::json;

    fn store_with(entries: &[(&str, &str)]) -> InMemorySecretsStore {
        let store = InMemorySecretsStore::new();
        for (name, value) in entries {
            store
                .register(Secret {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                })
                .expect("register synthetic test secret");
        }
        store
    }

    #[test]
    fn flat_string_whole_placeholder_substitutes_full_value() {
        let store = store_with(&[("DB_PASSWORD", "real-secret-abc")]);
        let result = resolve_placeholders(&json!("${DB_PASSWORD}"), &store).unwrap();
        assert_eq!(result.resolved, json!("real-secret-abc"));
        assert_eq!(result.names_substituted, vec!["DB_PASSWORD"]);
    }

    #[test]
    fn embedded_placeholder_substitutes_in_place() {
        let store = store_with(&[("DB_PASSWORD", "real-secret-abc")]);
        let result = resolve_placeholders(&json!("postgres://app:${DB_PASSWORD}@db:5432/prod"), &store).unwrap();
        assert_eq!(result.resolved, json!("postgres://app:real-secret-abc@db:5432/prod"));
        assert_eq!(result.names_substituted, vec!["DB_PASSWORD"]);
    }

    #[test]
    fn nested_object_recurses_into_leaves() {
        let store = store_with(&[("DB_PASSWORD", "real-secret-abc")]);
        let input = json!({
            "connection": {
                "user": "app",
                "password": "${DB_PASSWORD}"
            }
        });
        let result = resolve_placeholders(&input, &store).unwrap();
        assert_eq!(result.resolved["connection"]["password"], json!("real-secret-abc"));
        assert_eq!(result.resolved["connection"]["user"], json!("app"));
        assert_eq!(result.names_substituted, vec!["DB_PASSWORD"]);
    }

    #[test]
    fn nested_array_recurses_into_leaves() {
        let store = store_with(&[("API_TOKEN", "real-token-1")]);
        let input = json!(["GET", "/v1/users", "Authorization: Bearer ${API_TOKEN}"]);
        let result = resolve_placeholders(&input, &store).unwrap();
        assert_eq!(
            result.resolved,
            json!(["GET", "/v1/users", "Authorization: Bearer real-token-1"])
        );
        assert_eq!(result.names_substituted, vec!["API_TOKEN"]);
    }

    #[test]
    fn multiple_placeholders_in_one_string_substitute_in_walk_order() {
        let store = store_with(&[("USER", "alice"), ("PASS", "secret-123")]);
        let result = resolve_placeholders(&json!("user=${USER}&pass=${PASS}&user=${USER}"), &store).unwrap();
        assert_eq!(result.resolved, json!("user=alice&pass=secret-123&user=alice"));
        // Each occurrence appears in walk order — caller can audit reference count.
        assert_eq!(result.names_substituted, vec!["USER", "PASS", "USER"]);
    }

    #[test]
    fn no_placeholder_passes_through_unchanged() {
        let store = store_with(&[("DB_PASSWORD", "real-secret-abc")]);
        let input = json!({"tool": "noop", "args": [1, 2, true, null, "plain-string"]});
        let result = resolve_placeholders(&input, &store).unwrap();
        assert_eq!(result.resolved, input);
        assert!(result.names_substituted.is_empty());
    }

    #[test]
    fn unknown_placeholder_returns_unknown_placeholder_error() {
        let store = store_with(&[("DB_PASSWORD", "real-secret-abc")]);
        let err = resolve_placeholders(&json!({"connection_string": "${UNKNOWN_SECRET}"}), &store)
            .expect_err("unknown placeholder must surface");
        assert_eq!(
            err,
            SecretInjectionError::UnknownPlaceholder {
                name: "UNKNOWN_SECRET".to_owned()
            }
        );
    }
}
