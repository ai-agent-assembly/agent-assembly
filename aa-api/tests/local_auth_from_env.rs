//! Unit-level coverage for `LocalAuth::from_env` (AAASM-3805).
//!
//! Each test runs in its own nextest process, so mutating process-wide
//! environment variables here does not race with other tests.

use aa_api::LocalAuth;

#[test]
fn from_env_returns_off_when_auth_disabled() {
    std::env::set_var("AASM_API_AUTH", "off");
    std::env::remove_var("AASM_API_KEY");

    let (auth, generated) = LocalAuth::from_env();
    assert!(matches!(auth, LocalAuth::Off));
    assert!(!generated, "explicit off must not report a generated key");
}

#[test]
fn from_env_uses_supplied_api_key() {
    std::env::remove_var("AASM_API_AUTH");
    std::env::set_var("AASM_API_KEY", "aa_supplied_key_value");

    let (auth, generated) = LocalAuth::from_env();
    match auth {
        LocalAuth::ApiKey { key } => assert_eq!(key, "aa_supplied_key_value"),
        LocalAuth::Off => panic!("expected ApiKey, got Off"),
    }
    assert!(!generated, "a supplied key must not be reported as generated");
}

#[test]
fn from_env_generates_key_when_unset() {
    std::env::remove_var("AASM_API_AUTH");
    std::env::remove_var("AASM_API_KEY");

    let (auth, generated) = LocalAuth::from_env();
    match auth {
        LocalAuth::ApiKey { key } => assert!(!key.is_empty(), "generated key must be non-empty"),
        LocalAuth::Off => panic!("expected a generated ApiKey, got Off"),
    }
    assert!(generated, "an unset key must be reported as generated");
}

#[test]
fn from_env_generates_key_when_supplied_key_is_empty() {
    std::env::remove_var("AASM_API_AUTH");
    std::env::set_var("AASM_API_KEY", "");

    let (auth, generated) = LocalAuth::from_env();
    assert!(matches!(auth, LocalAuth::ApiKey { .. }));
    assert!(generated, "an empty supplied key falls through to generation");
}
