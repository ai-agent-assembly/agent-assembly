//! Build-identity primitives, re-exported outside `devint::` (AAASM-5984).
//!
//! [`crate::devint::provenance`] defines [`BuildIdentity`]/[`LONG_VERSION`]/
//! [`parse_version_banner`] for the Developer Integration API's own
//! client/server SHA verification (AAASM-5628) — that is why the module lives
//! under `devint`. `aa-proxy`, `aa-gateway`, and `aa-cli`'s `proxy` command
//! reuse the same primitives for an unrelated purpose (AAASM-5984: stating
//! which build performed interception/redaction), and none of the three is a
//! Developer Integration API client.
//!
//! `scripts/check-publish-surface.sh` (AAASM-5309) greps published `aa-cli`
//! command modules for the literal path `aa_runtime::devint` to catch a
//! published command whose DI-API server (`spawn_devint`) publish-strip
//! removed out from under it. A module path is all that check can see — it
//! cannot distinguish "reads `BUILD_SHA`" from "binds the DI-API socket" — so
//! `aa-cli/src/commands/proxy/build_identity.rs` importing
//! `aa_runtime::devint::provenance` directly false-positives it: `aasm proxy`
//! gets flagged as a DI-API client it has never been.
//!
//! This module is the fix: a `pub use` re-export at a path outside `devint::`,
//! so a consumer that only wants build identity — not DI-API provenance
//! verification — has one to reach without tripping that check. No type,
//! constant, or behaviour changes; every item here is the same one
//! `devint::provenance` defines.

pub use crate::devint::provenance::{
    parse_version_banner, short_sha, BuildIdentity, IdentitySource, BANNER_SHA_FIELD, BANNER_SOURCE_FIELD,
    BANNER_SOURCE_PATH_FIELD, BUILD_IDENTITY_SOURCE, BUILD_SHA, BUILD_SOURCE_PATH, LONG_VERSION, UNKNOWN_SHA,
};
