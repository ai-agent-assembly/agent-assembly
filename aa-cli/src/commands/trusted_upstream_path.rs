//! Resolves the ADR 0036 trusted-config artifact path
//! (`${AASM_STATE_DIR:-~/.aasm}/integrations/trusted-upstream-proxy.json`).
//!
//! Split out of `commands::integrations::trusted_upstream` (AAASM-5923) because
//! that module is inside the `strip-for-publish:begin/end devtool` region in
//! `commands/mod.rs` and is removed entirely from the published `aasm`
//! binary (AAASM-2340), while `ProxyGuard::build_command`
//! (`commands/proxy/guard.rs`) and `aasm proxy start`'s `proxy_child_env`
//! (`commands/proxy/start.rs`) are real spawn boundaries that ship in every
//! build and must resolve this path regardless of whether `aasm integrations
//! install` is present to have written it. This module carries no `install`
//! logic, only the shared path convention, so it is safe to leave unstripped.

use std::path::PathBuf;

/// `${AASM_STATE_DIR:-~/.aasm}/integrations/trusted-upstream-proxy.json` —
/// mirrors `aa-proxy::config`'s own `integration_state_dir()` resolution
/// exactly (same env var, same default, same `integrations` subdirectory)
/// so both sides of this artifact agree on where it lives without either
/// hardcoding the other's path.
pub fn trusted_upstream_config_path() -> Option<PathBuf> {
    let base = match std::env::var_os("AASM_STATE_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => dirs::home_dir()?.join(".aasm"),
    };
    Some(base.join("integrations").join("trusted-upstream-proxy.json"))
}
