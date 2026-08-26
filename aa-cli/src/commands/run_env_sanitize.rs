//! Shared ambient proxy-routing variable names for the D6 env-sanitization
//! invariant (ADR 0036 D6/R1/R2/R7): "immediately before spawn, remove
//! ambient proxy-routing variables, then conditionally re-inject a
//! supervisor-owned trusted value last."
//!
//! Split into two constants because the two groups are not symmetric under
//! injection: `ALL_PROXY`/`NO_PROXY` (and their lowercase forms) are never a
//! legitimate injection target — `NO_PROXY` is a negative/exclusion list, not
//! a routing target, and `ALL_PROXY` is a distinct routing key from
//! `HTTPS_PROXY`/`HTTP_PROXY` — so they are always stripped outright and
//! never reinjected, while the routing group's uppercase forms are the only
//! names step 3 of the invariant is ever allowed to set.

/// `ALL_PROXY`/`NO_PROXY` and their lowercase forms — always removed
/// unconditionally (when the boundary's own `--no-proxy`-equivalent carve-out
/// does not apply), never reinjected.
pub const PROXY_EXCLUSION_VARS: [&str; 4] = ["ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"];

/// `HTTPS_PROXY`/`HTTP_PROXY` and their lowercase forms — removed, then
/// (uppercase only) the sole names step 3 may reinject.
pub const PROXY_ROUTING_VARS: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];

/// All 8 variants, for a boundary (like `ProxyGuard::build_command` or
/// `aasm proxy start`) that never injects a trusted value, so removal is the
/// whole rule.
pub const PROXY_EXCLUSION_AND_ROUTING_VARS: [&str; 8] = [
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];
