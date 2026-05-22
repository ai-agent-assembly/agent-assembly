//! Remote Control-Plane mode runtime for `aa-gateway`.
//!
//! Bootstrap function and pre-flight checks invoked when `AA_MODE=remote`.
//! See AAASM-1577 (E17 S-C) for the design rationale: the gateway starts
//! as a multi-machine server binding `0.0.0.0:PORT` over plain HTTP or
//! optional TLS, exposes `/healthz`, and drains on SIGTERM.
//!
//! Submodules:
//!
//! - [`tls`] — pre-flight cert / key validation (AAASM-1702 / ST-2)
//! - `server` — listener bootstrap (AAASM-1709 / ST-3, lands next)

pub mod tls;
