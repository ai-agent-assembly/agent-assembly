//! Shipped entrypoint that serves the full `/api/v1/*` REST surface from a
//! single in-memory process (AAASM-3360).
//!
//! Usage:
//! ```text
//! cargo run -p aa-api --bin aa-api-server          # binds 127.0.0.1:7700
//! AA_API_ADDR=127.0.0.1:8080 \
//!   cargo run -p aa-api --bin aa-api-server         # custom bind address
//! ```
//!
//! Every route registered by `aa_api::routes::v1_router()` is served. Auth is
//! disabled in this mode, so protected routes (e.g. `/api/v1/agents`,
//! `/api/v1/policies`) are reachable without a bearer credential. See
//! `aa_api::AppState::local_in_memory` for the documented limitations of the
//! in-memory wiring.

use std::net::SocketAddr;

/// Default bind address when `AA_API_ADDR` is unset.
const DEFAULT_ADDR: &str = "127.0.0.1:7700";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let raw = std::env::var("AA_API_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let addr: SocketAddr = raw.parse().unwrap_or_else(|e| {
        eprintln!("invalid AA_API_ADDR={raw:?} ({e}); falling back to {DEFAULT_ADDR}");
        DEFAULT_ADDR.parse().expect("default address is valid")
    });

    eprintln!("aa-api serving full /api/v1/* REST surface (in-memory, auth disabled) on http://{addr}");
    aa_api::serve_local(addr).await
}
