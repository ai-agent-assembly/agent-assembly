//! Shipped entrypoint that serves the full `/api/v1/*` REST surface from a
//! single-process, locally-backed `AppState` (AAASM-3360, hardened by
//! AAASM-3369).
//!
//! Usage:
//! ```text
//! cargo run -p aa-api --bin aa-api-server          # binds 127.0.0.1:7700, API-key auth
//! AA_API_ADDR=127.0.0.1:8080 \
//!   cargo run -p aa-api --bin aa-api-server         # custom bind address
//! AASM_API_KEY=aa_… cargo run -p aa-api --bin aa-api-server   # use a fixed key
//! AASM_API_AUTH=off cargo run -p aa-api --bin aa-api-server   # disable auth (dev only)
//! ```
//!
//! Auth posture (AAASM-3369):
//! * By default the protected `/api/v1/*` surface requires
//!   `Authorization: Bearer aa_…`. A key is read from `AASM_API_KEY`, or a
//!   random admin key is generated and printed on startup.
//! * `AASM_API_AUTH=off` disables auth entirely (every request is admin) — for
//!   throwaway local development only.
//! * `/api/v1/health` is always reachable without a key; the top-level
//!   `/healthz` liveness probe is served alongside the dashboard SPA when a
//!   `dashboard/dist/` is resolved.
//!
//! Audit and retention are backed by a per-process local SQLite store, so
//! `/api/v1/audit/*`, `/api/v1/logs/*`, and `/api/v1/admin/retention*` return
//! real data instead of 503.

use std::net::SocketAddr;

use aa_api::LocalAuth;

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

    let (auth, generated) = LocalAuth::from_env();

    // AAASM-4572: validate the API key's format BEFORE printing the "serving"
    // banner. `LocalAuth::from_env` only checks `AASM_API_KEY` is non-empty; the
    // authoritative format check (`aa_… + 32 hex`) lives inside `serve_local`'s
    // `local_hardened_at`, which runs *after* the banner below. Without this
    // early gate a malformed key made the process announce "serving full REST
    // surface on …" and then exit 1 without ever binding the port — a
    // false-positive readiness signal for any script/monitor scraping the log.
    // `local_hardened_at` re-validates as the source of truth; this only gates
    // banner ordering so announce and abort stay mutually exclusive.
    if let LocalAuth::ApiKey { key } = &auth {
        if let Err(e) = aa_api::auth::api_key::ApiKey::parse(key) {
            return Err(format!("invalid AASM_API_KEY: {e}").into());
        }
    }

    match &auth {
        LocalAuth::Off => {
            eprintln!(
                "aa-api serving full /api/v1/* REST surface on http://{addr} \
                 (AUTH DISABLED via AASM_API_AUTH=off — do not expose this)"
            );
        }
        LocalAuth::ApiKey { key } => {
            if generated {
                // AAASM-4744: print only a short prefix of the generated key, not
                // the full secret. Dumping a live admin credential to stderr/logs
                // is a disclosure gap; the prefix lets an operator correlate the
                // key in the banner below without leaking it. Set AASM_API_KEY to
                // run with a known, reusable key.
                eprintln!(
                    "aa-api: generated a random admin API key {prefix}… (set AASM_API_KEY to use a known key)",
                    prefix = &key[..key.len().min(6)]
                );
            } else {
                eprintln!("aa-api: using admin API key from AASM_API_KEY");
            }
            eprintln!(
                "aa-api serving full /api/v1/* REST surface on http://{addr} \
                 (API-key auth; send `Authorization: Bearer {prefix}…`)",
                prefix = &key[..key.len().min(6)]
            );
        }
    }

    aa_api::serve_local(addr, auth).await
}
