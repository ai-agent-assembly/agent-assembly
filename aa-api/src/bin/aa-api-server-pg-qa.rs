//! **QA-ONLY** entrypoint: the shipped `aa-api-server` wiring plus a real
//! Postgres-backed native-account store, so the ADR-0031 password auth path
//! (register / login / lockout / invite / reset / session-revoke) is reachable
//! as a real user for verification.
//!
//! This is NOT a shipped binary — it exists so QA can exercise the Postgres
//! happy-path that the SQLite `aa-api-server` intentionally degrades (its
//! `auth_store` is always `None`). It replicates `serve_local`'s body but
//! connects a [`PgUserStore`] from `AAASM_DATABASE_URL`, runs the users
//! migrations, and injects it into `AppState.auth_store`.
//!
//! Usage:
//! ```text
//! AAASM_DATABASE_URL=postgres://qa:qa@127.0.0.1:55432/aaqa \
//!   AASM_API_KEY=aa_<32hex> AA_API_ADDR=127.0.0.1:7700 \
//!   cargo run -p aa-api --bin aa-api-server-pg-qa
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use aa_api::state::LocalAuth;
use aa_storage_postgres::{PgUserStore, PostgresPool, PostgresPoolConfig};

const DEFAULT_ADDR: &str = "127.0.0.1:7700";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let db_url = std::env::var("AAASM_DATABASE_URL")
        .map_err(|_| "AAASM_DATABASE_URL is required for the Postgres QA harness")?;
    let raw = std::env::var("AA_API_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let addr: SocketAddr = raw.parse().unwrap_or_else(|_| DEFAULT_ADDR.parse().unwrap());

    // Connect + migrate the users/login/reset schema (mirrors the PgUserStore
    // integration harness). The pool doubles as the migrator and the store.
    let pool = PostgresPool::connect(&PostgresPoolConfig {
        url: db_url,
        max_connections: 5,
        statement_timeout_ms: 0,
    })
    .await?;
    pool.migrate().await?;
    eprintln!("aa-api-pg-qa: connected to Postgres and ran migrations");

    let (auth, _generated) = LocalAuth::from_env();
    if let LocalAuth::ApiKey { key } = &auth {
        aa_api::auth::api_key::ApiKey::parse(key).map_err(|e| format!("invalid AASM_API_KEY: {e}"))?;
    }

    // Build the same hardened local state the shipped binary uses, then inject
    // the real Postgres native-account store so the password auth path is live.
    let mut state =
        aa_api::AppState::local_hardened_at(auth, aa_api::state::resolve_local_registry_db_path()).await?;
    state.auth_store = Some(Arc::new(PgUserStore::new(pool)));
    eprintln!("aa-api-pg-qa: auth_store wired — native email/password auth is ENABLED");

    let config = aa_api::config::ApiConfig {
        bind_addr: addr,
        auth: (*state.auth_config).clone(),
    };

    // Resolve the dashboard SPA the same way serve_local does, so the real UI is
    // served for design-QA.
    let spa_dist = aa_gateway::dashboard_server::find_dashboard_dist();
    eprintln!(
        "aa-api-pg-qa serving full /api/v1/* + dashboard on http://{addr} (Postgres native-auth ENABLED){}",
        if spa_dist.is_some() { "" } else { " [REST only — no dashboard/dist resolved]" }
    );

    aa_api::run_server_with_spa(config, state, spa_dist.as_deref()).await
}
