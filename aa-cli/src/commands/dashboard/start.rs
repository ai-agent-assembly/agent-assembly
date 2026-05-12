//! `aasm dashboard start` — serve the embedded governance dashboard SPA.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use clap::Args;
use include_dir::{include_dir, Dir};
use tokio::net::TcpListener;

use crate::config::{resolve_dashboard_port, CliConfig, ResolvedContext};

use super::pid;

static ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/../dashboard/dist");

/// Arguments for `aasm dashboard start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Port to listen on (overrides config and AASM_DASHBOARD_PORT env var).
    #[arg(long, env = "AASM_DASHBOARD_PORT")]
    pub port: Option<u16>,
    /// Open the system browser after the server is ready.
    #[arg(long)]
    pub open: bool,
}

pub fn dispatch(args: StartArgs, ctx: &ResolvedContext, config: &CliConfig) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(run(args, ctx, config))
}

async fn run(args: StartArgs, ctx: &ResolvedContext, config: &CliConfig) -> ExitCode {
    let port = resolve_dashboard_port(config, args.port);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("invalid socket address");

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind to {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = pid::write_pid(port) {
        eprintln!("warning: could not write PID file: {e}");
    }

    let gateway_url = Arc::new(ctx.api_url.clone());

    let app = Router::new()
        .route("/api/{*path}", any(proxy_handler))
        .fallback(static_handler)
        .with_state(gateway_url);

    let url = format!("http://127.0.0.1:{port}");
    println!("Dashboard running at {url}");
    println!("Press Ctrl-C to stop.");

    let auto_open = args.open || config.dashboard.auto_open;
    if auto_open {
        if let Err(e) = open::that(&url) {
            eprintln!("warning: could not open browser: {e}");
        }
    }

    let serve = axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    });

    if let Err(e) = serve.await {
        eprintln!("error: server error: {e}");
        let _ = pid::remove_pid();
        return ExitCode::FAILURE;
    }

    let _ = pid::remove_pid();
    ExitCode::SUCCESS
}

/// Serve embedded static files; fall back to `index.html` for SPA routing.
async fn static_handler(uri: Uri) -> impl IntoResponse {
    let raw = uri.path().trim_start_matches('/');
    let path = if raw.is_empty() { "index.html" } else { raw };

    if let Some(file) = ASSETS.get_file(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            [(header::CONTENT_TYPE, mime.as_ref().to_string())],
            file.contents().to_vec(),
        )
            .into_response();
    }

    // SPA fallback: any unmatched path returns index.html.
    if let Some(index) = ASSETS.get_file("index.html") {
        return (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            index.contents().to_vec(),
        )
            .into_response();
    }

    (StatusCode::NOT_FOUND, "Not found").into_response()
}

/// Reverse-proxy `/api/*` to the configured gateway address.
async fn proxy_handler(
    State(gateway_url): State<Arc<String>>,
    method: Method,
    uri: Uri,
    req_headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());
    let target = format!("{}{}", gateway_url, path_and_query);

    let client = reqwest::Client::new();
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    let mut builder = client.request(reqwest_method, &target);
    for (name, value) in &req_headers {
        if name != header::HOST {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
    }
    builder = builder.body(body.to_vec());

    let upstream = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, e.to_string()).into_response();
        }
    };

    let status = StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let resp_headers = upstream.headers().clone();
    let resp_body = upstream.bytes().await.unwrap_or_default();

    let mut response = Response::new(Body::from(resp_body));
    *response.status_mut() = status;
    for (name, value) in &resp_headers {
        response.headers_mut().insert(name, value.clone());
    }
    response
}
