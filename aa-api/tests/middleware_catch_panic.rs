//! Regression test for AAASM-4151 / AAASM-4018: the outermost
//! `CatchPanicLayer` in the API middleware stack must convert a panic in a
//! handler into a `500 Internal Server Error` instead of letting it unwind the
//! request task (and, under a shipped `panic = "abort"` build, abort the whole
//! process). This locks the middleware wiring; the shipped `release`/`dist`
//! profiles pin `panic = "unwind"` so the layer is actually effective in prod.

use aa_api::middleware::apply_middleware;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

async fn panicking_handler() -> &'static str {
    panic!("simulated handler panic (AAASM-4151 regression)");
}

#[tokio::test]
async fn handler_panic_is_caught_as_500() {
    let app = apply_middleware(Router::new().route("/boom", get(panicking_handler)));

    let resp = app
        .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
        .await
        .expect("catch_panic must yield a response, not propagate the panic");

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
