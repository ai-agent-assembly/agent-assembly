//! Tower middleware stack for the API server.
//!
//! Middleware is applied in this order (outermost first):
//! 1. Panic capture (`catch_panic`) — outermost, so a panic anywhere in the
//!    stack or a handler becomes a `500` instead of aborting the connection
//! 2. Request ID injection (`x-request-id`)
//! 3. Structured tracing (logs method, path, status, duration, request_id)
//! 4. CORS (allow dashboard origin)
//! 5. Response compression (gzip)
//!
//! Authentication is handled by FromRequestParts extractors (see auth module),
//! not middleware layers.

pub mod compression;
pub mod cors;
pub mod request_id;
pub mod tracing;

use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{PropagateRequestIdLayer, SetRequestIdLayer};

use self::request_id::UuidRequestId;

/// Apply the full middleware stack to the given router.
pub fn apply_middleware(router: Router) -> Router {
    router
        .layer(self::compression::compression_layer())
        .layer(self::cors::cors_layer())
        .layer(self::tracing::trace_layer())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
        // AAASM-4018: defense-in-depth. A panic in any handler (e.g. an
        // unchecked slice on a malformed path parameter) would otherwise unwind
        // the request task and drop the connection; the outermost catch_panic
        // turns it into a `500 Internal Server Error` so one bad request cannot
        // take down the worker.
        .layer(CatchPanicLayer::new())
}
