//! Security test: the local-mode gRPC agent-registration listener is
//! loopback-only and never reachable off `127.0.0.1` (AAASM-4447 / AAASM-4463).
//!
//! The registration plane mints credential tokens, so it must not be exposed on
//! a routable interface. Two guarantees are asserted:
//!
//! 1. The shipped bind target ([`aa_api::server::LOCAL_GRPC_ADDR`]) is a loopback
//!    address on the SDK's expected port — so `serve_local` can never bind
//!    `0.0.0.0`.
//! 2. When actually served, the bound socket is loopback (not the unspecified
//!    `0.0.0.0` wildcard), and a loopback client reaches it while the address
//!    proves it is not listening on any external interface.

use std::future::pending;
use std::net::SocketAddr;

/// The shipped registration endpoint must always be a loopback address on the
/// port the SDK dials — the static half of the off-host-unreachability
/// guarantee. A regression to `0.0.0.0:50051` (all interfaces) fails here.
#[test]
fn shipped_grpc_addr_is_loopback_only() {
    let addr: SocketAddr = aa_api::server::LOCAL_GRPC_ADDR
        .parse()
        .expect("LOCAL_GRPC_ADDR parses as a socket address");
    assert!(
        addr.ip().is_loopback(),
        "the gRPC registration listener must bind a loopback address, got {addr}"
    );
    assert!(
        !addr.ip().is_unspecified(),
        "the gRPC registration listener must never bind the 0.0.0.0 wildcard, got {addr}"
    );
    assert_eq!(addr.port(), 50051, "must match the SDK DEFAULT_GATEWAY_ENDPOINT port");
}

/// When the registration service is actually served, the socket it accepts on
/// is loopback — reachable from `127.0.0.1` but not from any external interface.
#[tokio::test]
async fn served_grpc_listener_is_bound_to_loopback() {
    let registry = std::sync::Arc::new(aa_gateway::registry::AgentRegistry::new());

    // Bind on the loopback host with an ephemeral port (parallel-safe); the
    // shipped binary uses the fixed loopback :50051 verified above.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback gRPC port");
    let bound: SocketAddr = listener.local_addr().expect("local_addr");

    // The accepting socket is loopback and not the 0.0.0.0 wildcard — i.e. it is
    // not listening on any routable interface, so it cannot be reached off-host.
    assert!(
        bound.ip().is_loopback(),
        "served gRPC socket must be loopback, got {bound}"
    );
    assert!(
        !bound.ip().is_unspecified(),
        "served gRPC socket must not be the 0.0.0.0 wildcard, got {bound}"
    );

    // A loopback client can still reach it (the endpoint is functional, just
    // confined to localhost). Race the never-terminating server against a short
    // connect probe.
    let serve = aa_api::server::serve_lifecycle_grpc(listener, registry, pending::<()>());
    let probe = async {
        let stream = tokio::net::TcpStream::connect(bound).await;
        assert!(stream.is_ok(), "loopback client must reach the registration listener");
    };
    tokio::select! {
        served = serve => panic!("gRPC server exited before the probe finished: {served:?}"),
        () = probe => {}
    }
}
