//! Integration-surface contract tests (AAASM-4454).
//!
//! # What broke, and why these tests exist
//!
//! AAASM-4447 found that `aasm start --mode local` brings up `aa-api-server`,
//! which serves **only** the REST `/api/v1/*` surface — while the SDK's native
//! agent-registration path (`aa-sdk-client`) speaks **gRPC**
//! `AgentLifecycleService.Register` against `:50051`. The two can never connect,
//! and nothing in the suite caught the drift because no test tied the surface
//! the SDK *depends on* to the surface the CLI *actually starts*.
//!
//! These tests encode that contract. They read the repository's own source as
//! the source of truth (see `conformance::surface`) rather than booting
//! processes — fast, deterministic, and enough to catch this drift class.
//!
//! The architecture fix for 4447 itself is being handled separately as an ADR;
//! this ticket is the *preventive* net. Where the contract cannot hold today,
//! the test is `#[ignore]`d with a message linking 4447 — a red/ignored contract
//! that documents the required surface, not a test rigged to pass on the gap.

use conformance::surface;

/// The gRPC service the SDK's native registration path binds to.
///
/// Source of truth: `aa-sdk-client/src/gateway.rs`, which connects an
/// `AgentLifecycleServiceClient` and calls `.register(...)`.
const SDK_REGISTRATION_SERVICE: &str = "AgentLifecycleService";

/// The specific RPC the SDK invokes to register.
const SDK_REGISTRATION_RPC: &str = "Register";

/// The full lifecycle RPC set the runtime + SDK depend on being present on the
/// service. Ordered as declared in `proto/agent.proto`.
const REQUIRED_LIFECYCLE_RPCS: &[&str] = &[
    "RequestChallenge",
    "Register",
    "Heartbeat",
    "Deregister",
    "ControlStream",
];

// ── Test 1: proto surface (passes today) ─────────────────────────────────────

/// The agent-lifecycle gRPC service the SDK relies on must declare every RPC in
/// the registration/heartbeat lifecycle.
///
/// This is the schema anchor for the whole contract: if someone renames or
/// drops `Register` (or any lifecycle RPC) in `proto/agent.proto`, the SDK's
/// native path silently loses its entrypoint. This test fails loudly instead.
///
/// It also references the generated tonic client/server types, so the proto
/// text and the *compiled* code cannot drift apart: the module path below only
/// exists if the service was code-generated under that name.
#[test]
fn sdk_registration_service_declares_full_lifecycle() {
    // Compile-time tie between proto text and generated code: these paths only
    // resolve if `AgentLifecycleService` was generated with client + server.
    #[allow(unused_imports)]
    use aa_proto::assembly::agent::v1::agent_lifecycle_service_client::AgentLifecycleServiceClient;
    #[allow(unused_imports)]
    use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleServiceServer;

    let proto = surface::read_repo_file("proto/agent.proto");
    let rpcs = surface::proto_service_rpcs(&proto, SDK_REGISTRATION_SERVICE);

    assert!(
        !rpcs.is_empty(),
        "service `{SDK_REGISTRATION_SERVICE}` not found in proto/agent.proto — the SDK's \
         native registration surface has moved or been renamed",
    );
    for required in REQUIRED_LIFECYCLE_RPCS {
        assert!(
            rpcs.iter().any(|r| r == required),
            "proto/agent.proto `{SDK_REGISTRATION_SERVICE}` is missing rpc `{required}`; \
             declared rpcs = {rpcs:?}",
        );
    }
    assert!(
        rpcs.iter().any(|r| r == SDK_REGISTRATION_RPC),
        "the SDK registration RPC `{SDK_REGISTRATION_RPC}` must exist on `{SDK_REGISTRATION_SERVICE}`",
    );
}
