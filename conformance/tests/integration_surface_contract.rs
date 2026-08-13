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
//! AAASM-4447 has since landed: `serve_local` in `aa-api` now serves the gRPC
//! `AgentLifecycleService` on loopback `:50051` alongside its REST surface, so
//! the local-mode server finally exposes the registration surface the SDK dials.
//! The contract test that documented that gap
//! ([`local_mode_server_exposes_sdk_registration_surface`]) is therefore active
//! (no longer `#[ignore]`d) and passes because the surface genuinely exists now.

use conformance::surface;

/// The gRPC service the SDK's native registration path binds to.
///
/// Source of truth: `aa-sdk-client/src/gateway.rs`, which connects an
/// `AgentLifecycleServiceClient` and calls `.register(...)`.
const SDK_REGISTRATION_SERVICE: &str = "AgentLifecycleService";

/// The specific RPC the SDK invokes to register.
const SDK_REGISTRATION_RPC: &str = "Register";

/// The tonic-generated server type a gateway registers via `.add_service(...)`
/// to actually serve [`SDK_REGISTRATION_SERVICE`].
const SDK_REGISTRATION_SERVER_TYPE: &str = "AgentLifecycleServiceServer";

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

// ── Test 2: gateway serves that surface (passes today) ───────────────────────

/// The `aa-gateway` binary — what `aasm start --mode remote` launches — must
/// actually *serve* the gRPC registration service the SDK depends on.
///
/// Declaring the service in the proto (Test 1) is necessary but not sufficient:
/// a server has to register it via `.add_service(...)`. This test asserts that
/// remote mode wires up the surface, so a refactor that drops the registration
/// service from the gateway's tonic router is caught. Passes today; provides
/// ongoing regression value for the mode that *does* satisfy the contract.
#[test]
fn gateway_serves_sdk_registration_service() {
    let gateway = surface::workspace_root().join("aa-gateway");
    assert!(
        gateway.join("src").is_dir(),
        "expected aa-gateway crate at {}",
        gateway.display()
    );
    assert!(
        surface::crate_src_contains(&gateway, SDK_REGISTRATION_SERVER_TYPE),
        "aa-gateway no longer references `{SDK_REGISTRATION_SERVER_TYPE}` — the gRPC \
         registration surface the SDK depends on may have been removed from the gateway",
    );
    assert!(
        surface::crate_src_contains(&gateway, ".add_service("),
        "aa-gateway does not register any tonic service via `.add_service(...)`",
    );
}

// ── Test 3: local mode serves that surface (passes since AAASM-4447) ─────────

/// The server that `aasm start --mode local` launches must expose the agent-
/// registration surface the SDK's native path needs — **either** the gRPC
/// `AgentLifecycleService` **or** a documented REST registration route.
///
/// This is the exact drift AAASM-4447 uncovered: local mode spawns
/// `aa-api-server`, whose crate is `aa-api`. That crate used to serve only REST
/// `/api/v1/*` — no `AgentLifecycleServiceServer` — while the SDK dials gRPC
/// `Register` on `:50051`, so an agent could never register in local mode and
/// this assertion failed. AAASM-4447 closed the gap: `serve_local` now also
/// serves the gRPC `AgentLifecycleService` on loopback `:50051` over the same
/// registry (see `aa-api/src/server.rs`), so `aa-api`'s source now references
/// `AgentLifecycleServiceServer` and this test passes for the right reason — the
/// surface genuinely exists, detected by the same source-introspection helper
/// [`gateway_serves_sdk_registration_service`] uses for remote mode.
#[test]
fn local_mode_server_exposes_sdk_registration_surface() {
    // Which binary does `aasm start --mode local` launch? Read it from the CLI
    // source so this tracks real behavior instead of a hard-coded assumption.
    let start_src = surface::read_repo_file("aa-cli/src/commands/start.rs");
    let program = surface::local_mode_server_program(&start_src)
        .expect("could not determine the binary `aasm start --mode local` launches from start.rs");

    // Map that binary back to the crate whose surface must satisfy the contract.
    let crate_dir = surface::crate_dir_for_binary(&program)
        .unwrap_or_else(|| panic!("no workspace crate provides the `{program}` binary"));

    let serves_grpc = surface::crate_src_contains(&crate_dir, SDK_REGISTRATION_SERVER_TYPE);
    let has_rest_registration = surface::crate_has_registration_rest_route(&crate_dir);

    assert!(
        serves_grpc || has_rest_registration,
        "`aasm start --mode local` launches `{program}` (crate {}), but that crate exposes no \
         agent-registration surface the SDK can use: it neither serves gRPC \
         `{SDK_REGISTRATION_SERVICE}` (via `{SDK_REGISTRATION_SERVER_TYPE}`) nor declares a REST \
         registration route. The SDK's native path dials gRPC `{SDK_REGISTRATION_RPC}`, so an \
         agent started against local mode can never register. See AAASM-4447.",
        crate_dir.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
    );
}
