//! Shared readiness marker for `aa-gateway` startup (AAASM-6053).
//!
//! `aa-gateway` emits [`TCP_LISTENING_MARKER`] via `tracing` immediately
//! after it has itself successfully bound its TCP listener — never before.
//! `aasm gateway start` (`aa-cli/src/commands/gateway/start.rs`) tails the
//! spawned child's log file for this exact string instead of trusting a bare
//! TCP connect as proof of readiness.
//!
//! A bare connect cannot distinguish "my spawned child bound this" from
//! "something else already had the port" — when another process holds the
//! port, the connect succeeds instantly against *that* listener while the
//! real child is still working through async service setup, seconds away
//! from its own `AddrInUse` failure. This marker is the fix: it only ever
//! reaches the log after this process's own `bind()` returned `Ok`, so it
//! cannot be produced by anything else that merely happens to be listening
//! on the same address.
//!
//! Lives in `aa-core` (rather than duplicated as a literal in both
//! `aa-gateway` and `aa-cli`) so the emitter and the reader cannot drift
//! apart the way the two intended-registries in AAASM-4859 (see
//! `aa-core::net`'s module doc) did.
/// Substring `aa-gateway` writes to its log immediately after its own TCP
/// `bind()` succeeds. See the module docs for why this exists.
pub const TCP_LISTENING_MARKER: &str = "gRPC server listening on TCP";
