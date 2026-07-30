//! The Developer Integration API (DI-API) — ADR 0030 Decision 5, AAASM-5279.
//!
//! # What this is
//!
//! The one authenticated channel by which an **untrusted** local thin client —
//! a VS Code extension, an installer, `aasm integration …` — asks the trusted
//! runtime to install, inspect, verify, repair or remove a developer-tool
//! integration. It is a *lifecycle and UX* surface. It carries no policy
//! decisions and no agent-action traffic; those go SDK → `aa-sdk-client` →
//! runtime/gateway on a different socket (ADR 0004).
//!
//! # The trust model, in the order a connection meets it
//!
//! 1. **The socket itself.** `~/.aa/run/devint.sock`, in a `0700` directory,
//!    created `0600` under a tightened `umask` — the same construction
//!    [`crate::ipc::server`] uses (AAASM-3581), and re-asserted on every bind
//!    rather than trusted from the last one ([`socket`]). It is deliberately
//!    **not** the SDK fast-path socket: a DI client never holds a file
//!    descriptor onto agent traffic, so that traffic is unreachable by
//!    construction rather than by a rule someone has to write.
//!    Loopback TCP is a forbidden design (§5.2).
//! 2. **Peer credentials.** [`crate::ipc::peercred::peer_uid_is_allowed`],
//!    reused verbatim: a peer whose UID is not the runtime's is dropped before
//!    any work is done for it.
//! 3. **Version negotiation.** An explicit `Hello`/`HelloAck` exchange before
//!    any verb is accepted, with deterministic supported / degraded /
//!    incompatible outcomes and no silent downgrade ([`negotiate`]).
//! 4. **A capability token.** 256 bits from a CSPRNG, opaque, resolved against
//!    a server-side record, scoped per tool and per verb, absolutely expiring,
//!    rotatable and revocable ([`token`]). Absent, expired, unknown or
//!    unresolvable ⇒ deny plus an audit event, with no anonymous tier.
//!
//! # Why layer 4 is not the AAASM-3922 mistake again
//!
//! The SDK handshake key is derived from the agent id, which is the public
//! socket filename, so it proves integrity and version-binding rather than
//! possession of a secret (see [`crate::ipc::handshake`]). A DI capability
//! token is the opposite by construction: it is drawn from the OS CSPRNG, is
//! derived from nothing, is knowable only from the `0600` file it was written
//! to, and is verified by *looking it up* rather than by recomputing it. That
//! is also why it is not a JWT — a credential that verifies offline cannot be
//! revoked, and revocation is a hard requirement here.
//!
//! # What cannot be asked for
//!
//! [`verb::DiVerb`] is a closed enum. There is no "call core", no path or
//! method passthrough, no filter or predicate passthrough, no opaque forwarded
//! envelope, and no policy-decision or audit-emit verb. The service depends on
//! the [`lifecycle::IntegrationLifecycle`] port, not on `aa_core::storage`,
//! identity, or gateway credential types — a handler that wanted to read
//! storage would not compile without a dependency edit.
//!
//! # What cannot leave
//!
//! Responses are built by [`projection`], whose types have no field able to
//! hold a policy document, a rendered settings body, an environment-variable
//! value, a raw prompt or tool output, or a storage/gateway credential.
//! Minimisation is the shape of the response types, not a redaction pass
//! someone might forget (§5.5).

pub mod scope;
pub mod verb;

pub use scope::TokenScope;
pub use verb::DiVerb;
