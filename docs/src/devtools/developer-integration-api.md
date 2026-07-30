# Developer Integration API (DI-API)

The DI-API is the **only** channel by which a local, untrusted client — a
VS Code extension, a JetBrains plugin, an installer, or the `aasm` CLI — asks
the AASM runtime to install, inspect, verify, repair or remove a developer-tool
integration.

It is a **lifecycle and UX surface**. It carries no policy decisions and no
agent-action traffic. An agent that wants an allow/deny still goes
SDK → `aa-sdk-client` → runtime/gateway, on a different socket with a different
verb space ([ADR 0004](../adr/0004-governance-enforcement-flow.md)). The design
is fixed by
[ADR 0030 Decision 5](../adr/0030-developer-integration-boundaries-and-trust-model.md);
this page is the operational reference for people building against it.

> Implemented in `aa-runtime/src/devint/`. Wire schema:
> `proto/devint.proto` (`assembly.devint.v1`). Reference client:
> `aa-runtime/src/devint/client.rs`.

## Transport and discovery

| | |
| --- | --- |
| Transport | Unix domain socket (named pipe on Windows, not yet implemented) |
| Path | `~/.aa/run/devint.sock` |
| Override | `AA_DEVINT_SOCKET` |
| Directory mode | `0700` — created and re-asserted on every bind |
| Socket mode | `0600` — created under a tightened `umask`, then re-asserted |
| Framing | `[1-byte tag][prost varint length][prost payload]` |

**Loopback TCP is not offered and will not be.** A TCP port is reachable by
every local user and by any browser on the machine, the kernel supplies no peer
identity for it, and it adds CSRF and DNS-rebinding surface. Both permission
bits above are load-bearing: a deployment that relocates the socket via
`AA_DEVINT_SOCKET` **must** preserve them, or the OS layer of the two-layer
authentication is gone and only the token remains.

The DI-API socket is deliberately **separate** from the SDK fast-path socket.
That is a security property, not tidiness: a DI client never holds a file
descriptor onto agent-action traffic, so that traffic is unreachable to it by
construction rather than by an authorization rule someone has to remember.

### Discovery

A client resolves the path from `AA_DEVINT_SOCKET`, else the convention above.
**An absent socket means the runtime is not running** — show a bootstrap prompt.
It is not a transient condition to retry in a loop, and a client must never
synthesise "healthy" from a successful `connect()`.

## Authentication — two layers

### Layer 1: the operating system

`0700` directory, `0600` socket, and a peer-credential check: the connecting
process's UID must equal the runtime's. A mismatched or unreadable peer
credential is dropped before any frame is read.

### Layer 2: the capability token

OS identity says "the developer's UID". It cannot tell the VS Code extension
apart from a trojaned `npm postinstall` script running as the same user. The
capability token draws that distinction.

| Property | Value |
| --- | --- |
| Size | 256 bits from the OS CSPRNG |
| Form | opaque lowercase hex, no structure, **not a JWT** |
| Derivation | none — not from the client name, tool id, socket path or token id |
| Storage | server-side record `{token_id, client_name, issued_at, expires_at, scope}` plus SHA-256 of the secret |
| Issued | at an explicit, user-visible enrolment step — never implicitly on first connect |
| Scope | per tool **and** per verb |
| Expiry | absolute, not sliding |
| Rotation | issue-new-then-revoke-old, so there is never a window with no valid token |
| Revocation | delete the record; takes effect immediately, including on open connections |

Two properties are worth stating plainly because getting them wrong has
happened before in this codebase:

- **The token is not derived from anything public.** The SDK IPC handshake key
  is derived from the agent id, which *is* the public socket filename, so it
  proves integrity and version-binding rather than possession of a secret
  (AAASM-3922). A DI capability token built that way would be no secret at all.
- **It is not self-contained.** Verification is a lookup, not a signature check.
  A credential that verifies offline cannot be revoked, and revocation is a hard
  requirement here.

### Denials

**Absent, malformed, unknown, expired and out-of-scope all deny.** There is no
fall-through to an implicit grant, no "local connections are trusted", and no
anonymous read-only tier — an empty enrolment book authorizes nothing at all.

| Wire code | Cause |
| --- | --- |
| `DENY_CODE_UNAUTHENTICATED` | absent, malformed **or** unknown token |
| `DENY_CODE_TOKEN_EXPIRED` | a record resolved and is past its absolute expiry |
| `DENY_CODE_OUT_OF_SCOPE` | the token does not cover this verb on this tool |
| `DENY_CODE_UNKNOWN_VERB` | a discriminant outside the closed verb set |
| `DENY_CODE_PROTOCOL_VIOLATION` | e.g. a second `Hello` attempting to renegotiate |
| `DENY_CODE_UNAVAILABLE_AT_VERSION` | the verb does not exist at the negotiated version |
| `DENY_CODE_UNKNOWN_TOOL` | no adapter knows the named tool |
| `DENY_CODE_LIFECYCLE_ERROR` | the lifecycle service refused or failed |

The first three of these collapse into one code on purpose: a probing client
must not be able to use the response to tell "no such token" from "wrong shape"
from "you sent nothing". The **audit trail** records the finer outcome locally.

## Version negotiation

The first exchange on every connection, before any verb is accepted:

```text
→ Hello    { client_name, client_version,
             di_api_versions: [u32],
             lifecycle_schema_versions: [u32] }
← HelloAck { outcome, di_api_version, core_version, lifecycle_schema_version,
             min_supported, max_supported,
             unavailable_verbs[], degraded_reason, remediation }
  or
← Incompatible { reason, remediation, min_supported, max_supported }
```

The server selects the **highest** version both sides offer, over the client's
*offered set* rather than a claimed range. Three outcomes, and only three:

| Outcome | Meaning | Client obligation |
| --- | --- | --- |
| `SUPPORTED` | every verb is available | proceed |
| `DEGRADED` | a subset is available; `unavailable_verbs` names the rest | **surface it** and disable the matching UI |
| `INCOMPATIBLE` | no shared version, or below the floor | show `remediation`; the connection closes |

Rules that follow from this:

- **Never a silent downgrade.** `DEGRADED` is an outcome the client must show a
  user, not an implicit fallback.
- **The negotiated version is fixed for the connection's lifetime.** A second
  `Hello` is a protocol violation, not a renegotiation.
- **An unstated version is incompatible**, never "assume the oldest".
- A client should offer its **whole** supported window; offering less is how a
  client talks itself into a degraded connection for no reason.

Current window: `min_supported = 1`, `max_supported = 2`. `scoped_events` and
`approval_relay` were added at v2, so a v1 client is `DEGRADED`.

## The verb space

The verb space is a **closed enum**. There is no "call core", no method or path
string, no filter, predicate or query passthrough, and no opaque forwarded
envelope. An operation that does not exist cannot be requested, however the
request is crafted.

| Verb | Mutates? | Returns |
| --- | --- | --- |
| `list_tools` | no | `ToolList` — tools, detection, capabilities, ceiling |
| `plan` | no | `PlanView` — a reviewable dry run |
| `apply` | **yes** | `ApplyView` — receipt id, per-step outcome, fingerprints |
| `status` | no | `StatusView` — derived protection state plus its evidence |
| `verify` | no | `VerificationView` — the adjudicated protection test |
| `repair` | **yes** | `RepairView` — what was restored, and the resulting status |
| `remove` | **yes** | `RemovalView` — the reversal plan |
| `scoped_events` | no | `ScopedEventList` — redacted event projection |
| `approval_relay` | no | `ApprovalRelayAck` — "accepted for adjudication" |

`list_tools` is the only verb that names no tool, so it is the only one a
tool-scoped token may invoke without a tool-scope check.

### What will never be added

A `check`-like verb, an approval **decision** verb, an audit-emit verb, or any
passthrough that could carry one. Adding any of them reopens ADR 0004 *and*
ADR 0030. The verb list is pinned by a unit test against the ADR's transcribed
set, so widening it fails the build rather than passing review.

`approval_relay` is a **presentation relay**: the client reports which button a
human pressed, and the runtime/gateway remains the decision authority. The
acknowledgement says the input was accepted for adjudication. It is not a
verdict and must not be rendered as one.

## Data minimisation

Minimisation is enforced by the **shape of the response types**, not by a
redaction pass someone can forget to call.

| The service holds | The DI-API returns |
| --- | --- |
| a policy document | `PolicyProfileRefView { id, display_name, digest }` |
| rendered settings content | `content_sha256` and the AASM-owned `managed_keys` |
| `EnvValue::Literal("sk-…")` | the variable **name**, nothing else |
| a proxy variable map | the variable **names**, nothing else |
| a model base URL | the setting **name** — a URL can carry a token in its query |
| audit rows | counts, verdict kinds, timestamps, redaction **labels** |
| any storage or gateway credential | nothing — no DI-API type has a field for one |

`StepView` is the sharp edge and worth reading in full: it carries a step's
identity, kind, settings surface, key names, artifact paths and content
fingerprint, and has **no field a step value could land in**. A reviewer can see
what will change and compare digests; nobody can read a secret out of it.

No DI token is ever presented upstream. The runtime authenticates to the gateway
with its own credential, which never traverses the DI-API in either direction —
so compromising a client yields no reusable organization or gateway credential.

## Audit

Two classes of event are recorded, and never anything else:

- **Client authentication and authorization failures** — every absent,
  malformed, unknown, expired and out-of-scope token, plus rejected peers,
  unknown verbs, failed negotiations and renegotiation attempts.
- **Lifecycle mutations** — `apply`, `repair`, `remove`, with the outcome.

An event carries the **token id**, the client name, the verb, the tool and the
outcome. It never carries the token value, never carries protected content, and
has no free-form payload field for either to be pasted into. Denials that
reached no record carry no id, rather than an invented one.

## Writing a client

The reference implementation is `aa-runtime/src/devint/client.rs`
(`DevIntClient`). A correct client, in order:

1. **Discovers** the socket, and treats its absence as a stopped runtime.
2. **Negotiates first**, offering its whole version window, and **surfaces** a
   degraded outcome instead of swallowing it.
3. **Presents its capability token on every request.** There is no anonymous
   tier: a client without a token can negotiate, learn the versions, and then
   tell the user to enrol — nothing more.
4. **Renders what the service computed.** Never derive or upgrade a protection
   state client-side; a locally derived state is a claim wearing a
   measurement's clothes.
5. **Reads a status with its timestamp.** `observed_at_unix_secs` is part of the
   claim: it is "verified at T", not "true now".

```rust
use aa_runtime::devint::{DevIntClient, SocketDiscovery};

let discovery = DevIntClient::discover()?;
let SocketDiscovery::Present(path) = discovery else {
    // The runtime is not running — prompt to start it. Do not retry silently.
    return Ok(());
};

let mut client = DevIntClient::connect(&path, "vscode-aasm", "1.4.0", Some(token)).await?;
if client.negotiated().degraded {
    // Show this. Do not proceed as though the missing verbs exist.
    eprintln!("{}", client.negotiated().degraded_reason);
}

let status = client.status("claude-code").await?;
println!("{} (verified at {})", status.achieved_level, status.observed_at_unix_secs);
```

`aasm`'s own lifecycle commands become a DI-API client in
[AAASM-5280](https://lightning-dust-mite.atlassian.net/browse/AAASM-5280); an
in-process `--local` fallback is deliberately not offered, because it would be a
second code path with a different trust model.

## Operational notes

- `~/.aa/run/` must be `0700` and the socket `0600`. The runtime asserts both on
  every bind and refuses to serve if either is wrong.
- Treat a `DEGRADED` negotiation or a `Drifted` status as a signal, not noise.
- Rotate a token by issuing a replacement first and revoking the old one after
  the client has picked the new one up.
- Revoke on client uninstall. A revoked token stops working immediately,
  including on a session that is already open.
