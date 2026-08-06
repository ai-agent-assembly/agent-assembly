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

> **Opt-in everywhere; absent only from crates.io.** The runtime serves this
> surface only when `AA_DEVINT_ENABLED` is set — it is **off by default** on
> every channel. On crates.io it is not there at all:
> `.ci/strip-for-publish.sh` runs in `release.yml`'s `publish-crates` job and
> removes the DI-API bring-up from `aa-runtime` and the `aasm integrations`
> client from `aa-cli`, so `cargo install aasm` has neither end of this channel.
> A source build, the GitHub Release tarballs, the `curl` installer and the
> Homebrew formula all carry both ends, gated on the environment variable alone.

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
             unavailable_verbs[], degraded_reason, remediation,
             provenance? }                       # v4 and above only
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

Current window: `min_supported = 1`, `max_supported = 4`. `scoped_events` and
`approval_relay` were added at v2, so a v1 client is `DEGRADED`.

### What each version added

**Only v2 added verbs.** v3 and v4 add what a peer can *say*, not what it can
call, so a v1–v3 peer is `SUPPORTED` rather than `DEGRADED` and keeps every verb
it had. Protobuf message presence already makes a field's absence unambiguous,
so behaviour is correct without consulting the version at all; knowing the peer
speaks v3 lets a client name the reason — "this runtime speaks DI-API 3; build
provenance arrived in 4" — instead of the vaguer "the field is missing".

| Version | Addition | Verb change |
| --- | --- | --- |
| 1 | The lifecycle verbs. | — |
| 2 | `scoped_events`, `approval_relay`. | **adds 2** |
| 3 | `status` and `verify` carry a `PolicyView` — which policy a governed launch would run under (AAASM-5349). | none |
| 4 | `HelloAck` carries a `RuntimeProvenance` — which build is answering (AAASM-5628). | none |

### v4 — `RuntimeProvenance` on the `HelloAck`

A `core_version` cannot distinguish two checkouts sitting at the same version.
That is not hypothetical: a runtime built from a different checkout served an
entire QA campaign while every measurement was recorded against the build under
test, and a runtime whose worktree had been deleted kept serving and reported a
healthy tool as `not_installed`. **Port reachability is never sufficient** — in
both cases the socket was reachable and the runtime was healthy.

So the handshake states an identity, before any result is obtained:

| Field | Meaning |
| --- | --- |
| `core_version` | The running core version, repeated so the block is a complete identity on its own. |
| `build_sha` | The commit the binary was compiled from, or `unknown`. Never fabricated. |
| `build_id_source` | How `build_sha` was obtained: `injected`, `checkout`, `packaged`, or `absent`. |
| `pid` | The serving process. The only field that distinguishes two runtimes of the *same* build. |
| `executable_path` | Absolute path of the running executable, as the OS reports it. |
| `executable_present` | Whether that path still exists, evaluated **when the frame is written**, not at start. |
| `source_path` | The checkout it was built from, when known. Empty means the build suppressed it — **no build in this repository does**, so this is in practice a CI runner path on a release artifact and a developer's home directory on a local build. Treat it as such before pasting a status JSON anywhere public. |
| `started_at_unix_secs` | When this runtime began serving. |

A v1–v3 peer omits the message entirely, and *message presence* — not an empty
string — is what tells a client "this peer cannot say" apart from "this peer has
no identity".

#### The comparison is three-state

A client compares the reported identity against the one compiled into its own
`aa-runtime`. The result is **never a boolean**:

| Case | Result |
| --- | --- |
| two equal **authoritative** identities | `Match` |
| two different **authoritative** identities | `Mismatch` |
| `unknown` vs `unknown` | **`Unverifiable`** — never `Match` |
| known vs `unknown` | **`Unverifiable`** |

An identity is authoritative only when `build_id_source` names a real mechanism
(`injected`, `checkout` or `packaged`). Absence of provenance on both peers
proves only that both are unknown, not that they are the same build.

**`pid`, executable name, executable path, DI-API version and package version
are not proof of identical build content**, individually or in combination, and
none of them may upgrade a verdict. `core_version` is compared because it can
*falsify* — two different versions cannot be one build — but a version string
can never *verify*.

#### What a match does not establish

**Every provenance field is self-reported.** A process that can bind the DI-API
socket can claim any `build_sha` and any `build_id_source` and be reported
`verified`. This is an **attribution** control — it catches a stale, duplicated
or wrong-checkout runtime — **not an authentication** control. It is not weaker
than what precedes it: a peer able to bind that socket already shares the
runtime's UID and could replace the `aa-runtime` binary outright. Do not cite it
as a defence against a hostile local process.

**`checkout` names `HEAD`, not the working tree.** A build from a dirty checkout
reports its `HEAD` commit, so two dirty worktrees at the same `HEAD` with
different uncommitted changes compare as a match. Marking dirty builds
unidentifiable was rejected: nearly every development build is dirty, so it would
make refusal the normal state during development. `packaged` has no such gap — a
tarball packaged from a dirty tree is refused outright.

See [ADR 0030 §5.4a](../adr/0030-developer-integration-boundaries-and-trust-model.md)
for the trust model this sits inside.

#### What a client must do with the result

| Standing | Read-only request | Privileged write, or an enforcement claim |
| --- | --- | --- |
| `verified` | proceed | proceed |
| `unverifiable` | **proceed, reporting it as `unverifiable`** — never as verified | **refuse** |
| `refuted` (mismatch, deleted executable, or more than one runtime reachable) | **refuse** | **refuse** |

`aasm` implements this with exit codes `11` and `10` respectively; see the
[CLI reference](../cli/integrations.md#exit-codes).

**"More than one runtime reachable" is one-directional evidence.** A count above
one proves ambiguity — each of those sockets was connected to. A count of one
proves only that nothing else was *found*: `aasm`'s scan probes files named
`devint*.sock`, in the answering socket's own directory, once as the session
opens. A runtime under another name, in another directory (which
`AA_DEVINT_SOCKET` makes trivial), or started a moment later is not counted.
Read `reachable_runtimes == 1` as "no duplicate was observed", never as "this is
the only runtime".

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

`aasm`'s own lifecycle commands **are** a DI-API client
([AAASM-5280](https://lightning-dust-mite.atlassian.net/browse/AAASM-5280)); an
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
