# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.0.x (alpha) | ✅ Active development — security patches applied |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a security issue, use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/ai-agent-assembly/agent-assembly/security) of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the details and submit.

<!-- BEGIN GENERATED: security_contact_email -->
Alternatively, email **security@agent-assembly.com**

> **Legacy address.** `security@agent-assembly.dev` remains a legacy compatibility alias. During the in-progress migration to the canonical `security@agent-assembly.com` identity, the legacy address continues to receive mail via Cloudflare Email Routing, so a report sent there still reaches us. The canonical mailbox is not yet live-sending.
<!-- END GENERATED: security_contact_email -->
with the subject line: `[SECURITY] agent-assembly — <brief description>`.

### What to include

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept.
- The affected version(s) and component(s).
- Any suggested mitigations, if known.

## Response SLA

| Stage | Target |
|---|---|
<!-- BEGIN GENERATED: security_sla -->
| Initial acknowledgement | Within 2 business days |
| Severity assessment | Within 5 business days |
<!-- END GENERATED: security_sla -->
| Patch or mitigation | Dependent on severity (Critical: 7 days, High: 14 days, Medium/Low: next release) |

## Deployment posture — gateway gRPC agent plane

The gateway's gRPC **agent plane** (default `127.0.0.1:50051`, and the optional
Unix-domain socket) carries the agent lifecycle, policy, approval, audit,
topology, and secrets RPCs. Its security model has two layers:

1. **Per-RPC credential authentication (always on).** Every RPC must present the
   agent `credential_token` issued at registration — in the
   `x-aa-credential-token` metadata header, or as `authorization: Bearer
   <token>`. The gateway resolves the token to a verified caller identity
   (agent + tenant) and **fails closed** (rejects with `UNAUTHENTICATED`) on a
   missing, malformed, or unknown token. Approval decisions are bound to the
   authenticated caller's tenant, and the deciding operator (`decided_by`) is
   derived from the verified caller — never trusted from the request body.
   Rejections are counted in the `aa_grpc_auth_rejected_total` metric.

2. **Network exposure (operator responsibility).** The plane binds to
   **loopback by default** and the gateway is not shipped in the limited-function
   OSS self-host stack. **Do not bind the gRPC plane to a routable interface
   without enabling transport encryption.** mTLS is the supported transport
   hardening for non-loopback deployments; it is configured via
   `AA_GATEWAY_GRPC_TLS_CERT` / `AA_GATEWAY_GRPC_TLS_KEY` (and
   `AA_GATEWAY_GRPC_CLIENT_CA` for mutual TLS). While the live TLS handshake is
   being finished (tracked under AAASM-3418), the gateway **refuses to start** if
   these variables are set rather than serve plaintext on a socket the operator
   believes is encrypted.

Honest boundary: per-endpoint authentication is endpoint hygiene, not an
absolute control. The sidecar proxy can independently deny egress traffic
that fails policy, and eBPF can independently detect what neither the SDK nor
the proxy observed — but neither is a backstop that catches what the other
misses; each reaches its own claim level (ADR 0033 §6), and an absent
mechanism is reported as absent, not covered by another.

## Deployment posture — `aa-api` HTTP surface & operator dashboard

The `aa-api` REST/HTTP surface and the bundled React **operator dashboard**
(including its WebSocket live-ops, approvals, and alert streams) are designed for
a **local / self-hosted / operator-controlled** deployment — a single process on
the operator's own host or private network. Treat them accordingly:

1. **Do not expose the dashboard / `aa-api` HTTP surface directly to the public
   internet** without a trusted authenticating layer in front of it (a VPN, a
   private network, or an authenticated reverse proxy). `aa-api` binds to loopback
   by default; binding to a routable interface (e.g. `--mode remote`) puts the API
   and dashboard on the network.
2. **Browser session auth is a scoped trade-off.** The dashboard keeps its session
   JWT in `sessionStorage` under a strict CSP. This is an **intentional, accepted
   trade-off for the OSS local threat model** — it is *not* hardened against a
   same-origin XSS, and it is not the design the SaaS edition uses. See
   [ADR 0012](docs/src/adr/0012-websocket-and-browser-credential-handling.md).
3. **WebSocket streams carry no credential in the URL.** Browser WS connections
   authenticate with a short-lived, single-use ticket minted over an authenticated
   REST call (AAASM-4861), so no long-lived token appears in a URL that
   proxy/CDN/LB access logs would capture. The application logs the request path
   only, not the query string; operators who front `aa-api` with their own
   reverse proxy / CDN should still configure edge redaction of `token` / `ticket`
   query parameters — infrastructure outside this repo is not automatically
   protected.

## Deployment posture — Developer Integration API (DI-API)

The DI-API is the local socket by which an untrusted local client — a VS Code
extension, a JetBrains plugin, an installer, or the `aasm` CLI — asks the runtime
to install, inspect, verify, repair or remove a **developer-tool integration**.
Four properties define its posture:

1. **Off by default.** The runtime reads `AA_DEVINT_ENABLED` at startup and binds
   nothing without it. On **crates.io only**, it is absent altogether:
   `.ci/strip-for-publish.sh` runs in `release.yml`'s `publish-crates` job and
   removes the DI-API bring-up from `aa-runtime` and the `aasm integrations`
   client from `aa-cli`, so `cargo install aasm` has neither end of this channel.
   Every other channel — the GitHub Release tarballs, the `curl` installer and
   the Homebrew formula — ships binaries built from the unstripped tree in the
   `build` job, so **both ends are present there** and `AA_DEVINT_ENABLED` is the
   only thing standing between them and a bound socket. Treat the environment
   gate, not the strip, as the control that applies to the binaries most users
   actually have.
2. **A second socket that carries no policy and no agent traffic.** It is
   deliberately separate from the SDK fast-path socket, and that separation is a
   security property rather than tidiness: a DI client never holds a file
   descriptor onto agent-action traffic, so that traffic is unreachable to it by
   construction rather than by an authorization rule someone has to remember.
   Allow/deny decisions still go SDK → `aa-sdk-client` → runtime/gateway, on a
   different socket with a different verb space.
3. **Two-layer authentication, failing closed.** A `0700` directory, a `0600`
   Unix socket, and a peer-credential check requiring the connecting process's
   UID to equal the runtime's — a mismatched or unreadable peer credential is
   dropped before any frame is read. Above that, a per-client capability token
   written `0600`; a token file readable by more than its owner is **refused
   rather than used**, so a filesystem mistake cannot become a silent
   authentication downgrade. There is no anonymous tier. **Loopback TCP is not
   offered and will not be** — a TCP port is reachable by every local user and by
   any browser on the machine, the kernel supplies no peer identity for it, and it
   adds CSRF and DNS-rebinding surface. A deployment that relocates the socket via
   `AA_DEVINT_SOCKET` must preserve both permission bits.
4. **No sensitive payload can cross it.** No DI-API response type has a field able
   to hold a rendered settings body, an environment-variable value, a policy
   document or a credential; a policy is named by reference (id, display name,
   digest), never carried.

### The one privileged write

`aasm integrations install --install-managed-settings` is the **only** privileged,
root-owned write the product performs. It is macOS-only, **opt-in**, never a
default, and never implied by a protection profile — `--scope managed` on its own
is refused precisely because it says nothing about administrator authorization.
It elevates for a **single file placement** and nothing else: `aasm` never runs as
root, and no other step in any plan asks for authorization.

Before consent is requested, the plan discloses the exact path, the exact content
and its SHA-256, the diff against what is on the host, any conflict, and the
backup and rollback behaviour. It refuses to replace a managed-settings file
Agent Assembly did not write (for example one deployed by your organisation's
device management), fails immediately without a terminal rather than blocking on
a credential prompt nobody can answer, and rolls the write back if the read-back
does not match rather than reporting success on the authorization mechanism's
word.

Honest boundary: this is the only route to a `Host Enforced` protection level,
and `Host Enforced` means *"the managed policy is installed at the OS-managed
path, owned as expected and not writable by you."* It does **not** mean the
bypass has been demonstrated to fail. **That half is unmeasured on every host**,
including managed ones: no run has yet put a managed-only key against a real
user-side override attempt. Nor is a device-management enrolment what is missing
— the write is a plain `install -o root -g wheel` to a filesystem path, with no
configuration profile or managed preference domain involved, so an
administrator-consented write on any Mac produces the same artifact. AAASM-5308
carries the measurement. See
[Limitations and known bypasses](docs/src/devtools/limitations.md).

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available, we will:

1. Release a patched version.
2. Publish a GitHub Security Advisory.
3. Credit the reporter (unless they prefer to remain anonymous).
