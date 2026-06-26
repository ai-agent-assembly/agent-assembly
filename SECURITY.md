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

Alternatively, email **security@agent-assembly.dev** with the subject line:
`[SECURITY] agent-assembly — <brief description>`.

### What to include

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept.
- The affected version(s) and component(s).
- Any suggested mitigations, if known.

## Response SLA

| Stage | Target |
|---|---|
| Initial acknowledgement | Within 2 business days |
| Severity assessment | Within 5 business days |
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
absolute control. The sidecar proxy and eBPF layers remain the authoritative
backstop for bypass attempts.

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available, we will:

1. Release a patched version.
2. Publish a GitHub Security Advisory.
3. Credit the reporter (unless they prefer to remain anonymous).
