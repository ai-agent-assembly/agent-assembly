# aa-auth

Authentication primitives for Agent Assembly — API-key and JWT verification,
credential-token checks, and the fail-closed auth posture the gateway enforces.

[![crates.io](https://img.shields.io/crates/v/aa-auth?logo=rust&label=crates.io)](https://crates.io/crates/aa-auth)
[![docs.rs](https://img.shields.io/docsrs/aa-auth?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-auth)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/LICENSE)

Owns the shared authentication types and verification logic so the gateway can
guard privileged surfaces (e.g. `/admin/status`) without pulling the full
gateway into its dependency graph. Deliberately a **leaf** crate: it holds the
auth mode (`AuthMode`), the API-key/JWT verifiers, and the request-extractor
contracts, and its bypass-default (`AuthMode::Off` unless auth is explicitly
configured) preserves the zero-config developer experience while failing closed
the moment auth is turned on.

Extracted from `aa-gateway` (AAASM-3898) so authentication is independently
testable and reusable across the HTTP (`aa-api`) and gRPC surfaces.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
