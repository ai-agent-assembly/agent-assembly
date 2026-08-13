# aa-security

Security primitives for Agent Assembly — credential scanning, redaction, and
audit-normalization.

[![crates.io](https://img.shields.io/crates/v/aa-security?logo=rust&label=crates.io)](https://crates.io/crates/aa-security)
[![docs.rs](https://img.shields.io/docsrs/aa-security?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-security)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/LICENSE)

Owns the credential-detection scanner, redaction primitives, audit-normalization
types, and the canonical policy AST relied on by the trusted enforcement layers
(`aa-runtime`, `aa-gateway`, `aa-proxy`, and the eBPF loader). Deliberately a
**leaf** crate with no `aa-core` dependency, so the shared policy AST is hosted
here without a dependency cycle.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
