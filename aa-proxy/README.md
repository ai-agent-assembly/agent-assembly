# aa-proxy

Sidecar traffic interception proxy for Agent Assembly.

[![crates.io](https://img.shields.io/crates/v/aa-proxy?logo=rust&label=crates.io)](https://crates.io/crates/aa-proxy)
[![docs.rs](https://img.shields.io/docsrs/aa-proxy?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-proxy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/master/LICENSE)

Implements Layer 2 of the three-layer interception model: a sidecar proxy that
sits alongside each AI agent process, intercepting outbound HTTPS traffic and
enforcing governance policy before forwarding requests — with no code changes to
the agent. Runs as a standalone binary or embedded in-process via `aa_proxy::run()`.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
