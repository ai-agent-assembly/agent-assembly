# aa-runtime

Tokio async runtime wrapper and lifecycle management for Agent Assembly.

[![crates.io](https://img.shields.io/crates/v/aa-runtime?logo=rust&label=crates.io)](https://crates.io/crates/aa-runtime)
[![docs.rs](https://img.shields.io/docsrs/aa-runtime?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-runtime)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/LICENSE)

Wraps `tokio` to give Agent Assembly components a consistent async execution
environment — runtime initialization, shutdown coordination, and agent lifecycle
hooks. The runtime is the authoritative enforcement point in the three-layer
interception model.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
