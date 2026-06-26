# aa-storage

Storage trait abstraction (pure interface) for the Agent Assembly persistence layer.

[![crates.io](https://img.shields.io/crates/v/aa-storage?logo=rust&label=crates.io)](https://crates.io/crates/aa-storage)
[![docs.rs](https://img.shields.io/docsrs/aa-storage?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-storage)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/master/LICENSE)

A thin facade over `aa_core::storage` that re-exports the storage trait contract
(`PolicyStore`, `AuditSink`, `SessionStore`, `CredentialStore`, `RateLimitCounter`,
`LifecycleStore`). It is a pure interface with no concrete backend dependency, so
driver crates can express "I implement the storage contract" without coupling to
the rest of `aa-core`.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://ai-agent-assembly.github.io/agent-assembly-docs/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
