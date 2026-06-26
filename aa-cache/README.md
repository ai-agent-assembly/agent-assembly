# aa-cache

In-process L1 cache wrapper (DashMap + TTL + stampede protection) for the Agent
Assembly storage traits.

[![crates.io](https://img.shields.io/crates/v/aa-cache?logo=rust&label=crates.io)](https://crates.io/crates/aa-cache)
[![docs.rs](https://img.shields.io/docsrs/aa-cache?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-cache)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/master/LICENSE)

Wraps any storage backend behind an in-process `DashMap` with a configurable TTL
and per-key stampede protection, so policy lookups on the tool-call critical path
hit memory instead of crossing the network to Postgres or the gateway. The wrapped
store is abstracted by the `CacheSource` trait, so the cache is agnostic to what it
fronts.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
