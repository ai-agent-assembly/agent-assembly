# aa-storage-redis

Redis L2 shared-cache storage driver for Agent Assembly.

[![crates.io](https://img.shields.io/crates/v/aa-storage-redis?logo=rust&label=crates.io)](https://crates.io/crates/aa-storage-redis)
[![docs.rs](https://img.shields.io/docsrs/aa-storage-redis?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-storage-redis)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/master/LICENSE)

Implements the high-frequency `aa-storage` traits (`SessionStore`,
`RateLimitCounter`, and a read-through `PolicyStore`) against a Redis or Valkey
instance, so multiple Assembly processes coordinate through one shared L2 cache
instead of each hitting the L3 store. All keys are namespaced under `aa:`.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
