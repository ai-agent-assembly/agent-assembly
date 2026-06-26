# aa-storage-memory

In-memory `aa-storage` driver (DashMap-backed) for tests and local development.

[![crates.io](https://img.shields.io/crates/v/aa-storage-memory?logo=rust&label=crates.io)](https://crates.io/crates/aa-storage-memory)
[![docs.rs](https://img.shields.io/docsrs/aa-storage-memory?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-storage-memory)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/master/LICENSE)

`DashMap`- and `parking_lot`-backed implementations of the six `aa-storage` traits
for unit/integration tests and local development without a real database. State is
ephemeral — it lives only for the life of the process — and the driver registers
under the name `memory` for selection via `agent-assembly.toml`.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
