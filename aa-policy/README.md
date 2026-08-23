# aa-policy

Policy document semantics for Agent Assembly — parsing, validation, and
version history.

[![crates.io](https://img.shields.io/crates/v/aa-policy?logo=rust&label=crates.io)](https://crates.io/crates/aa-policy)
[![docs.rs](https://img.shields.io/docsrs/aa-policy?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-policy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/LICENSE)

Owns the policy document's on-disk shape: parsing and validating policy YAML,
resolving overlapping rules, and tracking a policy's version history —
consumed by `aa-gateway`'s policy engine.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
