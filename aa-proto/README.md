# aa-proto

Generated protobuf/gRPC types for Agent Assembly (prost + tonic).

[![crates.io](https://img.shields.io/crates/v/aa-proto?logo=rust&label=crates.io)](https://crates.io/crates/aa-proto)
[![docs.rs](https://img.shields.io/docsrs/aa-proto?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-proto)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/master/LICENSE)

The single code-generation entrypoint for every proto definition under `proto/`,
and the single source of truth for the wire format. Other crates (`aa-runtime`,
`aa-gateway`, …) depend on this crate rather than running their own prost/tonic
codegen; the generated modules mirror the proto package hierarchy.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://ai-agent-assembly.github.io/agent-assembly-docs/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
