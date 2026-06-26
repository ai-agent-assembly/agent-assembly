# aa-ebpf-common

Shared `no_std` types between eBPF kernel probes and userspace loader.

[![crates.io](https://img.shields.io/crates/v/aa-ebpf-common?logo=rust&label=crates.io)](https://crates.io/crates/aa-ebpf-common)
[![docs.rs](https://img.shields.io/docsrs/aa-ebpf-common?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-ebpf-common)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/master/LICENSE)

The shared event types for Layer 3 (eBPF) of the interception model. This `no_std`
crate is compiled twice — for the host target by `aa-ebpf` (userspace consumer)
and for the bpf target by `aa-ebpf-programs` (kernel producer). All types are
`#[repr(C)]` and `Copy` so they cross the BPF ring buffer with no serialization.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://ai-agent-assembly.github.io/agent-assembly-docs/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
