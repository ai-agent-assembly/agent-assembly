# aa-ebpf

Kernel-level eBPF monitoring hooks for Agent Assembly — one of the three
independently-deployable enforcement mechanisms (AAASM-4). Observe-only:
it reports what it sees, it does not block.

## Architecture

BPF programs live in a **separate crate** (`aa-ebpf-probes/`) that compiles to the
`bpfel-unknown-none` target under nightly Rust. The userspace crate (`aa-ebpf`, this
crate) loads the compiled bytecode via `aya::Ebpf::load`.

```
aa-ebpf-probes/          ← BPF-side (nightly, bpfel-unknown-none) — outside workspace
    src/main.rs          ← kprobe / uprobe / tracepoint programs
    rust-toolchain.toml  ← nightly pin with rust-src + bpfel-unknown-none
    .cargo/config.toml   ← default target = bpfel-unknown-none

aa-ebpf/                 ← userspace (stable, in workspace)
    build.rs             ← compiles aa-ebpf-probes via aya-build (Linux only)
    src/lib.rs           ← embeds bytecode, exposes pub API (Linux only)
```

## Prerequisites

| Requirement | Version |
|---|---|
| Rust toolchain | nightly (managed by `aa-ebpf-probes/rust-toolchain.toml`) |
| Linux kernel | 5.8+ (BPF ring buffer); 5.15+ recommended (stable BTF) |
| OS | Linux only — eBPF cannot be loaded on macOS or Windows |

The main workspace stays on **stable**. Only `aa-ebpf-probes/` requires nightly.

## Building BPF programs

`cargo build --workspace` does **not** compile BPF programs — they are compiled
by `aa-ebpf`'s `build.rs` when you build `aa-ebpf` on a Linux host.

```bash
# Build the userspace crate (triggers BPF compilation automatically via build.rs)
cargo build -p aa-ebpf   # Linux only

# Build BPF programs directly (faster iteration)
cd aa-ebpf-probes
cargo build --release
```

On macOS the `aa-ebpf` crate builds without errors but `AA_FILE_IO_BPF` and all
other Linux-gated symbols are absent. This is expected.

## CI

The `ebpf-build` GitHub Actions job (`.github/workflows/ci.yml`) compiles the
BPF programs on an `ubuntu-latest` runner with nightly Rust and the
`bpfel-unknown-none` target. macOS CI jobs never enter `aa-ebpf-probes/`
and are unaffected.

## CO-RE / BTF

Compile Once, Run Everywhere (CO-RE) via BTF is **not enabled** in the current
hello-world skeleton. When implementing real probes (AAASM-37 / AAASM-38 /
AAASM-39), generate `vmlinux.h` from the CI runner kernel and check it in:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > aa-ebpf-probes/src/vmlinux.h
```

Minimum kernel versions for CO-RE: **5.8** (BPF ring buffer) / **5.15** (stable BTF).

## Adding new probes

1. Add a new `[[bin]]` entry to `aa-ebpf-probes/Cargo.toml`.
2. Write the BPF program in `aa-ebpf-probes/src/<probe-name>.rs`.
3. Add a corresponding `Package { name: "<probe-name>", ... }` entry in
   `aa-ebpf/build.rs`.
4. Expose the compiled bytes in `aa-ebpf/src/lib.rs` using `aya::include_bytes_aligned!`.
5. Write a loader function in `aa-ebpf/src/lib.rs` that attaches the program.

## Related tickets

| Ticket | Description |
|---|---|
| AAASM-4 | Three-Layer Agent Interception (parent Epic) |
| AAASM-37 | F11: OpenSSL uprobe (blocked on this ticket) |
| AAASM-38 | F12: File I/O kprobes (blocked on this ticket) |
| AAASM-39 | F13: Process exec tracepoints (blocked on this ticket) |
