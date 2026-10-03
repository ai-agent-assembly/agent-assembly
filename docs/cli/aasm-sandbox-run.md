# `aasm sandbox run`

<a id="cmd-aasm-sandbox-run"></a>

Run a WebAssembly module inside a fresh sandbox and report the outcome

## Synopsis

```text
Usage: aasm sandbox run [OPTIONS] <WASM>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `<WASM>` | `<WASM>` | Path to a `.wasm` module to execute under WASI preview 1 *(required)* |
| `--fuel` | `<FUEL>` | Wasmtime instruction-fuel budget. Defaults to the safe-by-default 10M units; pass a larger value for long-running tools |
| `--memory-pages` | `<MEMORY_PAGES>` | Maximum linear-memory pages (1 page = 64 KiB). Defaults to 16 (1 MiB) |
| `--wall-clock-ms` | `<WALL_CLOCK_MS>` | Wall-clock deadline in milliseconds. Defaults to 5000 (5s) |

