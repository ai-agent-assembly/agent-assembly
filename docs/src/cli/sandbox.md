# aasm sandbox

Run a WebAssembly tool inside the Agent Assembly tool-execution sandbox, with
filesystem, CPU (instruction fuel), memory, and wall-clock isolation. This
surfaces the `aa-sandbox` runtime to the CLI without going through the cloud
`/dispatch_tool` HTTP route.

## Synopsis

```text
aasm sandbox <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`run`](#aasm-sandbox-run) | Run a `.wasm` module inside a fresh sandbox. |
| [`info`](#aasm-sandbox-info) | Show the default sandbox runtime limits. |

---

## aasm sandbox run

Run a WebAssembly module under WASI preview 1 inside a fresh sandbox and report
the outcome. Unset limits fall back to the safe-by-default values.

| Name | Type | Default | Description |
|---|---|---|---|
| `<WASM>` | path (arg) | — | Path to a `.wasm` module to execute under WASI preview 1. |
| `--fuel <FUEL>` | integer | `10000000` (10M) | Wasmtime instruction-fuel budget. Raise for long-running tools. |
| `--memory-pages <MEMORY_PAGES>` | integer | `16` (1 MiB) | Maximum linear-memory pages (1 page = 64 KiB). |
| `--wall-clock-ms <WALL_CLOCK_MS>` | integer | `5000` (5s) | Wall-clock deadline in milliseconds. |

```bash
aasm sandbox run ./tool.wasm --fuel 50000000 --wall-clock-ms 10000
```

```text
Sandbox run: ./tool.wasm
  Outcome:    completed
  Fuel used:  3,201,884 / 50,000,000
  Wall time:  812ms / 10000ms
```

---

## aasm sandbox info

Show the default sandbox runtime limits. Takes no arguments.

```bash
aasm sandbox info
```

```text
Default sandbox limits:
  Fuel:           10,000,000 units
  Memory pages:   16  (1 MiB)
  Wall clock:     5000 ms
```
